// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package vaultfake — двойник Vault для проб: вход kubernetes-auth и KV v2 с
// CAS. Контракт двойника сверяется с настоящим Vault той же пробой
// (internal/vault/contract.go; integration-проба гонит её против Vault в
// контейнере), поэтому двойник не снисходительнее настоящего.
package vaultfake

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server — двойник Vault.
type Server struct {
	// AuthMount — путь метода kubernetes-auth.
	AuthMount string
	// Role — единственная принимаемая роль.
	Role string
	// AcceptJWT — проверка projected-токена.
	AcceptJWT func(jwt string) bool
	// Allowed — политика роли: какие пути KV (mount/path) доступны.
	Allowed func(mount, path string) bool
	// TokenTTL — срок токена Vault.
	TokenTTL time.Duration
	// Now — часы; nil — time.Now.
	Now func() time.Time

	mu       sync.Mutex
	tokens   map[string]time.Time
	kv       map[string]*entry
	failNext int
	logins   int
}

type entry struct {
	versions []map[string]string
	deleted  bool
}

// New — двойник с ролью role и политикой allowed.
func New(authMount, role string, allowed func(mount, path string) bool) *Server {
	return &Server{
		AuthMount: authMount,
		Role:      role,
		AcceptJWT: func(jwt string) bool { return jwt != "" },
		Allowed:   allowed,
		TokenTTL:  time.Hour,
		tokens:    map[string]time.Time{},
		kv:        map[string]*entry{},
	}
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// FailNext — следующие n запросов получат 503.
func (s *Server) FailNext(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext = n
}

// RevokeTokens — все выданные токены Vault становятся недействительными.
func (s *Server) RevokeTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = map[string]time.Time{}
}

// Logins — число успешных входов.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// Get — текущая версия записи для проверок; nil — записи нет.
func (s *Server) Get(mount, path string) (map[string]string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.kv[mount+"/"+path]
	if e == nil || e.deleted || len(e.versions) == 0 {
		return nil, 0
	}
	cp := map[string]string{}
	for k, v := range e.versions[len(e.versions)-1] {
		cp[k] = v
	}
	return cp, len(e.versions)
}

// Put — запись в обход API (для подготовки проб).
func (s *Server) Put(mount, path string, data map[string]string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.kv[mount+"/"+path]
	if e == nil {
		e = &entry{}
		s.kv[mount+"/"+path] = e
	}
	e.deleted = false
	e.versions = append(e.versions, data)
	return len(e.versions)
}

// Delete — удаление записи со всеми версиями в обход API.
func (s *Server) Delete(mount, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.kv, mount+"/"+path)
}

// Paths — все живые пути (mount/path).
func (s *Server) Paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k, e := range s.kv {
		if !e.deleted {
			out = append(out, k)
		}
	}
	return out
}

func writeErr(w http.ResponseWriter, status int, msgs ...string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if msgs == nil {
		msgs = []string{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": msgs})
}

func writeOK(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// ServeHTTP — подмножество API Vault, которым пользуется оператор.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.failNext > 0 {
		s.failNext--
		s.mu.Unlock()
		writeErr(w, http.StatusServiceUnavailable, "Vault is sealed")
		return
	}
	s.mu.Unlock()

	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	if p == r.URL.Path {
		writeErr(w, http.StatusNotFound)
		return
	}
	if p == "auth/"+s.AuthMount+"/login" && r.Method == http.MethodPost {
		s.login(w, r)
		return
	}
	if !s.authorized(r.Header.Get("X-Vault-Token")) {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	mount, kind, path, ok := splitKV(p)
	if !ok {
		writeErr(w, http.StatusNotFound)
		return
	}
	if s.Allowed != nil && !s.Allowed(mount, path) {
		writeErr(w, http.StatusForbidden, "1 error occurred:\n\t* permission denied\n\n")
		return
	}
	switch {
	case kind == "data" && r.Method == http.MethodGet:
		s.read(w, mount, path)
	case kind == "data" && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		s.write(w, r, mount, path)
	case kind == "metadata" && r.Method == http.MethodDelete:
		s.mu.Lock()
		delete(s.kv, mount+"/"+path)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		writeErr(w, http.StatusMethodNotAllowed)
	}
}

func splitKV(p string) (mount, kind, path string, ok bool) {
	parts := strings.SplitN(p, "/", 3)
	if len(parts) != 3 || (parts[1] != "data" && parts[1] != "metadata") || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "failed to parse JSON input")
		return
	}
	if body.Role != s.Role {
		writeErr(w, http.StatusBadRequest, "invalid role name \""+body.Role+"\"")
		return
	}
	if !s.AcceptJWT(body.JWT) {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	tok := "hvs.fake" + hex.EncodeToString(b)
	s.mu.Lock()
	s.tokens[tok] = s.now().Add(s.TokenTTL)
	s.logins++
	s.mu.Unlock()
	writeOK(w, map[string]any{"auth": map[string]any{
		"client_token":   tok,
		"lease_duration": int(s.TokenTTL / time.Second),
		"renewable":      true,
	}})
}

func (s *Server) authorized(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.tokens[tok]
	return ok && s.now().Before(exp)
}

func (s *Server) read(w http.ResponseWriter, mount, path string) {
	s.mu.Lock()
	e := s.kv[mount+"/"+path]
	if e == nil || len(e.versions) == 0 {
		s.mu.Unlock()
		writeErr(w, http.StatusNotFound)
		return
	}
	if e.deleted {
		v := len(e.versions)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"data": nil, "metadata": map[string]any{"version": v, "deletion_time": s.now().UTC().Format(time.RFC3339Nano)},
		}})
		return
	}
	v := len(e.versions)
	data := e.versions[v-1]
	s.mu.Unlock()
	writeOK(w, map[string]any{"data": map[string]any{
		"data": data, "metadata": map[string]any{"version": v, "deletion_time": "", "destroyed": false},
	}})
}

func (s *Server) write(w http.ResponseWriter, r *http.Request, mount, path string) {
	var body struct {
		Options map[string]json.Number `json:"options"`
		Data    map[string]string      `json:"data"`
	}
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "failed to parse JSON input")
		return
	}
	if body.Data == nil {
		writeErr(w, http.StatusBadRequest, "no data provided")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.kv[mount+"/"+path]
	cur := 0
	if e != nil {
		cur = len(e.versions)
	}
	if cas, ok := body.Options["cas"]; ok {
		want, err := cas.Int64()
		if err != nil || int(want) != cur {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"check-and-set parameter did not match the current version"}})
			return
		}
	}
	if e == nil {
		e = &entry{}
		s.kv[mount+"/"+path] = e
	}
	e.deleted = false
	e.versions = append(e.versions, body.Data)
	writeOK(w, map[string]any{"data": map[string]any{"version": len(e.versions)}})
}
