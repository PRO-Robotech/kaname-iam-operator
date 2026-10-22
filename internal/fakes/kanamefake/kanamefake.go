// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package kanamefake — двойник kaname IAM для проб.
//
// Провод двойника — НЕ рукописный: службы двойника реализуют сгенерированные
// интерфейсы серверов kaname `pkg/api` @v0.5.0, а REST-фронт собирается теми
// же сгенерированными обработчиками grpc-gateway (`Register*HandlerServer`),
// что и у kaname. Пути, параметры запроса, отображение JSON и форма отказа
// у двойника те же, что у kaname; руками написана только семантика, и её
// подмножество, которым пользуется оператор, сверяет integration-проба против
// настоящего kaname.
package kanamefake

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server — двойник kaname.
type Server struct {
	// AcceptAssertion — проверка утверждения jwt-bearer; возвращает принципала.
	AcceptAssertion func(assertion string) (principal string, ok bool)
	// TokenTTL — срок выдаваемого токена доступа.
	TokenTTL time.Duration
	// AsyncPolls — сколько чтений операции до её завершения (0 — сразу).
	AsyncPolls int

	mu sync.Mutex
	// background — задержка фонового исполнения операций (SetBackground).
	background   time.Duration
	now          func() time.Time
	tokens       map[string]string
	usedAssert   map[string]bool
	accounts     map[string]bool
	projects     map[string]string
	denied       map[string]bool
	sas          map[string]*iamv1.ServiceAccount
	keys         map[string]*iamv1.ServiceAccountOAuthClient
	keySecrets   map[string]string
	roles        map[string]*iamv1.Role
	bindings     map[string]*iamv1.AccessBinding
	ops          map[string]*opRow
	faults       []*fault
	opFaults     []*fault
	calls        []string
	issueHook    func(keyID string)
	requestHook  func(method, path string, body []byte)
	tokenCounter int
}

type opRow struct {
	op        *operationpb.Operation
	owner     string
	pollsLeft int
	// background — операция исполняется фоном: чтение её не завершает.
	background bool
	run        func() (*anypb.Any, error)
}

type fault struct {
	method string
	path   *regexp.Regexp
	code   codes.Code
	times  int
}

type principalKey struct{}

// New — пустой двойник.
func New() *Server {
	return &Server{
		AcceptAssertion: func(a string) (string, bool) { return "sva-operator", a != "" },
		TokenTTL:        time.Hour,
		now:             time.Now,
		tokens:          map[string]string{},
		usedAssert:      map[string]bool{},
		accounts:        map[string]bool{},
		projects:        map[string]string{},
		denied:          map[string]bool{},
		sas:             map[string]*iamv1.ServiceAccount{},
		keys:            map[string]*iamv1.ServiceAccountOAuthClient{},
		keySecrets:      map[string]string{},
		roles:           map[string]*iamv1.Role{},
		bindings:        map[string]*iamv1.AccessBinding{},
		ops:             map[string]*opRow{},
	}
}

// SetBackground включает фоновое исполнение операций: операция завершается
// сама через d после ответа на изменяющий вызов, без чтения, а чтение до того
// отдаёт её незавершённой. Так kaname исполняет мутацию воркером
// (operations.Run): строка ресурса появляется в списках позже ответа, и
// пустой список сразу после ответа не доказывает, что её не будет. 0 —
// исполнение сразу либо по AsyncPolls.
func (s *Server) SetBackground(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.background = d
}

// SetNow подменяет часы двойника.
func (s *Server) SetNow(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// AddAccount заводит аккаунт.
func (s *Server) AddAccount(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts[id] = true
}

// AddProject заводит проект в аккаунте.
func (s *Server) AddProject(id, accountID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.projects[id] = accountID
}

// AddRole заводит роль и возвращает её id.
func (s *Server) AddRole(name string, system bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newID("rol")
	s.roles[id] = &iamv1.Role{Id: id, Name: name, IsSystem: system}
	return id
}

// AddAccountRole заводит роль арендатора в аккаунте и возвращает её id: имя
// у неё любое, в том числе имя системной роли.
func (s *Server) AddAccountRole(name, accountID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newID("rol")
	s.roles[id] = &iamv1.Role{Id: id, Name: name, AccountId: accountID}
	return id
}

// DenyScope — вызовы в аккаунте или проекте id получают PERMISSION_DENIED.
func (s *Server) DenyScope(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denied[id] = true
}

// Fail — следующие times вызовов method path (regexp по пути) получат code.
func (s *Server) Fail(method, pathRe string, code codes.Code, times int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, &fault{method: method, path: regexp.MustCompile(pathRe), code: code, times: times})
}

// FailOperation — следующие times операций вызова method path завершатся code.
func (s *Server) FailOperation(method, pathRe string, code codes.Code, times int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opFaults = append(s.opFaults, &fault{method: method, path: regexp.MustCompile(pathRe), code: code, times: times})
}

// OnIssue — крючок, зовущийся после выпуска ключа (до ответа).
func (s *Server) OnIssue(f func(keyID string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issueHook = f
}

// OnRequest — крючок, зовущийся на каждый вызов REST-фронта ДО его
// исполнения, с телом запроса. Им проба делает то, что в жизни случается
// посреди вызова: удаляет CR либо меняет его spec, пока kaname заводит объект.
func (s *Server) OnRequest(f func(method, path string, body []byte)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requestHook = f
}

// Calls — журнал вызовов «METHOD path».
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// ServiceAccounts — копии учёток.
func (s *Server) ServiceAccounts() []*iamv1.ServiceAccount {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*iamv1.ServiceAccount, 0, len(s.sas))
	for _, sa := range s.sas {
		out = append(out, proto.Clone(sa).(*iamv1.ServiceAccount))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetId() < out[j].GetId() })
	return out
}

// Keys — копии действующих ключей учётки.
func (s *Server) Keys(saID string) []*iamv1.ServiceAccountOAuthClient {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*iamv1.ServiceAccountOAuthClient
	for _, k := range s.keys {
		if k.GetSvaId() == saID {
			out = append(out, proto.Clone(k).(*iamv1.ServiceAccountOAuthClient))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetId() < out[j].GetId() })
	return out
}

// SecretOf — секрет ключа, как его выдал двойник (для сверки с Vault).
func (s *Server) SecretOf(keyID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keySecrets[keyID]
}

// Bindings — копии выдач (с отозванными).
func (s *Server) Bindings() []*iamv1.AccessBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*iamv1.AccessBinding, 0, len(s.bindings))
	for _, b := range s.bindings {
		out = append(out, proto.Clone(b).(*iamv1.AccessBinding))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetId() < out[j].GetId() })
	return out
}

// PutServiceAccount заводит учётку в обход API (чужая учётка, подготовка).
func (s *Server) PutServiceAccount(sa *iamv1.ServiceAccount) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sa.Id == "" {
		sa.Id = newID("sva")
	}
	s.sas[sa.Id] = proto.Clone(sa).(*iamv1.ServiceAccount)
	return sa.Id
}

// PutKey заводит ключ в обход API (выпуск, чей ответ потерян).
func (s *Server) PutKey(k *iamv1.ServiceAccountOAuthClient) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k.Id == "" {
		k.Id = newID("sak")
	}
	if k.CreatedAt == nil {
		k.CreatedAt = timestamppb.New(s.now())
	}
	s.keys[k.Id] = proto.Clone(k).(*iamv1.ServiceAccountOAuthClient)
	return k.Id
}

// PutBinding заводит выдачу в обход API (чужая выдача).
func (s *Server) PutBinding(b *iamv1.AccessBinding) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b.Id == "" {
		b.Id = newID("acb")
	}
	if b.Status == iamv1.AccessBinding_STATUS_UNSPECIFIED {
		b.Status = iamv1.AccessBinding_ACTIVE
	}
	s.bindings[b.Id] = proto.Clone(b).(*iamv1.AccessBinding)
	return b.Id
}

// SetEnabled — ручное отключение или включение учётки (инцидент).
func (s *Server) SetEnabled(saID string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sa := s.sas[saID]; sa != nil {
		sa.Enabled = enabled
	}
}

// RemoveServiceAccount — ручное удаление учётки.
func (s *Server) RemoveServiceAccount(saID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sas, saID)
}

// RemoveKey — ручной отзыв ключа.
func (s *Server) RemoveKey(keyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, keyID)
}

// RevokeBindingExternally — ручной отзыв выдачи.
func (s *Server) RevokeBindingExternally(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.bindings[id]; b != nil {
		b.Status = iamv1.AccessBinding_REVOKED
		b.RevokedAt = timestamppb.New(s.now())
	}
}

// Handler — REST-фронт двойника и токен-эндпоинт.
func (s *Server) Handler() http.Handler {
	mux := runtime.NewServeMux()
	ctx := context.Background()
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(iamv1.RegisterServiceAccountServiceHandlerServer(ctx, mux, &saService{s: s}))
	must(iamv1.RegisterSAKeyServiceHandlerServer(ctx, mux, &keyService{s: s}))
	must(iamv1.RegisterAccessBindingServiceHandlerServer(ctx, mux, &bindingService{s: s}))
	must(iamv1.RegisterRoleServiceHandlerServer(ctx, mux, &roleService{s: s}))
	must(operationpb.RegisterOperationServiceHandlerServer(ctx, mux, &opService{s: s}))

	top := http.NewServeMux()
	top.HandleFunc("/iam/v1/token", s.token)
	top.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.calls = append(s.calls, r.Method+" "+r.URL.Path)
		principal, ok := s.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		var hit *fault
		for _, f := range s.faults {
			if f.times > 0 && f.method == r.Method && f.path.MatchString(r.URL.Path) {
				f.times--
				hit = f
				break
			}
		}
		hook := s.requestHook
		s.mu.Unlock()
		if !ok {
			writeStatus(w, http.StatusUnauthorized, codes.Unauthenticated, "unauthenticated")
			return
		}
		if hook != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				writeStatus(w, http.StatusBadRequest, codes.InvalidArgument, "unreadable body")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			hook(r.Method, r.URL.Path, body)
		}
		if hit != nil {
			writeStatus(w, runtime.HTTPStatusFromCode(hit.code), hit.code, "injected fault")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, principal)
		ctx = context.WithValue(ctx, requestKey{}, r.Method+" "+r.URL.Path)
		mux.ServeHTTP(w, r.WithContext(ctx))
	}))
	return top
}

type requestKey struct{}

func writeStatus(w http.ResponseWriter, httpStatus int, code codes.Code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": int(code), "message": msg, "details": []any{}})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" ||
		len(r.PostForm["assertion"]) != 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
		return
	}
	assertion := r.PostForm.Get("assertion")
	s.mu.Lock()
	defer s.mu.Unlock()
	principal, ok := s.AcceptAssertion(assertion)
	if !ok || s.usedAssert[assertion] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		return
	}
	s.usedAssert[assertion] = true
	s.tokenCounter++
	tok := fmt.Sprintf("kat-%d-%s", s.tokenCounter, newID(""))
	s.tokens[tok] = principal
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": tok, "token_type": "Bearer", "expires_in": int(s.TokenTTL / time.Second),
	})
}

// ExpireTokens делает все выданные токены недействительными.
func (s *Server) ExpireTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = map[string]string{}
}

func principalOf(ctx context.Context) string {
	p, _ := ctx.Value(principalKey{}).(string)
	return p
}

// startOp заводит операцию. Выполнение — фоном (SetBackground), сразу
// (AsyncPolls = 0) либо на AsyncPolls-м чтении. Отказ операции по
// FailOperation заменяет выполнение.
func (s *Server) startOp(ctx context.Context, desc string, md proto.Message, run func() (*anypb.Any, error)) (*operationpb.Operation, error) {
	return s.startOpMode(ctx, desc, md, false, run)
}

// startOpMode — sync: операция завершается на пути запроса при любом
// AsyncPolls (у kaname так выпускается секрет).
func (s *Server) startOpMode(ctx context.Context, desc string, md proto.Message, sync bool, run func() (*anypb.Any, error)) (*operationpb.Operation, error) {
	mdAny, err := anypb.New(md)
	if err != nil {
		return nil, grpcstatus.Error(codes.Internal, err.Error())
	}
	op := &operationpb.Operation{Id: newID("opr"), Description: desc, Metadata: mdAny, CreatedAt: timestamppb.New(s.now())}
	req, _ := ctx.Value(requestKey{}).(string)
	method, path, _ := strings.Cut(req, " ")
	for _, f := range s.opFaults {
		if f.times > 0 && f.method == method && f.path.MatchString(path) {
			f.times--
			code := f.code
			run = func() (*anypb.Any, error) { return nil, grpcstatus.Error(code, "injected operation fault") }
			break
		}
	}
	row := &opRow{op: op, owner: principalOf(ctx), pollsLeft: s.AsyncPolls, run: run}
	s.ops[op.Id] = row
	switch {
	case sync || (s.background == 0 && row.pollsLeft == 0):
		s.finish(row)
	case s.background > 0:
		row.background = true
		time.AfterFunc(s.background, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if !row.op.GetDone() {
				s.finish(row)
			}
		})
	}
	return proto.Clone(op).(*operationpb.Operation), nil
}

func (s *Server) finish(row *opRow) {
	resp, err := row.run()
	row.op.Done = true
	row.op.ModifiedAt = timestamppb.New(s.now())
	if err != nil {
		st, _ := grpcstatus.FromError(err)
		row.op.Result = &operationpb.Operation_Error{Error: &status.Status{Code: int32(st.Code()), Message: st.Message()}}
		return
	}
	row.op.Result = &operationpb.Operation_Response{Response: resp}
}

func mustAny(m proto.Message) *anypb.Any {
	a, err := anypb.New(m)
	if err != nil {
		panic(err)
	}
	return a
}

var nameFormRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

var labelKeyRe = regexp.MustCompile(`^[a-z][-_./@a-z0-9]{0,62}$`)

func validLabels(l map[string]string) error {
	if len(l) > 64 {
		return grpcstatus.Error(codes.InvalidArgument, "Illegal argument labels: cardinality must be <=64")
	}
	for k, v := range l {
		if !labelKeyRe.MatchString(k) {
			return grpcstatus.Error(codes.InvalidArgument, "Illegal argument label key: invalid format")
		}
		if len(v) > 63 {
			return grpcstatus.Error(codes.InvalidArgument, "Illegal argument label value: length must be <=63")
		}
	}
	return nil
}

var nameFilterRe = regexp.MustCompile(`^name = "((?:[^"\\]|\\.)*)"$`)

func parseNameFilter(f string) (string, bool, error) {
	if f == "" {
		return "", false, nil
	}
	m := nameFilterRe.FindStringSubmatch(strings.TrimSpace(f))
	if m == nil {
		return "", false, grpcstatus.Error(codes.InvalidArgument, "Bad expression at column 1. Unknown field")
	}
	v, err := strconv.Unquote(`"` + m[1] + `"`)
	if err != nil {
		return "", false, grpcstatus.Error(codes.InvalidArgument, "Bad expression")
	}
	return v, true, nil
}

func page[T any](items []T, size int64, token string) ([]T, string, error) {
	if size <= 0 {
		size = 50
	}
	start := 0
	if token != "" {
		n, err := strconv.Atoi(token)
		if err != nil || n < 0 || n > len(items) {
			return nil, "", grpcstatus.Error(codes.InvalidArgument, "invalid page_token")
		}
		start = n
	}
	end := start + int(size)
	if end >= len(items) {
		return items[start:], "", nil
	}
	return items[start:end], strconv.Itoa(end), nil
}

// ── ServiceAccountService ────────────────────────────────────────────────

type saService struct {
	iamv1.UnimplementedServiceAccountServiceServer
	s *Server
}

func (h *saService) Get(_ context.Context, req *iamv1.GetServiceAccountRequest) (*iamv1.ServiceAccount, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	sa := s.sas[req.GetServiceAccountId()]
	if sa == nil {
		return nil, grpcstatus.Errorf(codes.NotFound, "ServiceAccount %s not found", req.GetServiceAccountId())
	}
	return proto.Clone(sa).(*iamv1.ServiceAccount), nil
}

func (h *saService) List(_ context.Context, req *iamv1.ListServiceAccountsRequest) (*iamv1.ListServiceAccountsResponse, error) {
	s := h.s
	name, byName, err := parseNameFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*iamv1.ServiceAccount
	for _, sa := range s.sas {
		if req.GetAccountId() != "" && sa.GetAccountId() != req.GetAccountId() {
			continue
		}
		if byName && sa.GetName() != name {
			continue
		}
		all = append(all, proto.Clone(sa).(*iamv1.ServiceAccount))
	}
	sort.Slice(all, func(i, j int) bool { return all[i].GetId() < all[j].GetId() })
	items, next, err := page(all, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	return &iamv1.ListServiceAccountsResponse{ServiceAccounts: items, NextPageToken: next}, nil
}

func (h *saService) Create(ctx context.Context, req *iamv1.CreateServiceAccountRequest) (*operationpb.Operation, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.GetAccountId() == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "account_id required")
	}
	if s.denied[req.GetAccountId()] {
		return nil, grpcstatus.Error(codes.PermissionDenied, "permission denied")
	}
	if !s.accounts[req.GetAccountId()] {
		return nil, grpcstatus.Error(codes.PermissionDenied, "permission denied")
	}
	if !nameFormRe.MatchString(req.GetName()) {
		return nil, grpcstatus.Error(codes.InvalidArgument, "Illegal argument name: invalid format")
	}
	if err := validLabels(req.GetLabels()); err != nil {
		return nil, err
	}
	id := newID("sva")
	return s.startOp(ctx, "Create service account "+req.GetName(),
		&iamv1.CreateServiceAccountMetadata{ServiceAccountId: id, AccountId: req.GetAccountId()},
		func() (*anypb.Any, error) {
			for _, sa := range s.sas {
				if sa.GetAccountId() == req.GetAccountId() && sa.GetName() == req.GetName() {
					return nil, grpcstatus.Error(codes.AlreadyExists, "service account name already taken")
				}
			}
			sa := &iamv1.ServiceAccount{
				Id: id, AccountId: req.GetAccountId(), Name: req.GetName(), Description: req.GetDescription(),
				Enabled: true, Labels: req.GetLabels(), CreatedAt: timestamppb.New(s.now()),
			}
			s.sas[id] = sa
			return mustAny(sa), nil
		})
}

func (h *saService) Update(ctx context.Context, req *iamv1.UpdateServiceAccountRequest) (*operationpb.Operation, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	sa := s.sas[req.GetServiceAccountId()]
	if sa == nil {
		return nil, grpcstatus.Errorf(codes.NotFound, "ServiceAccount %s not found", req.GetServiceAccountId())
	}
	paths := req.GetUpdateMask().GetPaths()
	if len(paths) == 0 {
		return nil, grpcstatus.Error(codes.InvalidArgument, "update_mask is required")
	}
	for _, p := range paths {
		switch p {
		case "description", "labels", "name":
		default:
			return nil, grpcstatus.Errorf(codes.InvalidArgument, "update_mask: unknown field %q", p)
		}
	}
	if err := validLabels(req.GetLabels()); err != nil {
		return nil, err
	}
	id := sa.GetId()
	return s.startOp(ctx, "Update service account", &iamv1.UpdateServiceAccountMetadata{ServiceAccountId: id, AccountId: sa.GetAccountId()},
		func() (*anypb.Any, error) {
			cur := s.sas[id]
			if cur == nil {
				return nil, grpcstatus.Error(codes.NotFound, "ServiceAccount not found")
			}
			for _, p := range paths {
				switch p {
				case "description":
					cur.Description = req.GetDescription()
				case "labels":
					cur.Labels = req.GetLabels()
				case "name":
					cur.Name = req.GetName()
				}
			}
			return mustAny(cur), nil
		})
}

func (h *saService) setEnabled(ctx context.Context, id string, enabled bool) (*operationpb.Operation, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	sa := s.sas[id]
	if sa == nil {
		return nil, grpcstatus.Errorf(codes.NotFound, "ServiceAccount %s not found", id)
	}
	var md proto.Message = &iamv1.DisableServiceAccountMetadata{ServiceAccountId: id, AccountId: sa.GetAccountId()}
	if enabled {
		md = &iamv1.EnableServiceAccountMetadata{ServiceAccountId: id, AccountId: sa.GetAccountId()}
	}
	return s.startOp(ctx, "Set enabled", md, func() (*anypb.Any, error) {
		cur := s.sas[id]
		if cur == nil {
			return nil, grpcstatus.Error(codes.NotFound, "ServiceAccount not found")
		}
		cur.Enabled = enabled
		return mustAny(cur), nil
	})
}

func (h *saService) Disable(ctx context.Context, req *iamv1.DisableServiceAccountRequest) (*operationpb.Operation, error) {
	return h.setEnabled(ctx, req.GetServiceAccountId(), false)
}

func (h *saService) Enable(ctx context.Context, req *iamv1.EnableServiceAccountRequest) (*operationpb.Operation, error) {
	return h.setEnabled(ctx, req.GetServiceAccountId(), true)
}

func (h *saService) Delete(ctx context.Context, req *iamv1.DeleteServiceAccountRequest) (*operationpb.Operation, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	id := req.GetServiceAccountId()
	sa := s.sas[id]
	if sa == nil {
		return nil, grpcstatus.Errorf(codes.NotFound, "ServiceAccount %s not found", id)
	}
	return s.startOp(ctx, "Delete service account", &iamv1.DeleteServiceAccountMetadata{ServiceAccountId: id, AccountId: sa.GetAccountId()},
		func() (*anypb.Any, error) {
			// Как у kaname: учётка с действующими ключами не удаляется (замер
			// на стенде @93ad1b88 — FAILED_PRECONDITION, REFERENCE_IN_USE).
			for _, k := range s.keys {
				if k.GetSvaId() == id {
					return nil, grpcstatus.Error(codes.FailedPrecondition,
						"resource is still referenced by other resources; release those references before deleting it")
				}
			}
			delete(s.sas, id)
			return mustAny(&emptypb.Empty{}), nil
		})
}

// ── SAKeyService ─────────────────────────────────────────────────────────

type keyService struct {
	iamv1.UnimplementedSAKeyServiceServer
	s *Server
}

const secretTTLCeiling = 90 * 24 * time.Hour

func (h *keyService) Issue(ctx context.Context, req *iamv1.IssueSAKeyRequest) (*operationpb.Operation, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	sa := s.sas[req.GetServiceAccountId()]
	if sa == nil {
		return nil, grpcstatus.Errorf(codes.NotFound, "ServiceAccount %s not found", req.GetServiceAccountId())
	}
	if req.GetTtlSeconds() < 0 {
		return nil, grpcstatus.Error(codes.InvalidArgument, "ttl_seconds must be >= 0")
	}
	kind := req.GetCredentialKind()
	if kind == iamv1.CredentialKind_CREDENTIAL_KIND_UNSPECIFIED {
		kind = iamv1.CredentialKind_CREDENTIAL_KIND_KEYPAIR
	}
	ttl := time.Duration(req.GetTtlSeconds()) * time.Second
	if kind == iamv1.CredentialKind_CREDENTIAL_KIND_SECRET {
		if len(req.GetAudience()) > 0 {
			return nil, grpcstatus.Error(codes.InvalidArgument, "audience: not meaningful for credential_kind SECRET")
		}
		if ttl > secretTTLCeiling {
			return nil, grpcstatus.Error(codes.InvalidArgument, "ttl_seconds: exceeds the SECRET ceiling")
		}
	}
	if ttl == 0 {
		ttl = 90 * 24 * time.Hour
	}
	if err := validLabels(req.GetLabels()); err != nil {
		return nil, err
	}
	if req.GetName() != "" && !nameFormRe.MatchString(req.GetName()) {
		return nil, grpcstatus.Error(codes.InvalidArgument, "Illegal argument name: invalid format")
	}
	if !sa.GetEnabled() {
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "ServiceAccount %s is disabled and cannot be issued a key", sa.GetId())
	}
	keyID := newID("sak")
	key := &iamv1.ServiceAccountOAuthClient{
		Id: keyID, SvaId: sa.GetId(), Description: req.GetDescription(), Name: req.GetName(),
		Labels: req.GetLabels(), CredentialKind: kind,
		ExpiresAt: timestamppb.New(s.now().Add(ttl)), CreatedAt: timestamppb.New(s.now()),
	}
	md := &iamv1.IssueSAKeyMetadata{ServiceAccountId: sa.GetId(), KeyId: keyID, AccountId: sa.GetAccountId()}
	shown := &iamv1.IssueSAKeyResponse{Key: key, ClientId: keyID, KeyId: keyID}
	if kind == iamv1.CredentialKind_CREDENTIAL_KIND_SECRET {
		shown.Secret = "kacho_" + keyID + "_" + newID("")
	} else {
		shown.PrivateKeyPem = "-----BEGIN PRIVATE KEY-----\nfake-" + keyID + "\n-----END PRIVATE KEY-----\n"
		shown.Algorithm = "ES256"
		shown.Audiences = req.GetAudience()
	}
	op, err := s.startOpMode(ctx, "Issue SA key", md, kind == iamv1.CredentialKind_CREDENTIAL_KIND_SECRET, func() (*anypb.Any, error) {
		s.keys[keyID] = proto.Clone(key).(*iamv1.ServiceAccountOAuthClient)
		if shown.Secret != "" {
			s.keySecrets[keyID] = shown.Secret
		} else {
			s.keySecrets[keyID] = shown.PrivateKeyPem
		}
		if s.issueHook != nil {
			s.issueHook(keyID)
		}
		return mustAny(shown), nil
	})
	if err != nil {
		return nil, err
	}
	// Секрет показывается ОДИН раз — в ответе выпуска; строка операции его не
	// несёт (как у kaname: чтение операции секрета не отдаёт).
	if row := s.ops[op.GetId()]; row != nil && row.op.GetDone() && row.op.GetResponse() != nil {
		stored := proto.Clone(shown).(*iamv1.IssueSAKeyResponse)
		stored.Secret, stored.PrivateKeyPem = "", ""
		row.op.Result = &operationpb.Operation_Response{Response: mustAny(stored)}
	}
	return op, nil
}

func (h *keyService) List(_ context.Context, req *iamv1.ListSAKeysRequest) (*iamv1.ListSAKeysResponse, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sas[req.GetServiceAccountId()] == nil {
		return nil, grpcstatus.Errorf(codes.NotFound, "ServiceAccount %s not found", req.GetServiceAccountId())
	}
	var all []*iamv1.ServiceAccountOAuthClient
	for _, k := range s.keys {
		if k.GetSvaId() == req.GetServiceAccountId() {
			all = append(all, proto.Clone(k).(*iamv1.ServiceAccountOAuthClient))
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].GetId() < all[j].GetId() })
	items, next, err := page(all, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	return &iamv1.ListSAKeysResponse{Keys: items, NextPageToken: next}, nil
}

func (h *keyService) Revoke(ctx context.Context, req *iamv1.RevokeSAKeyRequest) (*operationpb.Operation, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.keys[req.GetKeyId()]
	if k == nil || k.GetSvaId() != req.GetServiceAccountId() {
		return nil, grpcstatus.Errorf(codes.NotFound, "SAKey %s not found", req.GetKeyId())
	}
	sa := s.sas[req.GetServiceAccountId()]
	return s.startOp(ctx, "Revoke SA key",
		&iamv1.RevokeSAKeyMetadata{ServiceAccountId: req.GetServiceAccountId(), KeyId: req.GetKeyId(), AccountId: sa.GetAccountId()},
		func() (*anypb.Any, error) {
			if s.keys[req.GetKeyId()] == nil {
				return nil, grpcstatus.Errorf(codes.NotFound, "SAKey %s not found", req.GetKeyId())
			}
			delete(s.keys, req.GetKeyId())
			return mustAny(&iamv1.RevokeSAKeyResponse{KeyId: req.GetKeyId(), RevokedAt: timestamppb.New(s.now())}), nil
		})
}

// ── RoleService ──────────────────────────────────────────────────────────

type roleService struct {
	iamv1.UnimplementedRoleServiceServer
	s *Server
}

func (h *roleService) List(_ context.Context, req *iamv1.ListRolesRequest) (*iamv1.ListRolesResponse, error) {
	s := h.s
	name, byName, err := parseNameFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*iamv1.Role
	for _, r := range s.roles {
		if byName && r.GetName() != name {
			continue
		}
		// account_id сужает каталог до системных ролей и ролей этого аккаунта;
		// без него видны системные и роли аккаунтов, где у вызывающего есть
		// право чтения, — двойник считает видимыми все.
		if req.GetAccountId() != "" && !r.GetIsSystem() && r.GetAccountId() != req.GetAccountId() {
			continue
		}
		all = append(all, proto.Clone(r).(*iamv1.Role))
	}
	sort.Slice(all, func(i, j int) bool { return all[i].GetId() < all[j].GetId() })
	items, next, err := page(all, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	return &iamv1.ListRolesResponse{Roles: items, NextPageToken: next}, nil
}

// ── AccessBindingService ─────────────────────────────────────────────────

type bindingService struct {
	iamv1.UnimplementedAccessBindingServiceServer
	s *Server
}

// bindingKey — ключ уникальности действующей выдачи: субъекты, роль, область и
// цель (у kaname — target_digest в частичном уникальном индексе).
func bindingKey(subjects []*iamv1.Subject, role, scopeType, scopeID string, target *iamv1.AccessTarget) string {
	var subs []string
	for _, sub := range subjects {
		subs = append(subs, sub.GetType().String()+":"+sub.GetId())
	}
	sort.Strings(subs)
	var res []string
	for _, r := range target.GetResources().GetResources() {
		res = append(res, r.GetType()+":"+r.GetId())
	}
	sort.Strings(res)
	all := ""
	if target.GetAllInScope() != nil {
		all = "*"
	}
	return strings.Join(subs, ",") + "|" + role + "|" + scopeType + ":" + scopeID + "|" + strings.Join(res, ",") + all
}

func (h *bindingService) Get(_ context.Context, req *iamv1.GetAccessBindingRequest) (*iamv1.AccessBinding, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bindings[req.GetAccessBindingId()]
	if b == nil {
		return nil, grpcstatus.Errorf(codes.NotFound, "AccessBinding %s not found", req.GetAccessBindingId())
	}
	return proto.Clone(b).(*iamv1.AccessBinding), nil
}

func (h *bindingService) Create(ctx context.Context, req *iamv1.CreateAccessBindingRequest) (*operationpb.Operation, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	subjects := req.GetSubjects()
	if len(subjects) == 0 {
		return nil, grpcstatus.Error(codes.InvalidArgument, "subjects required")
	}
	for _, sub := range subjects {
		switch sub.GetType() {
		case iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT:
			if s.sas[sub.GetId()] == nil {
				return nil, grpcstatus.Errorf(codes.InvalidArgument, "subject %s not found", sub.GetId())
			}
		case iamv1.SubjectType_SUBJECT_TYPE_USER, iamv1.SubjectType_SUBJECT_TYPE_GROUP, iamv1.SubjectType_SUBJECT_TYPE_SYSTEM_CLASS:
		default:
			return nil, grpcstatus.Error(codes.InvalidArgument, "subject type required")
		}
	}
	if s.roles[req.GetRoleId()] == nil {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "role %s not found", req.GetRoleId())
	}
	switch req.GetScopeType() {
	case "iam.project":
		if _, ok := s.projects[req.GetScopeId()]; !ok {
			return nil, grpcstatus.Error(codes.PermissionDenied, "permission denied")
		}
	case "iam.account":
		if !s.accounts[req.GetScopeId()] {
			return nil, grpcstatus.Error(codes.PermissionDenied, "permission denied")
		}
	default:
		return nil, grpcstatus.Error(codes.InvalidArgument, "scope_type: unknown")
	}
	if s.denied[req.GetScopeId()] {
		return nil, grpcstatus.Error(codes.PermissionDenied, "permission denied")
	}
	if len(req.GetTarget().GetResources().GetResources()) == 0 && req.GetTarget().GetAllInScope() == nil {
		return nil, grpcstatus.Error(codes.InvalidArgument, "target required")
	}
	if err := validLabels(req.GetLabels()); err != nil {
		return nil, err
	}
	id := newID("acb")
	key := bindingKey(subjects, req.GetRoleId(), req.GetScopeType(), req.GetScopeId(), req.GetTarget())
	accountID := req.GetScopeId()
	if req.GetScopeType() == "iam.project" {
		accountID = s.projects[req.GetScopeId()]
	}
	return s.startOp(ctx, "Create access binding", &iamv1.CreateAccessBindingMetadata{AccessBindingId: id, AccountId: accountID},
		func() (*anypb.Any, error) {
			for _, b := range s.bindings {
				if b.GetStatus() != iamv1.AccessBinding_REVOKED &&
					bindingKey(b.GetSubjects(), b.GetRoleId(), b.GetScopeType(), b.GetScopeId(), b.GetTarget()) == key {
					return nil, grpcstatus.Error(codes.AlreadyExists, "access binding already exists")
				}
			}
			b := &iamv1.AccessBinding{
				Id: id, Subjects: subjects, RoleId: req.GetRoleId(), ScopeType: req.GetScopeType(), ScopeId: req.GetScopeId(),
				Target: req.GetTarget(), Labels: req.GetLabels(), ExpiresAt: req.GetExpiresAt(),
				Status: iamv1.AccessBinding_ACTIVE, CreatedAt: timestamppb.New(s.now()),
			}
			if len(subjects) > 0 {
				b.SubjectType, b.SubjectId = subjects[0].GetType().String(), subjects[0].GetId()
			}
			s.bindings[id] = b
			return mustAny(b), nil
		})
}

func (h *bindingService) Update(ctx context.Context, req *iamv1.UpdateAccessBindingRequest) (*operationpb.Operation, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bindings[req.GetAccessBindingId()]
	if b == nil || b.GetStatus() == iamv1.AccessBinding_REVOKED {
		return nil, grpcstatus.Errorf(codes.NotFound, "AccessBinding %s not found", req.GetAccessBindingId())
	}
	for _, p := range req.GetUpdateMask().GetPaths() {
		if p != "labels" && p != "deletion_protection" {
			return nil, grpcstatus.Errorf(codes.InvalidArgument, "update_mask: field %q is not updatable", p)
		}
	}
	if err := validLabels(req.GetLabels()); err != nil {
		return nil, err
	}
	id := b.GetId()
	return s.startOp(ctx, "Update access binding", &iamv1.UpdateAccessBindingMetadata{AccessBindingId: id},
		func() (*anypb.Any, error) {
			cur := s.bindings[id]
			for _, p := range req.GetUpdateMask().GetPaths() {
				if p == "labels" {
					cur.Labels = req.GetLabels()
				}
			}
			return mustAny(cur), nil
		})
}

func (h *bindingService) Revoke(ctx context.Context, req *iamv1.RevokeAccessBindingRequest) (*operationpb.Operation, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bindings[req.GetAccessBindingId()]
	if b == nil || b.GetStatus() == iamv1.AccessBinding_REVOKED {
		return nil, grpcstatus.Errorf(codes.NotFound, "AccessBinding %s not found", req.GetAccessBindingId())
	}
	id := b.GetId()
	return s.startOp(ctx, "Revoke access binding", &iamv1.RevokeAccessBindingMetadata{AccessBindingId: id},
		func() (*anypb.Any, error) {
			cur := s.bindings[id]
			cur.Status = iamv1.AccessBinding_REVOKED
			cur.RevokedAt = timestamppb.New(s.now())
			return mustAny(cur), nil
		})
}

func (h *bindingService) ListByAccount(ctx context.Context, req *iamv1.ListAccessBindingsByAccountRequest) (*iamv1.ListAccessBindingsResponse, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.denied[req.GetAccountId()] {
		return nil, grpcstatus.Error(codes.PermissionDenied, "permission denied")
	}
	var all []*iamv1.AccessBinding
	for _, b := range s.bindings {
		if b.GetStatus() == iamv1.AccessBinding_REVOKED && !req.GetIncludeRevoked() {
			continue
		}
		inAccount := (b.GetScopeType() == "iam.account" && b.GetScopeId() == req.GetAccountId()) ||
			(b.GetScopeType() == "iam.project" && s.projects[b.GetScopeId()] == req.GetAccountId())
		if inAccount {
			all = append(all, proto.Clone(b).(*iamv1.AccessBinding))
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].GetId() < all[j].GetId() })
	items, next, err := page(all, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	return &iamv1.ListAccessBindingsResponse{AccessBindings: items, NextPageToken: next}, nil
}

// ── OperationService ─────────────────────────────────────────────────────

type opService struct {
	operationpb.UnimplementedOperationServiceServer
	s *Server
}

func (h *opService) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.ops[req.GetOperationId()]
	if row == nil || row.owner != principalOf(ctx) {
		return nil, grpcstatus.Errorf(codes.NotFound, "operation %s not found", req.GetOperationId())
	}
	if !row.op.GetDone() && !row.background {
		row.pollsLeft--
		if row.pollsLeft <= 0 {
			s.finish(row)
		}
	}
	return proto.Clone(row.op).(*operationpb.Operation), nil
}
