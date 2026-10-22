// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package vault — клиент Vault KV v2 с входом kubernetes-auth.
//
// Оператор пишет ключи учёток в Vault напрямую, узкой ролью, а не через
// VaultClaim: роль видит только пути доставки ключей и больше ничего.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ErrCASMismatch — запись отвергнута: версия изменилась после чтения.
var ErrCASMismatch = errors.New("vault: check-and-set version mismatch")

// Options — параметры клиента.
type Options struct {
	// Address — https://host[:port] Vault.
	Address string
	// HTTPClient — клиент с TLS.
	HTTPClient *http.Client
	// AuthMount — путь метода kubernetes-auth (без auth/).
	AuthMount string
	// Role — роль kubernetes-auth.
	Role string
	// JWT — projected-токен SA для входа; читается на каждый вход.
	JWT func() (string, error)
	// CallTimeout — дедлайн каждого вызова.
	CallTimeout time.Duration
	// Now — часы; nil — time.Now.
	Now func() time.Time
	// Observe — наблюдатель вызовов; nil — без наблюдения.
	Observe func(op, outcome string, d time.Duration)
}

// Record — текущая версия записи KV v2.
type Record struct {
	Data    map[string]string
	Version int64
}

// Client — клиент Vault.
type Client struct {
	opts Options
	base *url.URL

	mu      sync.Mutex
	token   string
	expires time.Time
}

// tokenRenewMargin — доля срока токена Vault, после которой вход повторяется.
const tokenRenewFraction = 0.8

// maxBody — потолок тела ответа Vault.
const maxBody = 1 << 20

var (
	segmentRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	casRe     = regexp.MustCompile(`check-and-set parameter`)
)

// New собирает клиент.
func New(opts Options) (*Client, error) {
	u, err := url.Parse(strings.TrimSuffix(opts.Address, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("vault: address %q is not an absolute URL", opts.Address)
	}
	if opts.HTTPClient == nil || opts.JWT == nil || opts.Role == "" || opts.AuthMount == "" {
		return nil, errors.New("vault: HTTPClient, JWT, Role and AuthMount are required")
	}
	if opts.CallTimeout <= 0 {
		return nil, errors.New("vault: CallTimeout must be positive")
	}
	return &Client{opts: opts, base: u}, nil
}

// Error — отказ Vault.
type Error struct {
	Op       string
	Status   int
	Messages []string
}

func (e *Error) Error() string {
	msg := strings.Join(e.Messages, "; ")
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("vault %s: %d: %s", e.Op, e.Status, strings.TrimSpace(msg))
}

// IsRetryable — временный отказ (сеть, дедлайн, 5xx, 429, запечатан).
func IsRetryable(err error) bool {
	var ve *Error
	if errors.As(err, &ve) {
		return ve.Status == http.StatusTooManyRequests || ve.Status >= 500
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne)
}

// IsForbidden — отказ политики (403 после повторного входа).
func IsForbidden(err error) bool {
	var ve *Error
	return errors.As(err, &ve) && ve.Status == http.StatusForbidden
}

func validPath(mount, path string) error {
	for _, part := range []string{mount, path} {
		if part == "" {
			return errors.New("vault: empty mount or path")
		}
		for _, seg := range strings.Split(part, "/") {
			if seg == "" || seg == "." || seg == ".." || !segmentRe.MatchString(seg) {
				return fmt.Errorf("vault: path segment %q is not allowed", seg)
			}
		}
	}
	return nil
}

// Read читает текущую версию записи; nil — записи нет (или она удалена).
func (c *Client) Read(ctx context.Context, mount, path string) (*Record, error) {
	if err := validPath(mount, path); err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version      int64  `json:"version"`
				DeletionTime string `json:"deletion_time"`
				Destroyed    bool   `json:"destroyed"`
			} `json:"metadata"`
		} `json:"data"`
	}
	status, err := c.call(ctx, "kv.read", http.MethodGet, "/v1/"+mount+"/data/"+path, nil, &out, http.StatusNotFound)
	if err != nil {
		return nil, err
	}
	md := out.Data.Metadata
	if status == http.StatusNotFound || out.Data.Data == nil || md.DeletionTime != "" || md.Destroyed {
		return nil, nil
	}
	rec := &Record{Version: md.Version, Data: make(map[string]string, len(out.Data.Data))}
	for k, v := range out.Data.Data {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("vault kv.read: field %q of %s/%s is not a string", k, mount, path)
		}
		rec.Data[k] = s
	}
	return rec, nil
}

// WriteCAS пишет новую версию при условии, что текущая равна cas (0 — записи
// нет). Чужая версия — ErrCASMismatch.
func (c *Client) WriteCAS(ctx context.Context, mount, path string, data map[string]string, cas int64) (int64, error) {
	if err := validPath(mount, path); err != nil {
		return 0, err
	}
	in := map[string]any{"options": map[string]any{"cas": cas}, "data": data}
	var out struct {
		Data struct {
			Version int64 `json:"version"`
		} `json:"data"`
	}
	if _, err := c.call(ctx, "kv.write", http.MethodPost, "/v1/"+mount+"/data/"+path, in, &out); err != nil {
		var ve *Error
		if errors.As(err, &ve) && ve.Status == http.StatusBadRequest && casRe.MatchString(strings.Join(ve.Messages, " ")) {
			return 0, fmt.Errorf("%w: %s/%s at version %d", ErrCASMismatch, mount, path, cas)
		}
		return 0, err
	}
	if out.Data.Version <= 0 {
		return 0, fmt.Errorf("vault kv.write: %s/%s: no version in the answer", mount, path)
	}
	return out.Data.Version, nil
}

// DeleteAll удаляет запись со всеми версиями (metadata).
func (c *Client) DeleteAll(ctx context.Context, mount, path string) error {
	if err := validPath(mount, path); err != nil {
		return err
	}
	_, err := c.call(ctx, "kv.delete", http.MethodDelete, "/v1/"+mount+"/metadata/"+path, nil, nil, http.StatusNotFound)
	return err
}

// call выполняет вызов с токеном; 403 один раз снимает токен и входит
// заново (токен мог истечь или быть отозван). allowed — статусы, которые не
// являются отказом.
func (c *Client) call(ctx context.Context, op, method, path string, in, out any, allowed ...int) (int, error) {
	for attempt := 0; ; attempt++ {
		tok, err := c.login(ctx)
		if err != nil {
			return 0, err
		}
		status, err := c.raw(ctx, op, method, path, tok, in, out, allowed...)
		var ve *Error
		if attempt == 0 && errors.As(err, &ve) && ve.Status == http.StatusForbidden {
			c.dropToken(tok)
			continue
		}
		return status, err
	}
}

func (c *Client) now() time.Time {
	if c.opts.Now != nil {
		return c.opts.Now()
	}
	return time.Now()
}

func (c *Client) dropToken(tok string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == tok {
		c.token, c.expires = "", time.Time{}
	}
}

func (c *Client) login(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.expires) {
		return c.token, nil
	}
	jwt, err := c.opts.JWT()
	if err != nil {
		return "", fmt.Errorf("vault login: read service account token: %w", err)
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	in := map[string]string{"role": c.opts.Role, "jwt": jwt}
	if _, err := c.raw(ctx, "login", http.MethodPost, "/v1/auth/"+c.opts.AuthMount+"/login", "", in, &out); err != nil {
		return "", err
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("vault login: no client token in the answer")
	}
	ttl := time.Duration(float64(out.Auth.LeaseDuration)*tokenRenewFraction) * time.Second
	c.token, c.expires = out.Auth.ClientToken, c.now().Add(ttl)
	return c.token, nil
}

func (c *Client) raw(ctx context.Context, op, method, path, token string, in, out any, allowed ...int) (status int, err error) {
	start := time.Now()
	outcome := "transport"
	defer func() {
		if c.opts.Observe != nil {
			c.opts.Observe(op, outcome, time.Since(start))
		}
	}()
	callCtx, cancel := context.WithTimeout(ctx, c.opts.CallTimeout)
	defer cancel()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, fmt.Errorf("vault %s: encode: %w", op, err)
		}
		body = bytes.NewReader(b)
	}
	u := *c.base
	u.Path = c.base.Path + path
	req, err := http.NewRequestWithContext(callCtx, method, u.String(), body)
	if err != nil {
		return 0, fmt.Errorf("vault %s: build request: %w", op, err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.opts.HTTPClient.Do(req)
	if err != nil {
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			return 0, fmt.Errorf("vault %s: no answer within %s: %w", op, c.opts.CallTimeout, context.DeadlineExceeded)
		}
		return 0, fmt.Errorf("vault %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			return 0, fmt.Errorf("vault %s: no answer within %s: %w", op, c.opts.CallTimeout, context.DeadlineExceeded)
		}
		return 0, fmt.Errorf("vault %s: read: %w", op, err)
	}
	outcome = fmt.Sprint(resp.StatusCode)
	ok := resp.StatusCode >= 200 && resp.StatusCode <= 299
	for _, a := range allowed {
		if resp.StatusCode == a {
			ok = true
		}
	}
	if !ok {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(data, &e)
		return resp.StatusCode, &Error{Op: op, Status: resp.StatusCode, Messages: e.Errors}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			// Тело может нести значения записи — текст разбора не включается.
			return resp.StatusCode, fmt.Errorf("vault %s: answer (%d bytes) is not the expected JSON", op, len(data))
		}
	}
	return resp.StatusCode, nil
}
