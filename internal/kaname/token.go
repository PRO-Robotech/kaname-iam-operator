// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package kaname

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
)

// GrantTypeJWTBearer — вид выдачи RFC 7523 §2.1 (федеративная полоса kaname).
const GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// TokenRefreshMargin — за сколько до истечения кэшированный токен меняется.
const TokenRefreshMargin = 60 * time.Second

// AssertionSource выдаёт НОВОЕ утверждение на каждый обмен: kaname гасит
// идентификатор однократности (jti), и повтор того же утверждения — отказ.
type AssertionSource interface {
	Assertion(ctx context.Context) (string, error)
}

// FederatedTokenSourceOptions — параметры обмена.
type FederatedTokenSourceOptions struct {
	// TokenURL — токен-эндпоинт kaname.
	TokenURL string
	// RequestedAudience — параметр audience обмена; пусто — не передаётся.
	RequestedAudience string
	// HTTPClient — клиент с TLS.
	HTTPClient *http.Client
	// Assertions — источник утверждений.
	Assertions AssertionSource
	// CallTimeout — дедлайн обмена.
	CallTimeout time.Duration
	// Now — часы; nil — time.Now.
	Now func() time.Time
	// Observe — наблюдатель исхода обмена; nil — без наблюдения.
	Observe func(outcome string)
}

// FederatedTokenSource — вход FEDERATED: утверждение k8s (TokenRequest на
// собственный SA оператора) обменивается на токен доступа kaname по
// jwt-bearer. Токен кэшируется до exp − TokenRefreshMargin. Статического
// секрета нет.
type FederatedTokenSource struct {
	opts FederatedTokenSourceOptions

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewFederatedTokenSource собирает источник.
func NewFederatedTokenSource(opts FederatedTokenSourceOptions) *FederatedTokenSource {
	return &FederatedTokenSource{opts: opts}
}

// Token — действующий токен доступа (из кэша либо новым обменом).
func (s *FederatedTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.token != "" && now.Before(s.expires.Add(-TokenRefreshMargin)) {
		return s.token, nil
	}
	tok, ttl, err := s.exchange(ctx)
	if err != nil {
		s.observe("refused")
		return "", err
	}
	s.observe("accepted")
	s.token, s.expires = "", time.Time{}
	if ttl > TokenRefreshMargin {
		s.token, s.expires = tok, now.Add(ttl)
	}
	return tok, nil
}

// Invalidate снимает кэш.
func (s *FederatedTokenSource) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token, s.expires = "", time.Time{}
}

func (s *FederatedTokenSource) now() time.Time {
	if s.opts.Now != nil {
		return s.opts.Now()
	}
	return time.Now()
}

func (s *FederatedTokenSource) observe(outcome string) {
	if s.opts.Observe != nil {
		s.opts.Observe(outcome)
	}
}

const opTokenExchange = "Token.Exchange"

func (s *FederatedTokenSource) exchange(ctx context.Context) (string, time.Duration, error) {
	callCtx, cancel := context.WithTimeout(ctx, s.opts.CallTimeout)
	defer cancel()
	assertion, err := s.opts.Assertions.Assertion(callCtx)
	if err != nil {
		return "", 0, fmt.Errorf("kaname %s: assertion: %w", opTokenExchange, err)
	}
	form := url.Values{}
	form.Set("grant_type", GrantTypeJWTBearer)
	form.Set("assertion", assertion)
	if s.opts.RequestedAudience != "" {
		form.Set("audience", s.opts.RequestedAudience)
	}
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, s.opts.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("kaname %s: build request: %w", opTokenExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			return "", 0, &Error{Op: opTokenExchange, Code: codes.DeadlineExceeded, Message: fmt.Sprintf("no answer within %s", s.opts.CallTimeout)}
		}
		return "", 0, fmt.Errorf("kaname %s: %w", opTokenExchange, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", 0, fmt.Errorf("kaname %s: read response: %w", opTokenExchange, err)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
	}
	_ = json.Unmarshal(data, &body)
	if resp.StatusCode != http.StatusOK {
		// Текст отказа токен-эндпоинта — код OAuth (invalid_client и т. п.):
		// причину kaname наружу не различает, она в его журнале и метриках.
		msg := body.Error
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return "", 0, &Error{Op: opTokenExchange, Code: codeFromHTTP(resp.StatusCode), HTTPStatus: resp.StatusCode, Message: msg}
	}
	if !strings.EqualFold(body.TokenType, "bearer") {
		return "", 0, fmt.Errorf("kaname %s: token_type %q is not Bearer", opTokenExchange, body.TokenType)
	}
	if body.AccessToken == "" {
		return "", 0, fmt.Errorf("kaname %s: empty access_token", opTokenExchange)
	}
	if body.ExpiresIn <= 0 {
		return "", 0, fmt.Errorf("kaname %s: expires_in %d is not positive", opTokenExchange, body.ExpiresIn)
	}
	return body.AccessToken, time.Duration(body.ExpiresIn) * time.Second, nil
}
