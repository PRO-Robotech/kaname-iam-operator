// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package kaname — клиент REST-фронта kaname /iam/v1.
//
// Почему REST, а не gRPC. Оператор — внешний клиент kaname, и внешняя
// поверхность kaname для таких клиентов — REST-фронт (`/iam/v1/...`) и
// токен-эндпоинт (`POST /iam/v1/token`), который бывает только HTTP. Один
// транспорт — один TLS, один `http.Client` с таймаутом и одна классификация
// отказов. Типы сообщений не пишутся руками: тела запросов и ответов —
// сгенерированные сообщения kaname `pkg/api` @v0.5.0 (= 93ad1b88), а JSON —
// `protojson`, то есть ровно то отображение, которым край kaname
// (grpc-gateway) читает и пишет тела. Имя поля, вид перечисления и int64 как
// строка тогда не расходятся с контрактом молча.
package kaname

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	// Ответ операций удаления — google.protobuf.Empty в Any, детали отказа
	// операции (ErrorInfo и соседи) — тоже Any: protojson разбирает Any только
	// по типу, зарегистрированному в процессе, поэтому клиент связывает эти
	// типы сам (TestClientPackageLinksEveryOperationResponseType).
	_ "google.golang.org/genproto/googleapis/rpc/errdetails"
	_ "google.golang.org/protobuf/types/known/emptypb"
)

// TokenSource выдаёт токен доступа kaname.
type TokenSource interface {
	// Token — действующий токен доступа.
	Token(ctx context.Context) (string, error)
	// Invalidate снимает кэш: следующий Token получит новый.
	Invalidate()
}

// Options — параметры клиента.
type Options struct {
	// BaseURL — origin REST-фронта kaname.
	BaseURL string
	// HTTPClient — клиент с TLS; его Timeout — страховка поверх CallTimeout.
	HTTPClient *http.Client
	// Tokens — источник токена доступа.
	Tokens TokenSource
	// CallTimeout — дедлайн каждого вызова.
	CallTimeout time.Duration
	// Limiter — ограничитель темпа; nil — без ограничения.
	Limiter *rate.Limiter
	// Observe — наблюдатель вызовов (метрики); nil — без наблюдения.
	Observe func(op string, code string, d time.Duration)
}

// Client — клиент kaname /iam/v1.
type Client struct {
	opts Options
	base *url.URL
}

// New собирает клиент.
func New(opts Options) (*Client, error) {
	u, err := url.Parse(strings.TrimSuffix(opts.BaseURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("kaname: base URL %q is not an absolute URL", opts.BaseURL)
	}
	if opts.HTTPClient == nil || opts.Tokens == nil {
		return nil, errors.New("kaname: HTTPClient and Tokens are required")
	}
	if opts.CallTimeout <= 0 {
		return nil, errors.New("kaname: CallTimeout must be positive")
	}
	return &Client{opts: opts, base: u}, nil
}

// MaxListPages — предел страниц одного перечня: сервер, бесконечно
// возвращающий следующую страницу, не держит реконсиляцию вечно.
const MaxListPages = 50

// maxResponseBytes — потолок тела ответа.
const maxResponseBytes = 4 << 20

// listPageSize — размер страницы перечней.
const listPageSize = 100

var (
	unmarshalOpts = protojson.UnmarshalOptions{DiscardUnknown: true}
	marshalOpts   = protojson.MarshalOptions{}
	// idRe — форма идентификатора kaname в сегменте пути. Иное отвергается до
	// вызова: id из status CR не уводит запрос в чужой путь.
	idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

func invalidID(op, field, id string) error {
	return &Error{Op: op, Code: codes.InvalidArgument, Message: fmt.Sprintf("%s %q is not a kaname id", field, id)}
}

// GetServiceAccount читает учётку.
func (c *Client) GetServiceAccount(ctx context.Context, id string) (*iamv1.ServiceAccount, error) {
	const op = "ServiceAccounts.Get"
	if !idRe.MatchString(id) {
		return nil, invalidID(op, "service_account_id", id)
	}
	out := &iamv1.ServiceAccount{}
	if err := c.do(ctx, op, http.MethodGet, "/iam/v1/serviceAccounts/"+id, nil, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// FindServiceAccountByName ищет учётку по имени в аккаунте; nil — не найдена.
func (c *Client) FindServiceAccountByName(ctx context.Context, accountID, name string) (*iamv1.ServiceAccount, error) {
	const op = "ServiceAccounts.List"
	q := url.Values{}
	q.Set("account_id", accountID)
	q.Set("filter", fmt.Sprintf("name = %s", strconv.Quote(name)))
	var found *iamv1.ServiceAccount
	err := c.list(ctx, op, "/iam/v1/serviceAccounts", q, func() proto.Message { return &iamv1.ListServiceAccountsResponse{} },
		func(m proto.Message) string {
			resp := m.(*iamv1.ListServiceAccountsResponse)
			for _, sa := range resp.GetServiceAccounts() {
				// Фильтр сервера — равенство; клиент проверяет его ещё раз,
				// чтобы смена семантики фильтра не подменила учётку.
				if sa.GetName() == name && sa.GetAccountId() == accountID && found == nil {
					found = sa
				}
			}
			return resp.GetNextPageToken()
		})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// CreateServiceAccount запускает создание учётки.
func (c *Client) CreateServiceAccount(ctx context.Context, req *iamv1.CreateServiceAccountRequest) (*operationpb.Operation, error) {
	return c.operation(ctx, "ServiceAccounts.Create", http.MethodPost, "/iam/v1/serviceAccounts", req)
}

// UpdateServiceAccount запускает правку учётки по update_mask.
func (c *Client) UpdateServiceAccount(ctx context.Context, req *iamv1.UpdateServiceAccountRequest) (*operationpb.Operation, error) {
	const op = "ServiceAccounts.Update"
	if !idRe.MatchString(req.GetServiceAccountId()) {
		return nil, invalidID(op, "service_account_id", req.GetServiceAccountId())
	}
	return c.operation(ctx, op, http.MethodPatch, "/iam/v1/serviceAccounts/"+req.GetServiceAccountId(), req)
}

// DisableServiceAccount запускает отключение учётки.
func (c *Client) DisableServiceAccount(ctx context.Context, id string) (*operationpb.Operation, error) {
	const op = "ServiceAccounts.Disable"
	if !idRe.MatchString(id) {
		return nil, invalidID(op, "service_account_id", id)
	}
	return c.operation(ctx, op, http.MethodPost, "/iam/v1/serviceAccounts/"+id+":disable", &iamv1.DisableServiceAccountRequest{ServiceAccountId: id})
}

// EnableServiceAccount запускает включение учётки.
func (c *Client) EnableServiceAccount(ctx context.Context, id string) (*operationpb.Operation, error) {
	const op = "ServiceAccounts.Enable"
	if !idRe.MatchString(id) {
		return nil, invalidID(op, "service_account_id", id)
	}
	return c.operation(ctx, op, http.MethodPost, "/iam/v1/serviceAccounts/"+id+":enable", &iamv1.EnableServiceAccountRequest{ServiceAccountId: id})
}

// DeleteServiceAccount запускает удаление учётки.
func (c *Client) DeleteServiceAccount(ctx context.Context, id string) (*operationpb.Operation, error) {
	const op = "ServiceAccounts.Delete"
	if !idRe.MatchString(id) {
		return nil, invalidID(op, "service_account_id", id)
	}
	return c.operation(ctx, op, http.MethodDelete, "/iam/v1/serviceAccounts/"+id, nil)
}

// IssueKey запускает выпуск ключа учётки.
func (c *Client) IssueKey(ctx context.Context, req *iamv1.IssueSAKeyRequest) (*operationpb.Operation, error) {
	const op = "SAKeys.Issue"
	if !idRe.MatchString(req.GetServiceAccountId()) {
		return nil, invalidID(op, "service_account_id", req.GetServiceAccountId())
	}
	return c.operation(ctx, op, http.MethodPost, "/iam/v1/serviceAccounts/"+req.GetServiceAccountId()+"/keys", req)
}

// ListKeys перечисляет ключи учётки (все страницы).
func (c *Client) ListKeys(ctx context.Context, serviceAccountID string) ([]*iamv1.ServiceAccountOAuthClient, error) {
	const op = "SAKeys.List"
	if !idRe.MatchString(serviceAccountID) {
		return nil, invalidID(op, "service_account_id", serviceAccountID)
	}
	var out []*iamv1.ServiceAccountOAuthClient
	err := c.list(ctx, op, "/iam/v1/serviceAccounts/"+serviceAccountID+"/keys", url.Values{},
		func() proto.Message { return &iamv1.ListSAKeysResponse{} },
		func(m proto.Message) string {
			resp := m.(*iamv1.ListSAKeysResponse)
			out = append(out, resp.GetKeys()...)
			return resp.GetNextPageToken()
		})
	return out, err
}

// RevokeKey запускает отзыв ключа.
func (c *Client) RevokeKey(ctx context.Context, serviceAccountID, keyID string) (*operationpb.Operation, error) {
	const op = "SAKeys.Revoke"
	if !idRe.MatchString(serviceAccountID) {
		return nil, invalidID(op, "service_account_id", serviceAccountID)
	}
	if !idRe.MatchString(keyID) {
		return nil, invalidID(op, "key_id", keyID)
	}
	return c.operation(ctx, op, http.MethodDelete, "/iam/v1/serviceAccounts/"+serviceAccountID+"/keys/"+keyID, nil)
}

// GetOperation читает операцию.
func (c *Client) GetOperation(ctx context.Context, id string) (*operationpb.Operation, error) {
	const op = "Operations.Get"
	if !idRe.MatchString(id) {
		return nil, invalidID(op, "operation_id", id)
	}
	out := &operationpb.Operation{}
	if err := c.do(ctx, op, http.MethodGet, "/operations/"+id, nil, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateAccessBinding запускает заведение выдачи.
func (c *Client) CreateAccessBinding(ctx context.Context, req *iamv1.CreateAccessBindingRequest) (*operationpb.Operation, error) {
	return c.operation(ctx, "AccessBindings.Create", http.MethodPost, "/iam/v1/accessBindings", req)
}

// GetAccessBinding читает выдачу.
func (c *Client) GetAccessBinding(ctx context.Context, id string) (*iamv1.AccessBinding, error) {
	const op = "AccessBindings.Get"
	if !idRe.MatchString(id) {
		return nil, invalidID(op, "access_binding_id", id)
	}
	out := &iamv1.AccessBinding{}
	if err := c.do(ctx, op, http.MethodGet, "/iam/v1/accessBindings/"+id, nil, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateAccessBinding запускает правку меток выдачи (цель неизменяема).
func (c *Client) UpdateAccessBinding(ctx context.Context, req *iamv1.UpdateAccessBindingRequest) (*operationpb.Operation, error) {
	const op = "AccessBindings.Update"
	if !idRe.MatchString(req.GetAccessBindingId()) {
		return nil, invalidID(op, "access_binding_id", req.GetAccessBindingId())
	}
	return c.operation(ctx, op, http.MethodPatch, "/iam/v1/accessBindings/"+req.GetAccessBindingId(), req)
}

// RevokeAccessBinding запускает отзыв выдачи.
func (c *Client) RevokeAccessBinding(ctx context.Context, id string) (*operationpb.Operation, error) {
	const op = "AccessBindings.Revoke"
	if !idRe.MatchString(id) {
		return nil, invalidID(op, "access_binding_id", id)
	}
	return c.operation(ctx, op, http.MethodPost, "/iam/v1/accessBindings/"+id+":revoke", &iamv1.RevokeAccessBindingRequest{AccessBindingId: id})
}

// ListAccessBindingsByAccount перечисляет действующие выдачи аккаунта (все
// страницы, все области аккаунта).
func (c *Client) ListAccessBindingsByAccount(ctx context.Context, accountID string) ([]*iamv1.AccessBinding, error) {
	const op = "AccessBindings.ListByAccount"
	if !idRe.MatchString(accountID) {
		return nil, invalidID(op, "account_id", accountID)
	}
	var out []*iamv1.AccessBinding
	err := c.list(ctx, op, "/iam/v1/accounts/"+accountID+"/accessBindings", url.Values{},
		func() proto.Message { return &iamv1.ListAccessBindingsResponse{} },
		func(m proto.Message) string {
			resp := m.(*iamv1.ListAccessBindingsResponse)
			out = append(out, resp.GetAccessBindings()...)
			return resp.GetNextPageToken()
		})
	return out, err
}

// FindRole ищет роль по имени в каталоге аккаунта (системные + свои);
// ровно одно совпадение, иначе отказ.
func (c *Client) FindRole(ctx context.Context, name, accountID string) (*iamv1.Role, error) {
	const op = "Roles.List"
	q := url.Values{}
	q.Set("filter", fmt.Sprintf("name = %s", strconv.Quote(name)))
	if accountID != "" {
		q.Set("account_id", accountID)
	}
	var matches []*iamv1.Role
	err := c.list(ctx, op, "/iam/v1/roles", q, func() proto.Message { return &iamv1.ListRolesResponse{} },
		func(m proto.Message) string {
			resp := m.(*iamv1.ListRolesResponse)
			for _, r := range resp.GetRoles() {
				if r.GetName() == name {
					matches = append(matches, r)
				}
			}
			return resp.GetNextPageToken()
		})
	if err != nil {
		return nil, err
	}
	switch len(matches) {
	case 0:
		return nil, &Error{Op: op, Code: codes.NotFound, Message: fmt.Sprintf("role %q not found", name)}
	case 1:
		return matches[0], nil
	default:
		return nil, &Error{Op: op, Code: codes.InvalidArgument, Message: fmt.Sprintf("role name %q is ambiguous: %d roles carry it", name, len(matches))}
	}
}

// OperationResult разбирает завершённую операцию: отказ операции — *Error,
// ответ — в out (nil — ответ не нужен). Незавершённая — ErrOperationNotDone.
func OperationResult(op *operationpb.Operation, out proto.Message) error {
	if op == nil {
		return errors.New("kaname: nil operation")
	}
	if !op.GetDone() {
		return ErrOperationNotDone
	}
	if st := op.GetError(); st != nil {
		return &Error{Op: "Operation " + op.GetId(), Code: codeFromWire(int64(st.GetCode())), Message: st.GetMessage()}
	}
	if out == nil {
		return nil
	}
	resp := op.GetResponse()
	if resp == nil {
		return fmt.Errorf("kaname: operation %s is done without a response", op.GetId())
	}
	if err := resp.UnmarshalTo(out); err != nil {
		return fmt.Errorf("kaname: operation %s response is %s, not %s", op.GetId(), resp.GetTypeUrl(), out.ProtoReflect().Descriptor().FullName())
	}
	return nil
}

func (c *Client) operation(ctx context.Context, op, method, path string, req proto.Message) (*operationpb.Operation, error) {
	out := &operationpb.Operation{}
	if err := c.do(ctx, op, method, path, nil, req, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) list(ctx context.Context, op, path string, q url.Values,
	newPage func() proto.Message, consume func(proto.Message) string,
) error {
	token := ""
	for range MaxListPages {
		pq := url.Values{}
		for k, v := range q {
			pq[k] = v
		}
		pq.Set("page_size", strconv.Itoa(listPageSize))
		if token != "" {
			pq.Set("page_token", token)
		}
		page := newPage()
		if err := c.do(ctx, op, http.MethodGet, path, pq, nil, page); err != nil {
			return err
		}
		token = consume(page)
		if token == "" {
			return nil
		}
	}
	return fmt.Errorf("kaname %s: more than %d pages", op, MaxListPages)
}

// do выполняет вызов с собственным дедлайном. Отказ 401 один раз снимает
// кэш токена и повторяет вызов: токен мог истечь раньше, чем кэш это узнал.
func (c *Client) do(ctx context.Context, op, method, path string, q url.Values, req, out proto.Message) error {
	var body []byte
	if req != nil {
		b, err := marshalOpts.Marshal(req)
		if err != nil {
			return fmt.Errorf("kaname %s: encode request: %w", op, err)
		}
		body = b
	}
	for attempt := 0; ; attempt++ {
		err := c.once(ctx, op, method, path, q, body, out)
		var ke *Error
		if attempt == 0 && errors.As(err, &ke) && ke.HTTPStatus == http.StatusUnauthorized {
			c.opts.Tokens.Invalidate()
			continue
		}
		return err
	}
}

func (c *Client) once(ctx context.Context, op, method, path string, q url.Values, body []byte, out proto.Message) (err error) {
	start := time.Now()
	code := "transport"
	defer func() {
		if c.opts.Observe != nil {
			c.opts.Observe(op, code, time.Since(start))
		}
	}()
	if c.opts.Limiter != nil {
		if err := c.opts.Limiter.Wait(ctx); err != nil {
			return fmt.Errorf("kaname %s: rate limiter: %w", op, err)
		}
	}
	callCtx, cancel := context.WithTimeout(ctx, c.opts.CallTimeout)
	defer cancel()

	token, err := c.opts.Tokens.Token(callCtx)
	if err != nil {
		code = "token"
		return fmt.Errorf("kaname %s: access token: %w", op, err)
	}
	u := *c.base
	u.Path = c.base.Path + path
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(callCtx, method, u.String(), rdr)
	if err != nil {
		return fmt.Errorf("kaname %s: build request: %w", op, err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.opts.HTTPClient.Do(httpReq)
	if err != nil {
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			code = codes.DeadlineExceeded.String()
			return &Error{Op: op, Code: codes.DeadlineExceeded, Message: fmt.Sprintf("no answer within %s", c.opts.CallTimeout)}
		}
		return fmt.Errorf("kaname %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			code = codes.DeadlineExceeded.String()
			return &Error{Op: op, Code: codes.DeadlineExceeded, Message: fmt.Sprintf("no answer within %s", c.opts.CallTimeout)}
		}
		return fmt.Errorf("kaname %s: read response: %w", op, err)
	}
	if len(data) > maxResponseBytes {
		code = "oversize"
		return fmt.Errorf("kaname %s: response exceeds %d bytes", op, maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ke := errorFromResponse(op, resp.StatusCode, data)
		code = ke.Code.String()
		return ke
	}
	code = codes.OK.String()
	if out == nil {
		return nil
	}
	if err := unmarshalOpts.Unmarshal(data, out); err != nil {
		// Детали отказа операции — Any неизвестного клиенту типа (новая
		// ревизия kaname) — не делают операцию неразбираемой: код и текст
		// отказа дороже деталей, и разбор повторяется без них.
		if _, isOp := out.(*operationpb.Operation); isOp {
			if trimmed, ok := withoutErrorDetails(data); ok && unmarshalOpts.Unmarshal(trimmed, out) == nil {
				return nil
			}
		}
		// Текст разбора не включается: тело может нести предъявительский
		// секрет (ответ выпуска ключа), а текст ошибки уходит в журнал.
		code = "decode"
		return fmt.Errorf("kaname %s: response body (%d bytes) is not a %s", op, len(data), out.ProtoReflect().Descriptor().FullName())
	}
	return nil
}

// withoutErrorDetails снимает error.details с JSON операции.
func withoutErrorDetails(data []byte) ([]byte, bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil {
		return nil, false
	}
	raw, ok := obj["error"]
	if !ok {
		return nil, false
	}
	var st map[string]json.RawMessage
	if json.Unmarshal(raw, &st) != nil {
		return nil, false
	}
	if _, has := st["details"]; !has {
		return nil, false
	}
	delete(st, "details")
	b, err := json.Marshal(st)
	if err != nil {
		return nil, false
	}
	obj["error"] = b
	out, err := json.Marshal(obj)
	return out, err == nil
}

// errorFromResponse строит отказ из тела края (google.rpc.Status в JSON); тело
// не того вида — код выводится из статуса HTTP.
func errorFromResponse(op string, status int, data []byte) *Error {
	var st struct {
		Code    *int   `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &st); err == nil && st.Code != nil && *st.Code > 0 {
		if c := codeFromWire(int64(*st.Code)); c != codes.Unknown || *st.Code == int(codes.Unknown) {
			return &Error{Op: op, Code: c, HTTPStatus: status, Message: st.Message}
		}
	}
	return &Error{Op: op, Code: codeFromHTTP(status), HTTPStatus: status, Message: http.StatusText(status)}
}

func codeFromHTTP(status int) codes.Code {
	switch status {
	case http.StatusBadRequest:
		return codes.InvalidArgument
	case http.StatusUnauthorized:
		return codes.Unauthenticated
	case http.StatusForbidden:
		return codes.PermissionDenied
	case http.StatusNotFound:
		return codes.NotFound
	case http.StatusConflict:
		return codes.AlreadyExists
	case http.StatusTooManyRequests:
		return codes.ResourceExhausted
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return codes.Unavailable
	case http.StatusGatewayTimeout:
		return codes.DeadlineExceeded
	case http.StatusInternalServerError:
		return codes.Internal
	default:
		return codes.Unknown
	}
}
