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
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/anypb"
)

type staticTokens struct {
	mu          sync.Mutex
	tokens      []string
	invalidated int
}

func (s *staticTokens) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[min(s.invalidated, len(s.tokens)-1)], nil
}

func (s *staticTokens) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidated++
}

func newTestClient(t *testing.T, h http.Handler) (*Client, *staticTokens) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	tokens := &staticTokens{tokens: []string{"tok-1", "tok-2"}}
	c, err := New(Options{
		BaseURL:     srv.URL,
		HTTPClient:  srv.Client(),
		Tokens:      tokens,
		CallTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil {
		t.Fatal("New returned nil client")
	}
	return c, tokens
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func TestGetServiceAccountSendsBearerAndDecodes(t *testing.T) {
	var gotAuth, gotPath string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		writeJSON(w, 200, `{"id":"sva1","accountId":"acc1","name":"ci","enabled":true,"labels":{"k8s.in-cloud.io/uid":"u1"},"futureField":"x"}`)
	}))
	sa, err := c.GetServiceAccount(context.Background(), "sva1")
	if err != nil {
		t.Fatalf("GetServiceAccount: %v", err)
	}
	if gotAuth != "Bearer tok-1" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotPath != "/iam/v1/serviceAccounts/sva1" {
		t.Errorf("path = %q", gotPath)
	}
	if sa.GetId() != "sva1" || sa.GetAccountId() != "acc1" || !sa.GetEnabled() || sa.GetLabels()["k8s.in-cloud.io/uid"] != "u1" {
		t.Errorf("decoded %v", sa)
	}
}

func TestErrorBodyBecomesTypedError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, `{"code":5,"message":"ServiceAccount sva9 not found","details":[]}`)
	}))
	_, err := c.GetServiceAccount(context.Background(), "sva9")
	var ke *Error
	if !errors.As(err, &ke) {
		t.Fatalf("err %v is not *Error", err)
	}
	if ke.Code != codes.NotFound || ke.HTTPStatus != 404 || !strings.Contains(ke.Message, "sva9 not found") {
		t.Errorf("typed error = %+v", ke)
	}
	if Classify(err) != ClassNotFound {
		t.Errorf("class = %s", Classify(err))
	}
}

func TestErrorWithoutJSONBodyIsDerivedFromStatus(t *testing.T) {
	for status, want := range map[int]codes.Code{
		400: codes.InvalidArgument,
		401: codes.Unauthenticated,
		403: codes.PermissionDenied,
		404: codes.NotFound,
		409: codes.AlreadyExists,
		429: codes.ResourceExhausted,
		502: codes.Unavailable,
		503: codes.Unavailable,
		504: codes.DeadlineExceeded,
		500: codes.Internal,
		418: codes.Unknown,
	} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "<html>gateway</html>")
			}))
			_, err := c.GetOperation(context.Background(), "op1")
			if got := CodeOf(err); got != want {
				t.Errorf("status %d -> %s, want %s (err %v)", status, got, want, err)
			}
		})
	}
}

func TestEveryCallHasItsOwnDeadline(t *testing.T) {
	release := make(chan struct{})
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer close(release)
	start := time.Now()
	_, err := c.GetServiceAccount(context.Background(), "sva1")
	if err == nil {
		t.Fatal("hung call returned no error")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("call took %s: per-call deadline not applied", el)
	}
	if Classify(err) != ClassRetryable {
		t.Errorf("deadline class = %s (%v)", Classify(err), err)
	}
}

func TestUnauthenticatedRefreshesTokenOnce(t *testing.T) {
	var calls atomic.Int32
	c, tokens := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "Bearer tok-1" {
			writeJSON(w, 401, `{"code":16,"message":"token expired"}`)
			return
		}
		writeJSON(w, 200, `{"id":"sva1"}`)
	}))
	if _, err := c.GetServiceAccount(context.Background(), "sva1"); err != nil {
		t.Fatalf("after refresh: %v", err)
	}
	if tokens.invalidated != 1 || calls.Load() != 2 {
		t.Errorf("invalidated=%d calls=%d, want 1 and 2", tokens.invalidated, calls.Load())
	}
}

func TestPersistentUnauthenticatedIsForbiddenNotLoop(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeJSON(w, 401, `{"code":16,"message":"no"}`)
	}))
	_, err := c.GetServiceAccount(context.Background(), "sva1")
	if Classify(err) != ClassForbidden {
		t.Errorf("class = %s (%v)", Classify(err), err)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want exactly one retry", calls.Load())
	}
}

func TestFindServiceAccountByNameFiltersAndPages(t *testing.T) {
	var queries []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		q := r.URL.Query()
		if r.URL.Path != "/iam/v1/serviceAccounts" || q.Get("account_id") != "acc1" || q.Get("filter") != `name = "zot-ci"` {
			writeJSON(w, 400, `{"code":3,"message":"bad query"}`)
			return
		}
		if q.Get("page_token") == "" {
			// Подстрока имени — не совпадение: равенство проверяет и клиент.
			writeJSON(w, 200, `{"serviceAccounts":[{"id":"sva0","accountId":"acc1","name":"zot-ci-old"},{"id":"svaX","accountId":"acc2","name":"zot-ci"}],"nextPageToken":"p2"}`)
			return
		}
		writeJSON(w, 200, `{"serviceAccounts":[{"id":"sva1","accountId":"acc1","name":"zot-ci"}]}`)
	}))
	sa, err := c.FindServiceAccountByName(context.Background(), "acc1", "zot-ci")
	if err != nil {
		t.Fatalf("Find: %v (queries %v)", err, queries)
	}
	if sa == nil || sa.GetId() != "sva1" {
		t.Fatalf("found %v", sa)
	}
	if len(queries) != 2 {
		t.Errorf("pages read = %d, want 2", len(queries))
	}
}

func TestFindServiceAccountByNameAbsentIsNil(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"serviceAccounts":[]}`)
	}))
	sa, err := c.FindServiceAccountByName(context.Background(), "acc1", "zot-ci")
	if err != nil || sa != nil {
		t.Fatalf("absent: sa=%v err=%v", sa, err)
	}
}

func TestListStopsAtThePageCeiling(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeJSON(w, 200, `{"keys":[],"nextPageToken":"again"}`)
	}))
	_, err := c.ListKeys(context.Background(), "sva1")
	if err == nil {
		t.Fatal("endless paging accepted")
	}
	if int(calls.Load()) != MaxListPages {
		t.Errorf("calls = %d, want %d", calls.Load(), MaxListPages)
	}
}

func TestIssueKeySendsContractFields(t *testing.T) {
	var body map[string]any
	var gotPath, gotMethod string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_ = json.NewDecoder(r.Body).Decode(&body)
		writeJSON(w, 200, `{"id":"op1","done":false}`)
	}))
	op, err := c.IssueKey(context.Background(), &iamv1.IssueSAKeyRequest{
		ServiceAccountId: "sva1",
		TtlSeconds:       2592000,
		CredentialKind:   iamv1.CredentialKind_CREDENTIAL_KIND_SECRET,
		Name:             "push-abcd",
		Labels:           map[string]string{"k8s.in-cloud.io/nonce": "n1"},
	})
	if err != nil {
		t.Fatalf("IssueKey: %v", err)
	}
	if op.GetId() != "op1" {
		t.Errorf("op = %v", op)
	}
	if gotMethod != http.MethodPost || gotPath != "/iam/v1/serviceAccounts/sva1/keys" {
		t.Errorf("%s %s", gotMethod, gotPath)
	}
	if body["credentialKind"] != "CREDENTIAL_KIND_SECRET" || body["ttlSeconds"] != "2592000" {
		t.Errorf("body = %v", body)
	}
	labels, _ := body["labels"].(map[string]any)
	if labels["k8s.in-cloud.io/nonce"] != "n1" {
		t.Errorf("labels = %v", body["labels"])
	}
}

func TestMutationPathsAndVerbs(t *testing.T) {
	type call struct{ method, path string }
	var got []call
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, call{r.Method, r.URL.Path})
		writeJSON(w, 200, `{"id":"op","done":true}`)
	}))
	ctx := context.Background()
	steps := []func() error{
		func() error {
			_, e := c.CreateServiceAccount(ctx, &iamv1.CreateServiceAccountRequest{AccountId: "a", Name: "n"})
			return e
		},
		func() error {
			_, e := c.UpdateServiceAccount(ctx, &iamv1.UpdateServiceAccountRequest{ServiceAccountId: "s"})
			return e
		},
		func() error { _, e := c.DisableServiceAccount(ctx, "s"); return e },
		func() error { _, e := c.EnableServiceAccount(ctx, "s"); return e },
		func() error { _, e := c.DeleteServiceAccount(ctx, "s"); return e },
		func() error { _, e := c.RevokeKey(ctx, "s", "k"); return e },
		func() error { _, e := c.CreateAccessBinding(ctx, &iamv1.CreateAccessBindingRequest{}); return e },
		func() error {
			_, e := c.UpdateAccessBinding(ctx, &iamv1.UpdateAccessBindingRequest{AccessBindingId: "b"})
			return e
		},
		func() error { _, e := c.RevokeAccessBinding(ctx, "b"); return e },
		func() error { _, e := c.GetOperation(ctx, "op9"); return e },
	}
	for i, s := range steps {
		if err := s(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	want := []call{
		{"POST", "/iam/v1/serviceAccounts"},
		{"PATCH", "/iam/v1/serviceAccounts/s"},
		{"POST", "/iam/v1/serviceAccounts/s:disable"},
		{"POST", "/iam/v1/serviceAccounts/s:enable"},
		{"DELETE", "/iam/v1/serviceAccounts/s"},
		{"DELETE", "/iam/v1/serviceAccounts/s/keys/k"},
		{"POST", "/iam/v1/accessBindings"},
		{"PATCH", "/iam/v1/accessBindings/b"},
		{"POST", "/iam/v1/accessBindings/b:revoke"},
		{"GET", "/operations/op9"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("calls\n got %v\nwant %v", got, want)
	}
}

func TestForeignPathSegmentIsRefusedBeforeTheCall(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeJSON(w, 200, `{"id":"x"}`)
	}))
	_, err := c.GetServiceAccount(context.Background(), "../accounts/x")
	if Classify(err) != ClassInvalid {
		t.Errorf("class = %s (%v)", Classify(err), err)
	}
	if calls.Load() != 0 {
		t.Errorf("request sent for a foreign id: %d calls", calls.Load())
	}
	// Законный близнец: id формы kaname доходит до сервера.
	if _, err := c.GetServiceAccount(context.Background(), "sva0a1b2c3"); err != nil || calls.Load() != 1 {
		t.Errorf("lawful id: err %v calls %d", err, calls.Load())
	}
}

// Усыновление выдачи ищет по аккаунту области: перечень по субъекту kaname
// требует права уровня кластера и учётке оператора (editor на аккаунте,
// admin на проекте) не отдаётся — замер на стенде kaname @93ad1b88: 403
// AUTHZ_DENIED на :listBySubject, 200 на /accounts/{id}/accessBindings.
func TestListAccessBindingsByAccountQuery(t *testing.T) {
	var q string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.Path + "?" + r.URL.RawQuery
		writeJSON(w, 200, `{"accessBindings":[{"id":"acb1","roleId":"r1","scopeType":"iam.project","scopeId":"p1","labels":{"k8s.in-cloud.io/uid":"u"}}]}`)
	}))
	abs, err := c.ListAccessBindingsByAccount(context.Background(), "acc1")
	if err != nil || len(abs) != 1 || abs[0].GetId() != "acb1" {
		t.Fatalf("abs=%v err=%v", abs, err)
	}
	if !strings.HasPrefix(q, "/iam/v1/accounts/acc1/accessBindings?") || strings.Contains(q, "include_revoked=true") {
		t.Errorf("query = %s", q)
	}
	if _, err := c.ListAccessBindingsByAccount(context.Background(), "../x"); Classify(err) != ClassInvalid {
		t.Errorf("foreign account id: %v", err)
	}
}

// Роль выдачи — только системная: роль арендатора с тем же именем (её вправе
// завести администратор аккаунта) не подменяет системную и не делает поиск
// неоднозначным. Каждый случай меняет против законного близнеца один факт —
// признак is_system и число ролей с именем.
func TestFindRoleAcceptsOnlySystemRoles(t *testing.T) {
	var resp string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("filter") != `name = "registry.pusher"` || r.URL.Query().Has("account_id") {
			writeJSON(w, 400, `{"code":3,"message":"q"}`)
			return
		}
		writeJSON(w, 200, resp)
	}))
	find := func() (*iamv1.Role, error) { return c.FindSystemRole(context.Background(), "registry.pusher") }

	// Законный близнец: одна системная роль с этим именем.
	resp = `{"roles":[{"id":"r1","name":"registry.pusher","isSystem":true},{"id":"r2","name":"registry.pusher-x","isSystem":true}]}`
	if role, err := find(); err != nil || role.GetId() != "r1" {
		t.Fatalf("system role: role=%v err=%v", role, err)
	}
	// Только роль арендатора с тем же именем — отказ: её правила задал арендатор.
	resp = `{"roles":[{"id":"r9","name":"registry.pusher","accountId":"acc1"}]}`
	if role, err := find(); Classify(err) != ClassNotFound {
		t.Errorf("tenant role accepted: role=%v err=%v", role, err)
	}
	// Системная и роль арендатора с тем же именем — системная, без неоднозначности.
	resp = `{"roles":[{"id":"r1","name":"registry.pusher","isSystem":true},{"id":"r9","name":"registry.pusher","accountId":"acc1"}]}`
	if role, err := find(); err != nil || role.GetId() != "r1" {
		t.Errorf("system role beside a tenant namesake: role=%v err=%v", role, err)
	}
	resp = `{"roles":[]}`
	if _, err := find(); Classify(err) != ClassNotFound {
		t.Errorf("absent role class = %s (%v)", Classify(err), err)
	}
	resp = `{"roles":[{"id":"r1","name":"registry.pusher","isSystem":true},{"id":"r3","name":"registry.pusher","isSystem":true}]}`
	if _, err := find(); Classify(err) != ClassInvalid {
		t.Errorf("ambiguous system role class = %s (%v)", Classify(err), err)
	}
}

func TestOperationResult(t *testing.T) {
	sa := &iamv1.ServiceAccount{Id: "sva1"}
	anyResp, _ := anypb.New(sa)
	var out iamv1.ServiceAccount
	if err := OperationResult(&operationpb.Operation{Id: "op", Done: true, Result: &operationpb.Operation_Response{Response: anyResp}}, &out); err != nil {
		t.Fatalf("done ok: %v", err)
	}
	if out.GetId() != "sva1" {
		t.Errorf("out = %v", &out)
	}
	err := OperationResult(&operationpb.Operation{Id: "op", Done: true, Result: &operationpb.Operation_Error{Error: &rpcstatus.Status{Code: int32(codes.AlreadyExists), Message: "dup"}}}, &out)
	if Classify(err) != ClassAlreadyExists {
		t.Errorf("done error class = %s (%v)", Classify(err), err)
	}
	if !errors.Is(OperationResult(&operationpb.Operation{Id: "op"}, nil), ErrOperationNotDone) {
		t.Error("not done is not ErrOperationNotDone")
	}
	// Ответ иного типа, чем ждёт вызывающий, — отказ, а не пустой результат.
	if err := OperationResult(&operationpb.Operation{Id: "op", Done: true, Result: &operationpb.Operation_Response{Response: anyResp}}, &iamv1.AccessBinding{}); err == nil {
		t.Error("foreign response type accepted")
	}
}

func TestOperationResponseDecodedFromJSON(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"id":"op1","done":true,"response":{"@type":"type.googleapis.com/kaname.cloud.iam.v1.IssueSAKeyResponse","keyId":"sak1","secret":"kacho_sak1_abc"}}`)
	}))
	op, err := c.IssueKey(context.Background(), &iamv1.IssueSAKeyRequest{ServiceAccountId: "sva1"})
	if err != nil {
		t.Fatalf("IssueKey: %v", err)
	}
	var out iamv1.IssueSAKeyResponse
	if err := OperationResult(op, &out); err != nil {
		t.Fatalf("result: %v", err)
	}
	if out.GetKeyId() != "sak1" || out.GetSecret() != "kacho_sak1_abc" {
		t.Errorf("out = keyId %q", out.GetKeyId())
	}
}

func TestDecodeFailureDoesNotEchoTheBody(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"id":"op1","done":true,"response":{"secret":"kacho_LEAK_value"`)
	}))
	_, err := c.IssueKey(context.Background(), &iamv1.IssueSAKeyRequest{ServiceAccountId: "sva1"})
	if err == nil {
		t.Fatal("truncated body accepted")
	}
	if strings.Contains(err.Error(), "kacho_LEAK_value") {
		t.Errorf("error echoes the secret: %v", err)
	}
}

// Отказ операции kaname несёт детали (google.rpc.ErrorInfo и, в будущих
// ревизиях, типы, которых клиент не знает). Неизвестный тип детали не делает
// операцию неразбираемой: код и текст отказа доходят до классификации.
// Замер на стенде kaname @93ad1b88: удаление учётки с ключом — операция с
// ошибкой FAILED_PRECONDITION и деталью ErrorInfo REFERENCE_IN_USE.
func TestOperationErrorWithUnknownDetailsDecodes(t *testing.T) {
	for name, detail := range map[string]string{
		"error info": `{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"REFERENCE_IN_USE","domain":"iam.kaname.cloud","metadata":{}}`,
		"future":     `{"@type":"type.googleapis.com/kaname.future.v9.Detail","x":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, `{"id":"op1","done":true,"metadata":{"@type":"type.googleapis.com/kaname.cloud.iam.v1.DeleteServiceAccountMetadata","serviceAccountId":"sva1"},`+
					`"error":{"code":9,"message":"resource is still referenced by other resources","details":[`+detail+`]}}`)
			}))
			op, err := c.GetOperation(context.Background(), "op1")
			if err != nil {
				t.Fatalf("GetOperation: %v", err)
			}
			err = OperationResult(op, nil)
			if CodeOf(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "still referenced") {
				t.Fatalf("result = %v", err)
			}
		})
	}
}
