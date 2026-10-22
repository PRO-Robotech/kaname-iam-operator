// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package kaname

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type countingAssertions struct {
	n atomic.Int32
}

func (a *countingAssertions) Assertion(context.Context) (string, error) {
	n := a.n.Add(1)
	return fmt.Sprintf("assertion-%d", n), nil
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func tokenServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	return srv
}

func TestFederatedExchangeFormAndCache(t *testing.T) {
	var forms []string
	var mu sync.Mutex
	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/iam/v1/token" {
			writeJSON(w, 405, `{"error":"invalid_request"}`)
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSON(w, 400, `{"error":"invalid_request"}`)
			return
		}
		mu.Lock()
		forms = append(forms, r.PostForm.Encode())
		n := len(forms)
		mu.Unlock()
		writeJSON(w, 200, fmt.Sprintf(`{"access_token":"at-%d","token_type":"Bearer","expires_in":600}`, n))
	})
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	assertions := &countingAssertions{}
	ts := NewFederatedTokenSource(FederatedTokenSourceOptions{
		TokenURL:          srv.URL + "/iam/v1/token",
		RequestedAudience: "kacho-api",
		HTTPClient:        srv.Client(),
		Assertions:        assertions,
		CallTimeout:       time.Second,
		Now:               clock.Now,
	})
	ctx := context.Background()
	tok, err := ts.Token(ctx)
	if err != nil || tok != "at-1" {
		t.Fatalf("first token %q err %v", tok, err)
	}
	if len(forms) != 1 || forms[0] != "assertion=assertion-1&audience=kacho-api&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer" {
		t.Fatalf("form = %v", forms)
	}
	clock.Advance(500 * time.Second)
	if tok, _ := ts.Token(ctx); tok != "at-1" {
		t.Errorf("token before exp-60s re-exchanged: %q", tok)
	}
	clock.Advance(41 * time.Second)
	if tok, _ := ts.Token(ctx); tok != "at-2" {
		t.Errorf("token after exp-60s = %q, want a new exchange", tok)
	}
	if assertions.n.Load() != 2 {
		t.Errorf("assertions minted = %d: every exchange needs a fresh one", assertions.n.Load())
	}
	ts.Invalidate()
	if tok, _ := ts.Token(ctx); tok != "at-3" {
		t.Errorf("token after Invalidate = %q", tok)
	}
}

func TestFederatedExchangeWithoutRequestedAudienceOmitsTheParameter(t *testing.T) {
	var form string
	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm.Encode()
		writeJSON(w, 200, `{"access_token":"at","token_type":"bearer","expires_in":600}`)
	})
	ts := NewFederatedTokenSource(FederatedTokenSourceOptions{
		TokenURL: srv.URL, HTTPClient: srv.Client(), Assertions: &countingAssertions{}, CallTimeout: time.Second,
	})
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(form, "audience") {
		t.Errorf("form carries audience: %s", form)
	}
}

func TestFederatedExchangeRefusals(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		class  Class
		text   string
	}{
		{"invalid client", 401, `{"error":"invalid_client"}`, ClassForbidden, "invalid_client"},
		{"pace", 429, `{"error":"temporarily_unavailable"}`, ClassRetryable, "temporarily_unavailable"},
		{"capacity", 503, `{"error":"temporarily_unavailable"}`, ClassRetryable, "temporarily_unavailable"},
		{"not bearer", 200, `{"access_token":"x","token_type":"DPoP","expires_in":600}`, ClassUnknown, "token_type"},
		{"empty token", 200, `{"access_token":"","token_type":"Bearer","expires_in":600}`, ClassUnknown, "access_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, tc.status, tc.body) })
			ts := NewFederatedTokenSource(FederatedTokenSourceOptions{
				TokenURL: srv.URL, HTTPClient: srv.Client(), Assertions: &countingAssertions{}, CallTimeout: time.Second,
			})
			_, err := ts.Token(context.Background())
			if err == nil {
				t.Fatal("refusal accepted")
			}
			if Classify(err) != tc.class || !strings.Contains(err.Error(), tc.text) {
				t.Errorf("err %v class %s, want %s naming %q", err, Classify(err), tc.class, tc.text)
			}
		})
	}
}

func TestFederatedExchangeDoesNotCacheAShortToken(t *testing.T) {
	var n atomic.Int32
	srv := tokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, fmt.Sprintf(`{"access_token":"at-%d","token_type":"Bearer","expires_in":30}`, n.Add(1)))
	})
	ts := NewFederatedTokenSource(FederatedTokenSourceOptions{
		TokenURL: srv.URL, HTTPClient: srv.Client(), Assertions: &countingAssertions{}, CallTimeout: time.Second,
	})
	a, _ := ts.Token(context.Background())
	b, _ := ts.Token(context.Background())
	if a == b {
		t.Errorf("token shorter than the refresh margin was cached: %q", a)
	}
}

type failingAssertions struct{}

func (failingAssertions) Assertion(context.Context) (string, error) {
	return "", errors.New("tokenrequest refused")
}

func TestFederatedExchangeAssertionFailure(t *testing.T) {
	ts := NewFederatedTokenSource(FederatedTokenSourceOptions{
		TokenURL: "https://127.0.0.1:1/iam/v1/token", HTTPClient: http.DefaultClient, Assertions: failingAssertions{}, CallTimeout: time.Second,
	})
	if _, err := ts.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "tokenrequest refused") {
		t.Errorf("err = %v", err)
	}
}

func TestTokenRequestAssertionsAsksForOwnSAWithAudienceAndTTL(t *testing.T) {
	cs := fake.NewClientset()
	var got *authv1.TokenRequest
	var gotName, gotNS string
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca, ok := a.(k8stesting.CreateAction)
		if !ok || a.GetSubresource() != "token" {
			return false, nil, nil
		}
		tr := ca.GetObject().(*authv1.TokenRequest)
		got, gotNS = tr.DeepCopy(), a.GetNamespace()
		if impl, ok := a.(k8stesting.CreateActionImpl); ok {
			gotName = impl.Name
		}
		tr.Status.Token = "jwt-from-apiserver"
		return true, tr, nil
	})
	src := &TokenRequestAssertions{
		Client: cs, Namespace: "kaname-iam-system", ServiceAccount: "kaname-iam-operator",
		Audience: "https://kaname.local", TTL: 10 * time.Minute, CallTimeout: time.Second,
	}
	jwt, err := src.Assertion(context.Background())
	if err != nil || jwt != "jwt-from-apiserver" {
		t.Fatalf("jwt %q err %v", jwt, err)
	}
	if got == nil {
		t.Fatal("TokenRequest not sent")
	}
	if gotNS != "kaname-iam-system" || gotName != "kaname-iam-operator" {
		t.Errorf("token for %s/%s", gotNS, gotName)
	}
	if len(got.Spec.Audiences) != 1 || got.Spec.Audiences[0] != "https://kaname.local" {
		t.Errorf("audiences = %v", got.Spec.Audiences)
	}
	if got.Spec.ExpirationSeconds == nil || *got.Spec.ExpirationSeconds != 600 {
		t.Errorf("expirationSeconds = %v", got.Spec.ExpirationSeconds)
	}
}

func TestTokenRequestAssertionsEmptyTokenIsAnError(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authv1.TokenRequest{}, nil
	})
	src := &TokenRequestAssertions{Client: cs, Namespace: "n", ServiceAccount: "s", Audience: "a", TTL: 10 * time.Minute, CallTimeout: time.Second}
	if _, err := src.Assertion(context.Background()); err == nil {
		t.Error("empty token accepted")
	}
}
