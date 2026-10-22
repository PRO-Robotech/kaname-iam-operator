// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package vault_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname-iam-operator/internal/fakes/vaultfake"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/vault"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/vault/vaulttest"
)

func allowRobots(mount, path string) bool {
	return mount == "secret" && strings.HasPrefix(path, "clusters/c1/")
}

func newFake(t *testing.T) (*vaultfake.Server, *httptest.Server) {
	t.Helper()
	f := vaultfake.New("kubernetes", "kaname-iam-operator", allowRobots)
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func newClient(t *testing.T, srv *httptest.Server, jwtReads *atomic.Int32) *vault.Client {
	t.Helper()
	c, err := vault.New(vault.Options{
		Address:    srv.URL,
		HTTPClient: srv.Client(),
		AuthMount:  "kubernetes",
		Role:       "kaname-iam-operator",
		JWT: func() (string, error) {
			if jwtReads != nil {
				jwtReads.Add(1)
			}
			return "projected-jwt", nil
		},
		CallTimeout: 300 * time.Millisecond,
	})
	if err != nil || c == nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestContractAgainstTheFake(t *testing.T) {
	_, srv := newFake(t)
	vaulttest.RunContract(t, newClient(t, srv, nil), "secret", "clusters/c1", "clusters/other/x")
}

func TestLoginIsCachedAndRedoneAfterRevocation(t *testing.T) {
	f, srv := newFake(t)
	var reads atomic.Int32
	c := newClient(t, srv, &reads)
	ctx := context.Background()
	for range 3 {
		if _, err := c.Read(ctx, "secret", "clusters/c1/a"); err != nil {
			t.Fatal(err)
		}
	}
	if f.Logins() != 1 || reads.Load() != 1 {
		t.Fatalf("logins=%d jwt reads=%d, want 1 and 1", f.Logins(), reads.Load())
	}
	f.RevokeTokens()
	if _, err := c.Read(ctx, "secret", "clusters/c1/a"); err != nil {
		t.Fatalf("after revocation: %v", err)
	}
	if f.Logins() != 2 || reads.Load() != 2 {
		t.Fatalf("logins=%d jwt reads=%d after revocation, want 2 and 2", f.Logins(), reads.Load())
	}
}

func TestSealedVaultIsRetryable(t *testing.T) {
	f, srv := newFake(t)
	c := newClient(t, srv, nil)
	if _, err := c.Read(context.Background(), "secret", "clusters/c1/a"); err != nil {
		t.Fatal(err)
	}
	f.FailNext(1)
	_, err := c.Read(context.Background(), "secret", "clusters/c1/a")
	if err == nil || !vault.IsRetryable(err) || vault.IsForbidden(err) {
		t.Fatalf("sealed: err=%v retryable=%v", err, vault.IsRetryable(err))
	}
	if !strings.Contains(err.Error(), "sealed") {
		t.Errorf("error does not carry the refusal text: %v", err)
	}
}

func TestEveryCallHasItsOwnDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	c := newClient(t, srv, nil)
	start := time.Now()
	_, err := c.Read(context.Background(), "secret", "clusters/c1/a")
	if err == nil || !vault.IsRetryable(err) {
		t.Fatalf("hung vault: err=%v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("deadline not applied: %s", time.Since(start))
	}
}

func TestPathSegmentsAreRefused(t *testing.T) {
	_, srv := newFake(t)
	c := newClient(t, srv, nil)
	for _, p := range []string{"clusters/c1/../x", "/clusters/c1/a", "clusters/c1/a?x=1", ""} {
		if _, err := c.Read(context.Background(), "secret", p); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
}
