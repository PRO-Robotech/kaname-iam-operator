// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package kaname_test

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname-iam-operator/internal/fakes/kanamefake"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname/kanametest"
)

func newFakeClient(t *testing.T, f *kanamefake.Server) *kaname.Client {
	t.Helper()
	srv := httptest.NewTLSServer(f.Handler())
	t.Cleanup(srv.Close)
	n := 0
	ts := kaname.NewFederatedTokenSource(kaname.FederatedTokenSourceOptions{
		TokenURL:    srv.URL + "/iam/v1/token",
		HTTPClient:  srv.Client(),
		Assertions:  assertionSource(func() string { n++; return fmt.Sprintf("assertion-%d", n) }),
		CallTimeout: time.Second,
	})
	c, err := kaname.New(kaname.Options{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: ts, CallTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestContractAgainstTheFake(t *testing.T) {
	for _, polls := range []int{0, 2} {
		t.Run(fmt.Sprintf("async-polls-%d", polls), func(t *testing.T) {
			f := kanamefake.New()
			f.AsyncPolls = polls
			f.AddAccount("acc1")
			f.AddProject("prj1", "acc1")
			f.AddRole("registry.pusher", true)
			kanametest.RunContract(t, newFakeClient(t, f), kanametest.Fixture{
				AccountID: "acc1", ProjectID: "prj1", RoleName: "registry.pusher",
				TargetType: "registry.registries", TargetID: "abc123", NamePrefix: "p",
			})
		})
	}
}
