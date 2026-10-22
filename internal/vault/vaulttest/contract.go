// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package vaulttest — проба контракта клиента Vault. Её гонят и против
// двойника (unit), и против настоящего Vault в контейнере (integration):
// двойник, на котором строятся пробы контроллеров, обязан вести себя так же.
package vaulttest

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname-iam-operator/internal/vault"
)

// RunContract — проба контракта. mount — KV v2, base — префикс, доступный
// политике; forbidden — путь вне политики.
func RunContract(t *testing.T, c *vault.Client, mount, base, forbidden string) {
	t.Helper()
	ctx := context.Background()
	p := base + "/contract/robot/push"

	rec, err := c.Read(ctx, mount, p)
	if err != nil || rec != nil {
		t.Fatalf("read absent: rec=%v err=%v", rec, err)
	}
	v1, err := c.WriteCAS(ctx, mount, p, map[string]string{"username": "k1", "nonce": "n1"}, 0)
	if err != nil || v1 != 1 {
		t.Fatalf("create with cas=0: v=%d err=%v", v1, err)
	}
	rec, err = c.Read(ctx, mount, p)
	if err != nil || rec == nil || rec.Version != 1 || rec.Data["username"] != "k1" || rec.Data["nonce"] != "n1" {
		t.Fatalf("read after create: rec=%+v err=%v", rec, err)
	}
	if _, err := c.WriteCAS(ctx, mount, p, map[string]string{"username": "k2"}, 0); !errors.Is(err, vault.ErrCASMismatch) {
		t.Fatalf("second create with cas=0: err=%v, want ErrCASMismatch", err)
	}
	v2, err := c.WriteCAS(ctx, mount, p, map[string]string{"username": "k2", "nonce": "n2"}, 1)
	if err != nil || v2 != 2 {
		t.Fatalf("update with cas=1: v=%d err=%v", v2, err)
	}
	if _, err := c.WriteCAS(ctx, mount, p, map[string]string{"username": "k3"}, 1); !errors.Is(err, vault.ErrCASMismatch) {
		t.Fatalf("stale cas=1: err=%v, want ErrCASMismatch", err)
	}
	if err := c.DeleteAll(ctx, mount, p); err != nil {
		t.Fatalf("delete: %v", err)
	}
	rec, err = c.Read(ctx, mount, p)
	if err != nil || rec != nil {
		t.Fatalf("read after delete: rec=%+v err=%v", rec, err)
	}
	v, err := c.WriteCAS(ctx, mount, p, map[string]string{"username": "k4"}, 0)
	if err != nil || v != 1 {
		t.Fatalf("create after delete: v=%d err=%v", v, err)
	}
	if err := c.DeleteAll(ctx, mount, p); err != nil {
		t.Fatalf("cleanup delete: %v", err)
	}
	if err := c.DeleteAll(ctx, mount, p); err != nil {
		t.Fatalf("delete of an absent record: %v", err)
	}
	_, err = c.WriteCAS(ctx, mount, forbidden, map[string]string{"x": "y"}, 0)
	if err == nil || !vault.IsForbidden(err) || errors.Is(err, vault.ErrCASMismatch) {
		t.Fatalf("write outside the policy: err=%v, want forbidden", err)
	}
}
