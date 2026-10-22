// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package kanametest — проба контракта клиента kaname. Её гонят против
// двойника (unit) и против настоящего kaname (integration): семантика
// двойника, на котором строятся пробы контроллеров, сверяется с kaname.
package kanametest

import (
	"context"
	"errors"
	"testing"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname"
)

// Fixture — что проба получает от стенда.
type Fixture struct {
	// AccountID — аккаунт, где оператору можно заводить учётки.
	AccountID string
	// ProjectID — проект этого аккаунта, где оператору можно выдавать.
	ProjectID string
	// RoleName — роль, которую можно выдавать.
	RoleName string
	// TargetType и TargetID — цель выдачи.
	TargetType string
	TargetID   string
	// NamePrefix — префикс имён учёток прогона (уникален на прогон).
	NamePrefix string
}

// Await дожидается завершения операции и разбирает её результат в out.
func Await(ctx context.Context, t *testing.T, c *kaname.Client, op *operationpb.Operation, out proto.Message) error {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := kaname.OperationResult(op, out)
		if !errors.Is(err, kaname.ErrOperationNotDone) {
			return err
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation %s not done within 30s", op.GetId())
		}
		time.Sleep(100 * time.Millisecond)
		next, gerr := c.GetOperation(ctx, op.GetId())
		if gerr != nil {
			return gerr
		}
		op = next
	}
}

// RunContract — подмножество контракта kaname, которым пользуется оператор.
// Всё заведённое снимается в конце, в том числе на падении.
func RunContract(t *testing.T, c *kaname.Client, fx Fixture) {
	t.Helper()
	ctx := context.Background()
	sa := contractServiceAccount(ctx, t, c, fx)
	issued := contractKeys(ctx, t, c, sa)
	contractBindings(ctx, t, c, fx, sa)
	contractEnablement(ctx, t, c, sa)
	contractTeardown(ctx, t, c, sa, issued)
}

// contractServiceAccount — создание, повтор имени, поиск по имени, правка.
func contractServiceAccount(ctx context.Context, t *testing.T, c *kaname.Client, fx Fixture) *iamv1.ServiceAccount {
	t.Helper()
	name := fx.NamePrefix + "-contract"
	op, err := c.CreateServiceAccount(ctx, &iamv1.CreateServiceAccountRequest{
		AccountId: fx.AccountID, Name: name, Description: "contract probe",
		Labels: map[string]string{"k8s.in-cloud.io/uid": "u-1", "k8s.in-cloud.io/cluster": "c1"},
	})
	if err != nil {
		t.Fatalf("create SA: %v", err)
	}
	var sa iamv1.ServiceAccount
	if err := Await(ctx, t, c, op, &sa); err != nil {
		t.Fatalf("create SA result: %v", err)
	}
	t.Cleanup(func() { cleanupServiceAccount(ctx, t, c, sa.GetId()) })
	if sa.GetId() == "" || sa.GetName() != name || !sa.GetEnabled() || sa.GetLabels()["k8s.in-cloud.io/uid"] != "u-1" {
		t.Fatalf("created SA = %v", &sa)
	}

	// Повтор создания с тем же именем — отказ ALREADY_EXISTS (путь усыновления).
	op, err = c.CreateServiceAccount(ctx, &iamv1.CreateServiceAccountRequest{AccountId: fx.AccountID, Name: name})
	if err == nil {
		err = Await(ctx, t, c, op, nil)
	}
	if kaname.Classify(err) != kaname.ClassAlreadyExists {
		t.Fatalf("duplicate SA name: class %s (%v)", kaname.Classify(err), err)
	}

	found, err := c.FindServiceAccountByName(ctx, fx.AccountID, name)
	if err != nil || found == nil || found.GetId() != sa.GetId() {
		t.Fatalf("find by name: %v %v", found, err)
	}
	absent, err := c.FindServiceAccountByName(ctx, fx.AccountID, name+"-absent")
	if err != nil || absent != nil {
		t.Fatalf("find absent: %v %v", absent, err)
	}

	op, err = c.UpdateServiceAccount(ctx, &iamv1.UpdateServiceAccountRequest{
		ServiceAccountId: sa.GetId(), UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"description", "labels"}},
		Description: "contract probe 2",
		Labels:      map[string]string{"k8s.in-cloud.io/uid": "u-1", "k8s.in-cloud.io/cluster": "c1", "team": "a"},
	})
	if err != nil {
		t.Fatalf("update SA: %v", err)
	}
	if err := Await(ctx, t, c, op, nil); err != nil {
		t.Fatalf("update SA result: %v", err)
	}
	got, err := c.GetServiceAccount(ctx, sa.GetId())
	if err != nil || got.GetDescription() != "contract probe 2" || got.GetLabels()["team"] != "a" {
		t.Fatalf("after update: %v %v", got, err)
	}
	return &sa
}

// contractKeys — выпуск SECRET, повторное чтение операции, метки ключа, отказ
// секрета с адресатом.
func contractKeys(ctx context.Context, t *testing.T, c *kaname.Client, sa *iamv1.ServiceAccount) *iamv1.IssueSAKeyResponse {
	t.Helper()
	// Ключ SECRET: секрет — в ответе выпуска, метки — на ключе.
	op, err := c.IssueKey(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: sa.GetId(), TtlSeconds: 3600, CredentialKind: iamv1.CredentialKind_CREDENTIAL_KIND_SECRET,
		Labels: map[string]string{"k8s.in-cloud.io/nonce": "n-1", "k8s.in-cloud.io/key": "push"},
	})
	if err != nil {
		t.Fatalf("issue key: %v", err)
	}
	var issued iamv1.IssueSAKeyResponse
	if err := Await(ctx, t, c, op, &issued); err != nil {
		t.Fatalf("issue key result: %v", err)
	}
	if issued.GetKeyId() == "" || issued.GetSecret() == "" {
		t.Fatalf("issued key without id or secret (id %q)", issued.GetKeyId())
	}
	// Повторное чтение операции секрета не отдаёт.
	if again, err := c.GetOperation(ctx, op.GetId()); err == nil {
		var reread iamv1.IssueSAKeyResponse
		if kaname.OperationResult(again, &reread) == nil && reread.GetSecret() != "" {
			t.Fatal("operation re-read returns the secret")
		}
	}
	keys, err := c.ListKeys(ctx, sa.GetId())
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	var listed *iamv1.ServiceAccountOAuthClient
	for _, k := range keys {
		if k.GetId() == issued.GetKeyId() {
			listed = k
		}
	}
	if listed == nil || listed.GetLabels()["k8s.in-cloud.io/nonce"] != "n-1" || listed.GetExpiresAt() == nil {
		t.Fatalf("listed key = %v", listed)
	}
	// Секрет с адресатом — отказ INVALID_ARGUMENT.
	_, err = c.IssueKey(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: sa.GetId(), TtlSeconds: 3600, CredentialKind: iamv1.CredentialKind_CREDENTIAL_KIND_SECRET,
		Audience: []string{"x"},
	})
	if kaname.Classify(err) != kaname.ClassInvalid {
		t.Fatalf("secret with audience: class %s (%v)", kaname.Classify(err), err)
	}
	return &issued
}

// contractBindings — выдача, повтор ключа выдачи, перечень по аккаунту, правка
// меток, отзыв.
func contractBindings(ctx context.Context, t *testing.T, c *kaname.Client, fx Fixture, sa *iamv1.ServiceAccount) {
	t.Helper()
	// Выдача на учётку.
	role, err := c.FindRole(ctx, fx.RoleName, fx.AccountID)
	if err != nil {
		t.Fatalf("find role: %v", err)
	}
	target := &iamv1.AccessTarget{Target: &iamv1.AccessTarget_Resources{Resources: &iamv1.AccessTargetResources{
		Resources: []*iamv1.ResourceRef{{Type: fx.TargetType, Id: fx.TargetID}},
	}}}
	subj := []*iamv1.Subject{{Type: iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, Id: sa.GetId()}}
	op, err := c.CreateAccessBinding(ctx, &iamv1.CreateAccessBindingRequest{
		Subjects: subj, RoleId: role.GetId(), ScopeType: "iam.project", ScopeId: fx.ProjectID,
		Target: target, Labels: map[string]string{"k8s.in-cloud.io/uid": "u-2"},
	})
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}
	var ab iamv1.AccessBinding
	if err := Await(ctx, t, c, op, &ab); err != nil {
		t.Fatalf("create binding result: %v", err)
	}
	t.Cleanup(func() {
		if op, err := c.RevokeAccessBinding(ctx, ab.GetId()); err == nil {
			_ = Await(ctx, t, c, op, nil)
		}
	})
	if ab.GetId() == "" {
		t.Fatal("binding without id")
	}
	op, err = c.CreateAccessBinding(ctx, &iamv1.CreateAccessBindingRequest{
		Subjects: subj, RoleId: role.GetId(), ScopeType: "iam.project", ScopeId: fx.ProjectID, Target: target,
	})
	if err == nil {
		err = Await(ctx, t, c, op, nil)
	}
	if kaname.Classify(err) != kaname.ClassAlreadyExists {
		t.Fatalf("duplicate binding: class %s (%v)", kaname.Classify(err), err)
	}
	byAccount, err := c.ListAccessBindingsByAccount(ctx, fx.AccountID)
	if err != nil {
		t.Fatalf("list by account: %v", err)
	}
	seen := false
	for _, b := range byAccount {
		if b.GetId() == ab.GetId() {
			seen = b.GetLabels()["k8s.in-cloud.io/uid"] == "u-2" && b.GetRoleId() == role.GetId()
		}
	}
	if !seen {
		t.Fatalf("binding %s (project scope) not listed by its account with its labels and role", ab.GetId())
	}
	op, err = c.UpdateAccessBinding(ctx, &iamv1.UpdateAccessBindingRequest{
		AccessBindingId: ab.GetId(), UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
		Labels: map[string]string{"k8s.in-cloud.io/uid": "u-2", "team": "b"},
	})
	if err != nil {
		t.Fatalf("update binding: %v", err)
	}
	if err := Await(ctx, t, c, op, nil); err != nil {
		t.Fatalf("update binding result: %v", err)
	}

	op, err = c.RevokeAccessBinding(ctx, ab.GetId())
	if err != nil {
		t.Fatalf("revoke binding: %v", err)
	}
	if err := Await(ctx, t, c, op, nil); err != nil {
		t.Fatalf("revoke binding result: %v", err)
	}
	if b, err := c.GetAccessBinding(ctx, ab.GetId()); err == nil && b.GetStatus() != iamv1.AccessBinding_REVOKED {
		t.Fatalf("revoked binding status = %s", b.GetStatus())
	}
}

// contractEnablement — отключение, отказ выпуска у отключённой, включение.
func contractEnablement(ctx context.Context, t *testing.T, c *kaname.Client, sa *iamv1.ServiceAccount) {
	t.Helper()
	// Отключение, отказ выпуска у отключённой, включение.
	op, err := c.DisableServiceAccount(ctx, sa.GetId())
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := Await(ctx, t, c, op, nil); err != nil {
		t.Fatalf("disable result: %v", err)
	}
	if got, _ := c.GetServiceAccount(ctx, sa.GetId()); got.GetEnabled() {
		t.Fatal("disabled SA reads enabled")
	}
	op, err = c.IssueKey(ctx, &iamv1.IssueSAKeyRequest{ServiceAccountId: sa.GetId(), TtlSeconds: 3600, CredentialKind: iamv1.CredentialKind_CREDENTIAL_KIND_SECRET})
	if err == nil {
		err = Await(ctx, t, c, op, nil)
	}
	if kaname.Classify(err) != kaname.ClassRetryable || kaname.CodeOf(err).String() != "FailedPrecondition" {
		t.Fatalf("issue on a disabled SA: %v", err)
	}
	op, err = c.EnableServiceAccount(ctx, sa.GetId())
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := Await(ctx, t, c, op, nil); err != nil {
		t.Fatalf("enable result: %v", err)
	}
}

// contractTeardown — отзыв ключа, повторный отзыв, удаление учётки.
func contractTeardown(ctx context.Context, t *testing.T, c *kaname.Client, sa *iamv1.ServiceAccount, issued *iamv1.IssueSAKeyResponse) {
	t.Helper()
	op, err := c.RevokeKey(ctx, sa.GetId(), issued.GetKeyId())
	if err != nil {
		t.Fatalf("revoke key: %v", err)
	}
	if err := Await(ctx, t, c, op, nil); err != nil {
		t.Fatalf("revoke key result: %v", err)
	}
	_, err = c.RevokeKey(ctx, sa.GetId(), issued.GetKeyId())
	if kaname.Classify(err) != kaname.ClassNotFound {
		t.Fatalf("second revoke: class %s (%v)", kaname.Classify(err), err)
	}

	op, err = c.DeleteServiceAccount(ctx, sa.GetId())
	if err != nil {
		t.Fatalf("delete SA: %v", err)
	}
	if err := Await(ctx, t, c, op, nil); err != nil {
		t.Fatalf("delete SA result: %v", err)
	}
	if _, err := c.GetServiceAccount(ctx, sa.GetId()); kaname.Classify(err) != kaname.ClassNotFound {
		t.Fatalf("get after delete: class %s (%v)", kaname.Classify(err), err)
	}
}

// cleanupServiceAccount снимает учётку пробы и на падении: сначала её ключи
// (kaname не удаляет учётку с действующими ключами), затем её саму.
func cleanupServiceAccount(ctx context.Context, t *testing.T, c *kaname.Client, id string) {
	t.Helper()
	keys, err := c.ListKeys(ctx, id)
	if kaname.Classify(err) == kaname.ClassNotFound {
		return
	}
	for _, k := range keys {
		if op, err := c.RevokeKey(ctx, id, k.GetId()); err == nil {
			_ = Await(ctx, t, c, op, nil)
		}
	}
	if op, err := c.DeleteServiceAccount(ctx, id); err == nil {
		if err := Await(ctx, t, c, op, nil); err != nil {
			t.Errorf("cleanup: delete service account %s: %v", id, err)
		}
	}
}
