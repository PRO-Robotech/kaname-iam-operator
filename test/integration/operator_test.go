//go:build integration

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname/kanametest"
)

// TestKanameContractOnTheStand — контракт клиента против настоящего kaname под
// учёткой оператора (вход FEDERATED): тот же, что гоняется против двойника.
func TestKanameContractOnTheStand(t *testing.T) {
	kanametest.RunContract(t, opClient, kanametest.Fixture{
		AccountID: account, ProjectID: project, RoleName: env["KIO_IT_ROLE"],
		TargetType: env["KIO_IT_TARGET_TYPE"], TargetID: "kioit" + run, NamePrefix: "kio-it-" + run,
	})
}

const waitFor = 120 * time.Second

func eventually(t *testing.T, check func() error) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	var last error
	for time.Now().Before(deadline) {
		if last = check(); last == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("not reached within %s: %v", waitFor, last)
}

func ready(conds []metav1.Condition) error {
	c := meta.FindStatusCondition(conds, iamv1alpha1.ConditionReady)
	if c == nil || c.Status != metav1.ConditionTrue {
		return fmt.Errorf("ready = %+v", c)
	}
	return nil
}

func reserve(t *testing.T, ns, id string) {
	t.Helper()
	ctx := context.Background()
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: "registry.in-cloud.io", Version: "v1alpha1", Kind: "RegistryIDReservation"})
	u.SetName(id)
	_ = unstructured.SetNestedField(u.Object, ns, "spec", "registryRef", "namespace")
	if err := k8s.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8s.Delete(context.Background(), u) })
	_ = unstructured.SetNestedField(u.Object, "Active", "status", "phase")
	if err := k8s.Status().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
}

func binding(t *testing.T, id string) *iamv1.AccessBinding {
	t.Helper()
	var b iamv1.AccessBinding
	if err := admin.do(context.Background(), http.MethodGet, "/iam/v1/accessBindings/"+id, nil, &b); err != nil {
		t.Fatalf("get binding %s: %v", id, err)
	}
	return &b
}

// TestOperatorEndToEnd — предикат задачи: CR SA → учётка с метками и ключ в
// Vault; CR AB → выдача; смена цели → прежняя выдача отозвана, новая действует;
// учётка, отключённая в kaname, остаётся Drifted; удаление CR → перепись = 0.
func TestOperatorEndToEnd(t *testing.T) {
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tenantNSKey + "-" + run, Annotations: map[string]string{
		iamv1alpha1.AnnotationAccountID: account, iamv1alpha1.AnnotationProjectID: project,
	}}}
	if err := k8s.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8s.Delete(context.Background(), ns) })
	t1, t2 := "kioa"+run, "kiob"+run
	reserve(t, ns.Name, t1)
	reserve(t, ns.Name, t2)

	sa, cur := e2eServiceAccount(ctx, t, ns)
	ab, abCur := e2eBinding(ctx, t, ns, t1, t2)
	e2eDrift(ctx, t, sa, cur)
	e2eDeletion(ctx, t, ns, sa, ab, cur, abCur)
}

// e2eServiceAccount — CR SA → учётка с метками владения и ключ в Vault.
func e2eServiceAccount(ctx context.Context, t *testing.T, ns *corev1.Namespace) (*iamv1alpha1.IAMServiceAccount, *iamv1alpha1.IAMServiceAccount) {
	t.Helper()
	saName := "kio-it-" + run + "-ci"
	sa := &iamv1alpha1.IAMServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "ci", Namespace: ns.Name},
		Spec: iamv1alpha1.IAMServiceAccountSpec{
			Name: saName, Description: "integration robot", Labels: map[string]string{"run": run},
			Keys: []iamv1alpha1.KeySpec{{
				Name: "push", TTLSeconds: 86400,
				Delivery: iamv1alpha1.KeyDelivery{Vault: iamv1alpha1.VaultDelivery{App: "docker-registry", Instance: "abc"}},
			}},
		},
	}
	if err := k8s.Create(ctx, sa); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8s.Delete(context.Background(), sa) })
	cur := &iamv1alpha1.IAMServiceAccount{}
	eventually(t, func() error {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(sa), cur); err != nil {
			return err
		}
		return ready(cur.Status.Conditions)
	})
	var remote iamv1.ServiceAccount
	if err := admin.do(ctx, http.MethodGet, "/iam/v1/serviceAccounts/"+cur.Status.ID, nil, &remote); err != nil {
		t.Fatal(err)
	}
	l := remote.GetLabels()
	if remote.GetName() != saName || l[iamv1alpha1.LabelOwnerUID] != string(cur.UID) || l[iamv1alpha1.LabelCluster] != cluster || l["run"] != run {
		t.Fatalf("kaname account = %v", &remote)
	}
	ks := cur.Status.KeyStatusByName("push")
	path := fmt.Sprintf("clusters/%s/namespaces/%s/apps/docker-registry/abc/robots/ci/push", cluster, ns.Name)
	var rec struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := vaultAPI.call(ctx, http.MethodGet, "/v1/"+vaultMount+"/data/"+path, nil, &rec); err != nil {
		t.Fatalf("vault record: %v", err)
	}
	d := rec.Data.Data
	if ks == nil || d["username"] != ks.KeyID || !strings.HasPrefix(d["password"], "kacho_"+ks.KeyID+"_") || d["serviceAccountId"] != cur.Status.ID {
		t.Fatalf("vault record does not carry the issued key %v (username %q)", ks, d["username"])
	}
	keys, err := opClient.ListKeys(ctx, cur.Status.ID)
	if err != nil || len(keys) != 1 || keys[0].GetLabels()[iamv1alpha1.LabelKeyNonce] != d["nonce"] {
		t.Fatalf("kaname keys = %v err %v (vault nonce %q)", keys, err, d["nonce"])
	}
	return sa, cur
}

// e2eBinding — CR AB → выдача; смена цели — новая выдача, прежняя отозвана.
func e2eBinding(ctx context.Context, t *testing.T, ns *corev1.Namespace, t1, t2 string) (*iamv1alpha1.IAMAccessBinding, *iamv1alpha1.IAMAccessBinding) {
	t.Helper()
	ab := &iamv1alpha1.IAMAccessBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "ci-binding", Namespace: ns.Name},
		Spec: iamv1alpha1.IAMAccessBindingSpec{
			Subjects: []iamv1alpha1.Subject{{ServiceAccountRef: &iamv1alpha1.LocalServiceAccountRef{Name: "ci"}}},
			RoleRef:  iamv1alpha1.RoleRef{Name: env["KIO_IT_ROLE"]},
			Target:   iamv1alpha1.Target{Resources: []iamv1alpha1.ResourceRef{{Type: env["KIO_IT_TARGET_TYPE"], ID: t1}}},
		},
	}
	if err := k8s.Create(ctx, ab); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8s.Delete(context.Background(), ab) })
	abCur := &iamv1alpha1.IAMAccessBinding{}
	eventually(t, func() error {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(ab), abCur); err != nil {
			return err
		}
		return ready(abCur.Status.Conditions)
	})
	first := abCur.Status.ID
	if b := binding(t, first); b.GetStatus() != iamv1.AccessBinding_ACTIVE ||
		b.GetTarget().GetResources().GetResources()[0].GetId() != t1 || b.GetScopeId() != project {
		t.Fatalf("binding = %v", b)
	}

	// Смена цели: новая выдача, прежняя отозвана.
	eventually(t, func() error {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(ab), abCur); err != nil {
			return err
		}
		abCur.Spec.Target.Resources[0].ID = t2
		return k8s.Update(ctx, abCur)
	})
	eventually(t, func() error {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(ab), abCur); err != nil {
			return err
		}
		if abCur.Status.ID == first || abCur.Status.Replaced != nil {
			return fmt.Errorf("status = %+v", abCur.Status)
		}
		return ready(abCur.Status.Conditions)
	})
	if b := binding(t, first); b.GetStatus() != iamv1.AccessBinding_REVOKED {
		t.Fatalf("old binding status = %s", b.GetStatus())
	}
	if b := binding(t, abCur.Status.ID); b.GetStatus() != iamv1.AccessBinding_ACTIVE || b.GetTarget().GetResources().GetResources()[0].GetId() != t2 {
		t.Fatalf("new binding = %v", b)
	}
	return ab, abCur
}

// e2eDrift — учётка, отключённая в kaname, остаётся Drifted и не включается.
func e2eDrift(ctx context.Context, t *testing.T, sa, cur *iamv1alpha1.IAMServiceAccount) {
	t.Helper()
	var remote iamv1.ServiceAccount
	// Учётка, отключённая в kaname, остаётся Drifted, оператор её не включает.
	if err := admin.mutate(ctx, http.MethodPost, "/iam/v1/serviceAccounts/"+cur.Status.ID+":disable",
		&iamv1.DisableServiceAccountRequest{ServiceAccountId: cur.Status.ID}, nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(sa), cur); err != nil {
			return err
		}
		c := meta.FindStatusCondition(cur.Status.Conditions, iamv1alpha1.ConditionDrifted)
		if c == nil || c.Status != metav1.ConditionTrue || c.Reason != iamv1alpha1.ReasonDisabledExternally {
			return fmt.Errorf("drifted = %+v", c)
		}
		return nil
	})
	time.Sleep(5 * time.Second) // два окна сверки дрейфа
	if err := admin.do(ctx, http.MethodGet, "/iam/v1/serviceAccounts/"+cur.Status.ID, nil, &remote); err != nil || remote.GetEnabled() {
		t.Fatalf("account re-enabled by the operator: %v %v", remote.GetEnabled(), err)
	}
}

// e2eDeletion — удаление CR снимает выдачу, учётку, ключи и запись Vault.
func e2eDeletion(ctx context.Context, t *testing.T, ns *corev1.Namespace, sa *iamv1alpha1.IAMServiceAccount, ab *iamv1alpha1.IAMAccessBinding,
	cur *iamv1alpha1.IAMServiceAccount, abCur *iamv1alpha1.IAMAccessBinding) {
	t.Helper()
	var remote iamv1.ServiceAccount
	// Удаление: выдача отозвана, учётка, ключи и запись Vault сняты.
	saID, abID := cur.Status.ID, abCur.Status.ID
	if err := k8s.Delete(ctx, ab); err != nil {
		t.Fatal(err)
	}
	if err := k8s.Delete(ctx, sa); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error {
		for _, obj := range []client.Object{&iamv1alpha1.IAMAccessBinding{ObjectMeta: ab.ObjectMeta}, &iamv1alpha1.IAMServiceAccount{ObjectMeta: sa.ObjectMeta}} {
			if err := k8s.Get(ctx, client.ObjectKeyFromObject(obj), obj); !apierrors.IsNotFound(err) {
				return fmt.Errorf("%s still present: %w", obj.GetName(), err)
			}
		}
		return nil
	})
	if b := binding(t, abID); b.GetStatus() != iamv1.AccessBinding_REVOKED {
		t.Fatalf("binding after deletion = %s", b.GetStatus())
	}
	if err := admin.do(ctx, http.MethodGet, "/iam/v1/serviceAccounts/"+saID, nil, &remote); err == nil {
		t.Fatal("kaname account survived the deletion")
	}
	if left, _ := vaultAPI.list(ctx, "clusters/"+cluster+"/namespaces/"+ns.Name); len(left) != 0 {
		t.Fatalf("vault records survived: %v", left)
	}
}
