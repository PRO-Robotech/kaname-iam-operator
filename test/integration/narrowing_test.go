//go:build integration

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
)

// liveOwned — действующие выдачи настоящего kaname с метками владения CR uid.
func liveOwned(t *testing.T, uid string) []string {
	t.Helper()
	var abs iamv1.ListAccessBindingsResponse
	if err := admin.do(context.Background(), http.MethodGet, "/iam/v1/accounts/"+account+"/accessBindings?page_size=1000", nil, &abs); err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	var out []string
	for _, b := range abs.GetAccessBindings() {
		if b.GetLabels()[iamv1alpha1.LabelOwnerUID] == uid && b.GetStatus() != iamv1.AccessBinding_REVOKED {
			out = append(out, b.GetId())
		}
	}
	return out
}

// TestPolicyNarrowingRevokesInRealKaname — сужение политики оператора
// (перезапуск с новой конфигурацией, как при смене конфигурации развёрнутого
// оператора) отзывает в НАСТОЯЩЕМ kaname выдачу, ставшую недопустимой, и
// новой не заводит; выдача, оставшаяся допустимой, действует.
//
//  1. Сужение принципалов платформы: выдача на всю область аккаунта от
//     снятого принципала отозвана, CR — Rejected/PolicyNarrowed. Близнец —
//     выдача перечня объектов учётке-роботу: принципал ей не нужен.
//  2. Политика прогона вновь: выдача на всю область снова допустима и
//     заводится заново.
//  3. Сужение перечня ролей: выдача роли, снятой с перечня, отозвана.
//     Близнец — выдача на всю область роли, оставшейся в перечне.
func TestPolicyNarrowingRevokesInRealKaname(t *testing.T) {
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "narrow-" + run, Annotations: map[string]string{
		iamv1alpha1.AnnotationAccountID: account, iamv1alpha1.AnnotationProjectID: project,
	}}}
	if err := k8s.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8s.Delete(context.Background(), ns) })
	target := "kion" + run
	reserve(t, ns.Name, target)
	platform, err := as(platformUser)
	if err != nil {
		t.Fatal(err)
	}
	robot := &iamv1alpha1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "robot", Namespace: ns.Name},
		Spec:       iamv1alpha1.ServiceAccountSpec{Name: "kio-it-" + run + "-narrow", Description: "policy narrowing probe robot"},
	}
	if err := platform.Create(ctx, robot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeCR(t, robot) })
	eventually(t, func() error {
		cur := &iamv1alpha1.ServiceAccount{}
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(robot), cur); err != nil {
			return err
		}
		return ready(cur.Status.Conditions)
	})

	whole := &iamv1alpha1.AccessBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "whole", Namespace: ns.Name,
			Annotations: map[string]string{iamv1alpha1.AnnotationCreatedBy: platformUser}},
		Spec: iamv1alpha1.AccessBindingSpec{
			Subjects: []iamv1alpha1.Subject{{ServiceAccountRef: &iamv1alpha1.LocalServiceAccountRef{Name: robot.Name}}},
			RoleRef:  iamv1alpha1.RoleRef{Name: pusherRole},
			Scope:    iamv1alpha1.Scope{Type: iamv1alpha1.ScopeAccount},
			Target:   iamv1alpha1.Target{AllInScope: &iamv1alpha1.AllInScope{}},
		},
	}
	named := &iamv1alpha1.AccessBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "named", Namespace: ns.Name,
			Annotations: map[string]string{iamv1alpha1.AnnotationCreatedBy: platformUser}},
		Spec: iamv1alpha1.AccessBindingSpec{
			Subjects: []iamv1alpha1.Subject{{ServiceAccountRef: &iamv1alpha1.LocalServiceAccountRef{Name: robot.Name}}},
			RoleRef:  iamv1alpha1.RoleRef{Name: env["KIO_IT_ROLE"]},
			Target:   iamv1alpha1.Target{Resources: []iamv1alpha1.ResourceRef{{Type: env["KIO_IT_TARGET_TYPE"], ID: target}}},
		},
	}
	for _, ab := range []*iamv1alpha1.AccessBinding{whole, named} {
		if err := platform.Create(ctx, ab); err != nil {
			t.Fatalf("create %s: %v", ab.Name, err)
		}
		t.Cleanup(func() { removeCR(t, ab) })
	}
	wholeID, namedID := grantedID(t, whole), grantedID(t, named)

	restartOperator(t, func(p *config.Policy) { p.PlatformPrincipals = []string{"system:serviceaccount:platform-system:other"} })
	withdrawn(t, whole, wholeID)
	keptAndNotRegranted(t, named, namedID, whole)

	restartOperator(t, nil)
	again := grantedID(t, whole)
	if again == wholeID {
		t.Fatalf("widened back: binding %s is the revoked one", again)
	}

	restartOperator(t, func(p *config.Policy) { p.AllowedRoles = []string{pusherRole} })
	withdrawn(t, named, namedID)
	keptAndNotRegranted(t, whole, again, named)
}

// grantedID ждёт Ready и действующую выдачу в kaname.
func grantedID(t *testing.T, ab *iamv1alpha1.AccessBinding) string {
	t.Helper()
	cur := &iamv1alpha1.AccessBinding{}
	eventually(t, func() error {
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(ab), cur); err != nil {
			return err
		}
		if cur.Status.ObservedGeneration != cur.Generation || cur.Status.ID == "" {
			return fmt.Errorf("%s: status %+v", ab.Name, cur.Status)
		}
		return ready(cur.Status.Conditions)
	})
	if b := binding(t, cur.Status.ID); b.GetStatus() != iamv1.AccessBinding_ACTIVE {
		t.Fatalf("%s: kaname binding %s is %s", ab.Name, cur.Status.ID, b.GetStatus())
	}
	return cur.Status.ID
}

// withdrawn ждёт отзыва выдачи id в kaname по сужению: CR Rejected/
// PolicyNarrowed, id снят, своих действующих выдач нет.
func withdrawn(t *testing.T, ab *iamv1alpha1.AccessBinding, id string) {
	t.Helper()
	eventually(t, func() error {
		cur := &iamv1alpha1.AccessBinding{}
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(ab), cur); err != nil {
			return err
		}
		c := meta.FindStatusCondition(cur.Status.Conditions, iamv1alpha1.ConditionRejected)
		if c == nil || c.Status != metav1.ConditionTrue || c.Reason != iamv1alpha1.ReasonPolicyNarrowed {
			return fmt.Errorf("%s: rejected = %+v", ab.Name, c)
		}
		if cur.Status.ID != "" || cur.Status.PendingOperation != nil {
			return fmt.Errorf("%s still holds a binding: %+v", ab.Name, cur.Status)
		}
		if b := binding(t, id); b.GetStatus() != iamv1.AccessBinding_REVOKED {
			return fmt.Errorf("%s: kaname binding %s is %s", ab.Name, id, b.GetStatus())
		}
		if live := liveOwned(t, string(cur.UID)); len(live) > 0 {
			return fmt.Errorf("%s: live bindings %v", ab.Name, live)
		}
		return nil
	})
}

// keptAndNotRegranted держит окно в несколько интервалов сверки: выдача
// kept действует той же, отозванная gone вновь не заводится.
func keptAndNotRegranted(t *testing.T, kept *iamv1alpha1.AccessBinding, keptID string, gone *iamv1alpha1.AccessBinding) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cur := &iamv1alpha1.AccessBinding{}
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(kept), cur); err != nil {
			t.Fatal(err)
		}
		if cur.Status.ID != keptID || ready(cur.Status.Conditions) != nil {
			t.Fatalf("%s: the permissible binding was touched: %+v", kept.Name, cur.Status)
		}
		if b := binding(t, keptID); b.GetStatus() != iamv1.AccessBinding_ACTIVE {
			t.Fatalf("%s: kaname binding %s is %s", kept.Name, keptID, b.GetStatus())
		}
		g := &iamv1alpha1.AccessBinding{}
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(gone), g); err != nil {
			t.Fatal(err)
		}
		if live := liveOwned(t, string(g.UID)); len(live) > 0 || g.Status.ID != "" {
			t.Fatalf("%s granted again while the policy forbids it: %v %+v", gone.Name, live, g.Status)
		}
		time.Sleep(time.Second)
	}
}

// removeCR удаляет CR и ждёт, что его нет: перепись остатков после набора.
func removeCR(t *testing.T, obj client.Object) {
	t.Helper()
	if err := k8s.Delete(context.Background(), obj); err != nil && !apierrors.IsNotFound(err) {
		t.Errorf("delete %s: %v", obj.GetName(), err)
		return
	}
	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(obj), obj); apierrors.IsNotFound(err) {
			return
		}
		time.Sleep(time.Second)
	}
	t.Errorf("%s still present after %s", obj.GetName(), waitFor)
}
