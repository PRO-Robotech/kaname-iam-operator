// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

// Пробы класса «намерение после вызова»: изменяющий вызов kaname исполнен, а
// запись status после него отвергнута конфликтом версии, потому что CR
// изменился посреди вызова. Объект kaname с метками владения CR обязан найти
// своего хозяина: ни выдача, ни учётка не переживают свой CR и не остаются
// лишними.

// onceOn — крючок двойника, срабатывающий один раз на вызов method path,
// тело которого несёт marker.
func onceOn(t *testing.T, method, path, marker string, do func()) *atomic.Bool {
	t.Helper()
	fired := &atomic.Bool{}
	fakeK.OnRequest(func(m, p string, body []byte) {
		if m == method && p == path && bytes.Contains(body, []byte(marker)) && fired.CompareAndSwap(false, true) {
			do()
		}
	})
	t.Cleanup(func() { fakeK.OnRequest(nil) })
	return fired
}

// liveOwnedBindings — выдачи с меткой владения uid не в REVOKED.
func liveOwnedBindings(uid string) []*iamv1.AccessBinding {
	var out []*iamv1.AccessBinding
	for _, b := range fakeK.Bindings() {
		if b.GetLabels()[iamv1alpha1.LabelOwnerUID] == uid && b.GetStatus() != iamv1.AccessBinding_REVOKED {
			out = append(out, b)
		}
	}
	return out
}

func waitGone(t *testing.T, obj client.Object) {
	t.Helper()
	eventually(t, waitReady, func() error {
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(obj), obj.DeepCopyObject().(client.Object)); !apierrors.IsNotFound(err) {
			return fmt.Errorf("%s still present: %v", obj.GetName(), err)
		}
		return nil
	})
}

// CR удалён, пока kaname заводит его выдачу: запись status после Create
// отвергнута конфликтом. После удаления выдач с uid CR не в REVOKED — 0.
// Близнец — удаление после успешной записи (TestABDeletionRevokesAndOrphanDoesNot).
func TestABDeletedDuringCreateLeavesNoLiveBinding(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	readySA(t, tn, "zot-race")
	ab := newAB(tn, "race", "zot-race", "registry.pusher", "abc123")
	fired := onceOn(t, "POST", "/iam/v1/accessBindings", tn.project, func() {
		_ = k8s.Delete(context.Background(), &iamv1alpha1.AccessBinding{ObjectMeta: metav1.ObjectMeta{Name: ab.Name, Namespace: ab.Namespace}})
	})
	createAB(t, ab)
	waitGone(t, ab)
	if !fired.Load() {
		t.Fatal("precondition: the create of the binding was never called")
	}
	eventually(t, 5*time.Second, func() error {
		if live := liveOwnedBindings(string(ab.UID)); len(live) != 0 {
			return fmt.Errorf("live bindings of the deleted CR: %d (%s)", len(live), live[0].GetId())
		}
		return nil
	})
}

// Цель сменилась, пока kaname заводит замену: id заведённой замены не дошёл
// до status. После схождения у CR ровно одна действующая выдача — на
// последнюю цель. Близнец — та же смена без гонки
// (TestABTargetChangeCreatesNewBindingBeforeRevokingTheOld).
func TestABTargetChangedDuringReplacementLeavesOneLiveBinding(t *testing.T) {
	tn := newTenant(t, true)
	t0, t1, t2 := "r0"+randSuffix(), "r1"+randSuffix(), "r2"+randSuffix()
	for _, id := range []string{t0, t1, t2} {
		reserve(t, tn, id)
	}
	readySA(t, tn, "zot-swap")
	ab := newAB(tn, "swap", "zot-swap", "registry.pusher", t0)
	createAB(t, ab)
	first := waitABReady(t, ab)
	retarget := func(id string) {
		patchObj(t, ab, func(o client.Object) {
			o.(*iamv1alpha1.AccessBinding).Spec.Target.Resources[0].ID = id
		})
	}
	fired := onceOn(t, "POST", "/iam/v1/accessBindings", t1, func() {
		cur := &iamv1alpha1.AccessBinding{}
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(ab), cur); err != nil {
			return
		}
		cur.Spec.Target.Resources[0].ID = t2
		_ = k8s.Update(context.Background(), cur)
	})
	retarget(t1)
	eventually(t, waitReady, func() error {
		cur := getAB(t, ab)
		if !fired.Load() {
			return fmt.Errorf("the create of the replacement was not called yet")
		}
		if cur.Status.ObservedGeneration != cur.Generation || cur.Status.Replaced != nil {
			return fmt.Errorf("not converged: generation %d/%d, replaced %+v", cur.Status.ObservedGeneration, cur.Generation, cur.Status.Replaced)
		}
		if err := wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, ""); err != nil {
			return err
		}
		live := liveOwnedBindings(string(cur.UID))
		if len(live) != 1 {
			ids := make([]string, 0, len(live))
			for _, b := range live {
				ids = append(ids, b.GetId()+"→"+b.GetTarget().GetResources().GetResources()[0].GetId())
			}
			return fmt.Errorf("live bindings of the CR: %d %v, want 1", len(live), ids)
		}
		if got := live[0].GetTarget().GetResources().GetResources()[0].GetId(); got != t2 || live[0].GetId() != cur.Status.ID {
			return fmt.Errorf("live binding %s targets %s, status id %s", live[0].GetId(), got, cur.Status.ID)
		}
		return nil
	})
	if remoteAB(first.Status.ID).GetStatus() != iamv1.AccessBinding_REVOKED {
		t.Fatal("the first binding was not revoked")
	}
}

// CR учётки удалён, пока kaname её заводит: учётка с uid CR после удаления не
// остаётся (иначе пересозданный CR с тем же spec.name навсегда NotOwned).
// Близнец — удаление после успешной записи (TestSADeletionWaitsForBindingsThenCleansEverything).
func TestSADeletedDuringCreateLeavesNoAccount(t *testing.T) {
	tn := newTenant(t, true)
	name := "zrace" + randSuffix()
	sa := newSA(tn, name)
	fired := onceOn(t, "POST", "/iam/v1/serviceAccounts", name, func() {
		_ = k8s.Delete(context.Background(), &iamv1alpha1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: sa.Name, Namespace: sa.Namespace}})
	})
	createSA(t, sa)
	waitGone(t, sa)
	if !fired.Load() {
		t.Fatal("precondition: the create of the account was never called")
	}
	eventually(t, 5*time.Second, func() error {
		for _, r := range fakeK.ServiceAccounts() {
			if r.GetLabels()[iamv1alpha1.LabelOwnerUID] == string(sa.UID) {
				return fmt.Errorf("account %s of the deleted CR survived", r.GetId())
			}
		}
		return nil
	})
}

// Субъект user или group принимается только при гарантии допуска: подлинность
// аннотации created-by держит ValidatingAdmissionPolicy, и без неё аннотация —
// слово клиента. В кластере пробы политик допуска нет — выдача отвергнута,
// kaname не зовётся. Близнец — «twin: user subject from a platform principal»
// в TestABPolicyRefusalsHaveLawfulTwins.
func TestABUserSubjectIsRefusedWithoutTheAdmissionGuarantee(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	ab := newAB(tn, "forged", "unused", "registry.pusher", "abc123")
	ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: "system:serviceaccount:platform-system:onboarding"}
	ab.Spec.Subjects = []iamv1alpha1.Subject{{User: &iamv1alpha1.PrincipalRef{ID: "usr-forged"}}}
	creates := countCalls("POST /iam/v1/accessBindings")
	createAB(t, ab)
	eventually(t, waitReady, func() error {
		return wantCondition(getAB(t, ab).Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonForbidden)
	})
	consistently(t, time.Second, func() error {
		if countCalls("POST /iam/v1/accessBindings") != creates {
			return fmt.Errorf("kaname called for a user subject without the admission guarantee")
		}
		return nil
	})
}
