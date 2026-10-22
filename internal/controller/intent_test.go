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
	admissionv1 "k8s.io/api/admissionregistration/v1"
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

// opBackground — задержка фонового исполнения операции двойником: строка
// ресурса появляется в списках через это время после ответа на изменяющий
// вызов. Больше паузы requeueNow, с которой идёт проход после конфликта
// записи status, — проход, читающий список сразу, строки ещё не видит.
const opBackground = 1500 * time.Millisecond

// createModes — как двойник исполняет операцию: в ответе на вызов (близнец)
// и фоном, как kaname (operations.Run): строка появляется позже ответа.
var createModes = []struct {
	name       string
	background time.Duration
}{{"inline", 0}, {"background", opBackground}}

// inMode включает фоновое исполнение двойника до конца пробы.
func inMode(t *testing.T, d time.Duration) {
	t.Helper()
	fakeK.SetBackground(d)
	t.Cleanup(func() { fakeK.SetBackground(0) })
}

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
			return fmt.Errorf("%s still present: %w", obj.GetName(), err)
		}
		return nil
	})
}

// CR удалён, пока kaname заводит его выдачу: запись status после Create
// отвергнута конфликтом. После удаления выдач с uid CR не в REVOKED — 0.
// Близнец — удаление после успешной записи (TestABDeletionRevokesAndOrphanDoesNot).
// В фоновом режиме выдача появляется в списке позже ответа Create: пустой
// список при удалении не доказывает, что её не будет.
func TestABDeletedDuringCreateLeavesNoLiveBinding(t *testing.T) {
	for _, m := range createModes {
		t.Run(m.name, func(t *testing.T) {
			tn := newTenant(t, true)
			reserve(t, tn, "abc123")
			readySA(t, tn, "zot-race")
			ab := newAB(tn, "race", "zot-race", "registry.pusher", "abc123")
			fired := onceOn(t, "POST", "/iam/v1/accessBindings", tn.project, func() {
				_ = k8s.Delete(context.Background(), &iamv1alpha1.IAMAccessBinding{ObjectMeta: metav1.ObjectMeta{Name: ab.Name, Namespace: ab.Namespace}})
			})
			inMode(t, m.background)
			createAB(t, ab)
			waitGone(t, ab)
			if !fired.Load() {
				t.Fatal("precondition: the create of the binding was never called")
			}
			// Окно больше фоновой задержки: выдача, заведённая без хозяина,
			// успевает появиться.
			eventually(t, opBackground+5*time.Second, func() error {
				if live := liveOwnedBindings(string(ab.UID)); len(live) != 0 {
					return fmt.Errorf("live bindings of the deleted CR: %d (%s)", len(live), live[0].GetId())
				}
				return nil
			})
			consistently(t, 2*opBackground, func() error {
				if live := liveOwnedBindings(string(ab.UID)); len(live) != 0 {
					return fmt.Errorf("live bindings of the deleted CR: %d (%s)", len(live), live[0].GetId())
				}
				return nil
			})
		})
	}
}

// Цель сменилась, пока kaname заводит замену: id заведённой замены не дошёл
// до status. После схождения у CR ровно одна действующая выдача — на
// последнюю цель. Близнец — та же смена без гонки
// (TestABTargetChangeCreatesNewBindingBeforeRevokingTheOld).
func TestABTargetChangedDuringReplacementLeavesOneLiveBinding(t *testing.T) {
	for _, m := range createModes {
		t.Run(m.name, func(t *testing.T) {
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
					o.(*iamv1alpha1.IAMAccessBinding).Spec.Target.Resources[0].ID = id
				})
			}
			fired := onceOn(t, "POST", "/iam/v1/accessBindings", t1, func() {
				cur := &iamv1alpha1.IAMAccessBinding{}
				if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(ab), cur); err != nil {
					return
				}
				cur.Spec.Target.Resources[0].ID = t2
				_ = k8s.Update(context.Background(), cur)
			})
			inMode(t, m.background)
			retarget(t1)
			converged := func() error {
				cur := getAB(t, ab)
				if !fired.Load() {
					return fmt.Errorf("the create of the replacement was not called yet")
				}
				if cur.Status.ObservedGeneration != cur.Generation || cur.Status.Replaced != nil || cur.Status.PendingOperation != nil {
					return fmt.Errorf("not converged: generation %d/%d, replaced %+v, pending %+v",
						cur.Status.ObservedGeneration, cur.Generation, cur.Status.Replaced, cur.Status.PendingOperation)
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
			}
			eventually(t, waitReady, converged)
			// Выдача замены, чей id потерян, появляется фоном позже ответа
			// Create: схождение держится и после этого.
			consistently(t, 2*opBackground, converged)
			if remoteAB(first.Status.ID).GetStatus() != iamv1.AccessBinding_REVOKED {
				t.Fatal("the first binding was not revoked")
			}
		})
	}
}

// CR учётки удалён, пока kaname её заводит: учётка с uid CR после удаления не
// остаётся (иначе пересозданный CR с тем же spec.name навсегда NotOwned).
// Близнец — удаление после успешной записи (TestSADeletionWaitsForBindingsThenCleansEverything).
func TestSADeletedDuringCreateLeavesNoAccount(t *testing.T) {
	for _, m := range createModes {
		t.Run(m.name, func(t *testing.T) {
			tn := newTenant(t, true)
			name := "zrace" + randSuffix()
			sa := newSA(tn, name)
			fired := onceOn(t, "POST", "/iam/v1/serviceAccounts", name, func() {
				_ = k8s.Delete(context.Background(), &iamv1alpha1.IAMServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: sa.Name, Namespace: sa.Namespace}})
			})
			inMode(t, m.background)
			createSA(t, sa)
			waitGone(t, sa)
			if !fired.Load() {
				t.Fatal("precondition: the create of the account was never called")
			}
			none := func() error {
				for _, r := range fakeK.ServiceAccounts() {
					if r.GetLabels()[iamv1alpha1.LabelOwnerUID] == string(sa.UID) {
						return fmt.Errorf("account %s of the deleted CR survived", r.GetId())
					}
				}
				return nil
			}
			eventually(t, opBackground+5*time.Second, none)
			consistently(t, 2*opBackground, none)
		})
	}
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

// installAdmissionGuard ставит политики допуска, названные конфигурацией
// пробы (policy.admissionGuard), с привязками того же имени. Выражение
// политики пропускает всё: проба меряет сверку гарантии оператором, а не сам
// допуск (его судят test/admission и e2e). Снимаются в конце пробы.
func installAdmissionGuard(t *testing.T) {
	t.Helper()
	for _, name := range testCfg.Policy.AdmissionGuard {
		installGuardPolicy(t, name)
	}
	predate(t, testCfg.Policy.AdmissionGuard...)
}

// predate ждёт, пока политики names станут старше объектов, заводимых после:
// политику, созданную меньше чем за срок вступления в силу (и секунду
// точности отметок времени) до объекта, оператор старше него не считает.
func predate(t *testing.T, names ...string) {
	t.Helper()
	var last time.Time
	for _, name := range names {
		for _, obj := range []client.Object{&admissionv1.ValidatingAdmissionPolicy{}, &admissionv1.ValidatingAdmissionPolicyBinding{}} {
			if err := k8s.Get(context.Background(), client.ObjectKey{Name: name}, obj); err != nil {
				t.Fatalf("predate %s: %v", name, err)
			}
			if ct := obj.GetCreationTimestamp().Time; ct.After(last) {
				last = ct
			}
		}
	}
	time.Sleep(time.Until(last.Add(testCfg.Policy.AdmissionEnforcementDelay.Duration + time.Second + 100*time.Millisecond)))
}

// installGuardPolicy ставит одну политику допуска name с привязкой того же
// имени; снимается в конце пробы.
func installGuardPolicy(t *testing.T, name string) {
	t.Helper()
	ctx := context.Background()
	fail := admissionv1.Fail
	vap := &admissionv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: admissionv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &fail,
			MatchConstraints: &admissionv1.MatchResources{ResourceRules: []admissionv1.NamedRuleWithOperations{{
				RuleWithOperations: admissionv1.RuleWithOperations{
					Operations: []admissionv1.OperationType{admissionv1.Create},
					Rule:       admissionv1.Rule{APIGroups: []string{"iam.kaname.in-cloud.io"}, APIVersions: []string{"*"}, Resources: []string{"iamaccessbindings"}},
				},
			}}},
			Validations: []admissionv1.Validation{{Expression: "true"}},
		},
	}
	bnd := &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       admissionv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: name, ValidationActions: []admissionv1.ValidationAction{admissionv1.Deny}},
	}
	for _, obj := range []client.Object{vap, bnd} {
		if err := k8s.Create(ctx, obj); err != nil {
			t.Fatalf("install admission guard %s: %v", name, err)
		}
		t.Cleanup(func() { _ = k8s.Delete(context.Background(), obj) })
	}
}
