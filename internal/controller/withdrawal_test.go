// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/metrics"
)

// Пробы второго круга сужения: цель, ушедшая из namespace; гарантия допуска,
// судимая по каждой политике и по её поколению; Orphan, не оставляющий
// запрещённую выдачу; переустановка политик и засвидетельствование
// платформой; запись свидетельства против смены spec.

// userAB — выдача пользователю id от принципала платформы.
func userAB(tn tenant, name, id string) *iamv1alpha1.AccessBinding {
	ab := newAB(tn, name, "unused", "registry.pusher", "abc123")
	ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: platformPrincipal}
	ab.Spec.Subjects = []iamv1alpha1.Subject{{User: &iamv1alpha1.PrincipalRef{ID: id}}}
	return ab
}

// afterCreation ждёт, пока объекты k8s, заведённые сейчас, станут моложе ab:
// отметки времени — с точностью до секунды.
func afterCreation(t *testing.T, ab *iamv1alpha1.AccessBinding) {
	t.Helper()
	time.Sleep(time.Until(getAB(t, ab).CreationTimestamp.Add(time.Second + 100*time.Millisecond)))
}

// seenGuard ждёт, что оператор увидел политики допуска пробы такими, какие
// они стоят сейчас (те же uid), при текущем поколении spec.
func seenGuard(t *testing.T, ab *iamv1alpha1.AccessBinding) {
	t.Helper()
	ctx := context.Background()
	eventually(t, waitReady, func() error {
		cur := getAB(t, ab)
		if cur.Status.ObservedGeneration != cur.Generation || cur.Status.AdmissionWitness == nil {
			return fmt.Errorf("%s: generation %d observed %d, witness %+v", ab.Name, cur.Generation, cur.Status.ObservedGeneration, cur.Status.AdmissionWitness)
		}
		for _, name := range testCfg.Policy.AdmissionGuard {
			vap := &admissionv1.ValidatingAdmissionPolicy{}
			if err := k8s.Get(ctx, client.ObjectKey{Name: name}, vap); err != nil {
				return err
			}
			found := false
			for _, p := range cur.Status.AdmissionWitness.Policies {
				found = found || (p.Name == name && p.PolicyUID == vap.UID)
			}
			if !found {
				return fmt.Errorf("%s: witness %+v does not name policy %s uid %s", ab.Name, cur.Status.AdmissionWitness, name, vap.UID)
			}
		}
		return nil
	})
}

func setAnnotation(t *testing.T, obj client.Object, key, value string) {
	t.Helper()
	patchObj(t, obj, func(o client.Object) {
		a := o.GetAnnotations()
		if a == nil {
			a = map[string]string{}
		}
		a[key] = value
		o.SetAnnotations(a)
	})
}

// Цель, ушедшая из namespace CR (объект цели теперь принадлежит чужому
// namespace), запрещает выдачу так же, как сужение политики: выдача отозвана
// в kaname и вновь не заводится. Близнец — выдача той же учётке на цель,
// оставшуюся своей, действует.
func TestABTargetMovedToAnotherNamespaceIsWithdrawn(t *testing.T) {
	tn, other := newTenant(t, true), newTenant(t, true)
	moving, staying := "mv-"+randSuffix(), "st-"+randSuffix()
	reserve(t, tn, moving)
	reserve(t, tn, staying)
	readySA(t, tn, "zot-mv")
	moved := newAB(tn, "moved", "zot-mv", "registry.pusher", moving)
	kept := newAB(tn, "kept", "zot-mv", "registry.pusher", staying)
	createAB(t, moved)
	createAB(t, kept)
	movedID, keptID := waitABReady(t, moved).Status.ID, waitABReady(t, kept).Status.ID

	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(reservationGVK)
	u.SetName(moving)
	patchObj(t, u, func(o client.Object) {
		_ = unstructured.SetNestedField(o.(*unstructured.Unstructured).Object, other.ns, "spec", "registryRef", "namespace")
	})
	narrowedAway(t, moved, movedID)
	regrant := noRegrant(t, moved)
	consistently(t, 2*time.Second, func() error {
		if err := regrant(); err != nil {
			return err
		}
		return stillGranted(kept, keptID)
	})
}

// Смена состава policy.admissionGuard не переписывает свидетельство прочих
// политик: выдача, чью гарантию доказывает запись политики, увиденной до
// последней смены spec, остаётся допустимой, когда в перечень добавлена
// политика старше объекта. Без записи по каждой политике (свидетельство
// целиком при текущем поколении) следующий же проход отзывает её.
func TestABAdmissionGuardGrowingKeepsALawfulBinding(t *testing.T) {
	const extra = "kio-test-extra"
	installGuardPolicy(t, extra)
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	ab := userAB(tn, "guard-grow", "usr-grow")
	createAB(t, ab)
	refusedForbidden(t, ab)
	afterCreation(t, ab)
	installAdmissionGuard(t)
	touch(t, ab)
	seenGuard(t, ab)
	respec(t, ab, "2")
	granted := waitABReady(t, ab).Status.ID

	withPolicy(t, func(p *config.Policy) {
		p.AdmissionGuard = append(append([]string{}, testCfg.Policy.AdmissionGuard...), extra)
	})
	consistently(t, 3*time.Second, func() error { return stillGranted(ab, granted) })
}

// Правка политики допуска на месте (uid тот же, metadata.generation вырос) —
// судится: какой версией политики записан текущий spec, неизвестно, и выдача
// пользователю отозвана как потерявшая гарантию. Близнец — выдача учётке,
// которой гарантия не нужна, действует.
func TestABAdmissionPolicyChangedInPlaceWithdrawsTheBinding(t *testing.T) {
	installAdmissionGuard(t)
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	readySA(t, tn, "zot-edit")
	ab := userAB(tn, "guard-edit", "usr-edit")
	twin := newAB(tn, "guard-edit-sa", "zot-edit", "registry.pusher", "abc123")
	createAB(t, ab)
	createAB(t, twin)
	granted, twinID := waitABReady(t, ab).Status.ID, waitABReady(t, twin).Status.ID

	// Сужение охвата: политика больше не судит выдачи.
	vap := &admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: testCfg.Policy.AdmissionGuard[0]}}
	patchObj(t, vap, func(o client.Object) {
		o.(*admissionv1.ValidatingAdmissionPolicy).Spec.MatchConstraints.ResourceRules[0].Resources = []string{"serviceaccounts"}
	})
	narrowedAway(t, ab, granted)
	if len(recorded.of(ab, iamv1alpha1.ReasonAdmissionGuaranteeLost)) == 0 {
		t.Fatalf("no %s event for a binding withdrawn by a policy changed in place", iamv1alpha1.ReasonAdmissionGuaranteeLost)
	}
	consistently(t, time.Second, func() error { return stillGranted(twin, twinID) })
}

// deletionPolicy: Orphan касается только удаления CR: выдача, которую
// политика оператора запрещает, отзывается и при удалении CR. Два пути:
// сужение уже увидено и отзыв идёт (kaname отвечает 503 — удаление CR
// повторяет отзыв до успеха), и сужение впервые увидено на удалении
// (CR удалён, пока оператор стоял). Близнец — Orphan допустимой выдачи:
// после удаления CR выдача действует.
func TestABOrphanDeletionWithdrawsAForbiddenBinding(t *testing.T) {
	installAdmissionGuard(t)
	withPolicy(t, func(p *config.Policy) { p.PlatformPrincipals = []string{platformPrincipal, otherPlatform} })
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	readySA(t, tn, "zot-orphan")
	orphan := func(ab *iamv1alpha1.AccessBinding) *iamv1alpha1.AccessBinding {
		ab.Spec.DeletionPolicy = iamv1alpha1.DeletionPolicyOrphan
		return ab
	}
	retried := orphan(userAB(tn, "orphan-retried", "usr-retried"))
	unseen := orphan(userAB(tn, "orphan-unseen", "usr-unseen"))
	kept := orphan(newAB(tn, "orphan-kept", "zot-orphan", "registry.pusher", "abc123"))
	all := []*iamv1alpha1.AccessBinding{retried, unseen, kept}
	ids := map[string]string{}
	for _, ab := range all {
		createAB(t, ab)
	}
	for _, ab := range all {
		ids[ab.Name] = waitABReady(t, ab).Status.ID
	}

	stopOperator()
	if err := k8s.Delete(context.Background(), unseen); err != nil {
		t.Fatal(err)
	}
	revoke := "POST /iam/v1/accessBindings/" + ids[retried.Name] + ":revoke"
	fakeK.Fail("POST", "^/iam/v1/accessBindings/"+ids[retried.Name]+":revoke$", codes.Unavailable, 2)
	withPolicy(t, func(p *config.Policy) { p.PlatformPrincipals = []string{otherPlatform} })

	eventually(t, waitReady, func() error {
		return wantCondition(getAB(t, retried).Status.Conditions, iamv1alpha1.ConditionRejected, metav1.ConditionTrue, iamv1alpha1.ReasonPolicyNarrowed)
	})
	if got := remoteAB(ids[retried.Name]).GetStatus(); got != iamv1.AccessBinding_ACTIVE {
		t.Fatalf("precondition: the narrowed binding is to be deleted while its revoke fails, yet it is %s", got)
	}
	for _, ab := range []*iamv1alpha1.AccessBinding{retried, kept} {
		if err := k8s.Delete(context.Background(), ab); err != nil {
			t.Fatal(err)
		}
	}
	for _, ab := range all {
		waitGone(t, ab)
	}
	for _, ab := range []*iamv1alpha1.AccessBinding{retried, unseen} {
		if got := remoteAB(ids[ab.Name]).GetStatus(); got != iamv1.AccessBinding_REVOKED {
			t.Errorf("%s: Orphan deletion left the forbidden binding %s %s", ab.Name, ids[ab.Name], got)
		}
	}
	if n := countCalls(revoke); n < 3 {
		t.Errorf("revoke of %s called %d times, want the two refused calls repeated until it succeeds", ids[retried.Name], n)
	}
	if got := remoteAB(ids[kept.Name]).GetStatus(); got != iamv1.AccessBinding_ACTIVE {
		t.Errorf("Orphan deletion of a permitted binding revoked it: %s", got)
	}
}

// Переустановка политик допуска (новые uid) отзывает выдачи пользователю:
// spec мог быть записан, пока политик не было. Отзыв сообщается событием
// AdmissionGuaranteeLost и счётчиком отзывов по этой причине. Платформа,
// сверив spec, восстанавливает выдачу аннотацией rewitness без смены spec —
// значением, поставленным после того, как оператор увидел стоящие политики.
// Отрицание меняет один факт: значение, стоявшее раньше, чем политики
// увидены (его мог поставить кто угодно, пока политик не было), не
// исполняется.
func TestABReinstalledGuardWithdrawsAndThePlatformRewitnessRestores(t *testing.T) {
	installAdmissionGuard(t)
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	ab := userAB(tn, "guard-reinstall", "usr-reinstall")
	createAB(t, ab)
	cur := waitABReady(t, ab)
	granted, gen := cur.Status.ID, cur.Generation
	lost := testutil.ToFloat64(metrics.Withdrawals.WithLabelValues(iamv1alpha1.ReasonAdmissionGuaranteeLost))

	removeAdmissionGuard(t)
	narrowedAway(t, ab, granted)
	if len(recorded.of(ab, iamv1alpha1.ReasonAdmissionGuaranteeLost)) == 0 {
		t.Fatalf("no %s event for the binding withdrawn by the lost admission guarantee", iamv1alpha1.ReasonAdmissionGuaranteeLost)
	}
	if got := testutil.ToFloat64(metrics.Withdrawals.WithLabelValues(iamv1alpha1.ReasonAdmissionGuaranteeLost)); got <= lost {
		t.Fatalf("withdrawals by %s = %v, was %v", iamv1alpha1.ReasonAdmissionGuaranteeLost, got, lost)
	}

	setAnnotation(t, ab, iamv1alpha1.AnnotationRewitness, "before-"+randSuffix())
	afterCreation(t, ab)
	installAdmissionGuard(t)
	touch(t, ab)
	seenGuard(t, ab)
	regrant := noRegrant(t, ab)
	consistently(t, 2*time.Second, regrant)

	setAnnotation(t, ab, iamv1alpha1.AnnotationRewitness, "after-"+randSuffix())
	again := waitABReady(t, ab)
	if again.Generation != gen || again.Status.ID == "" || again.Status.ID == granted || remoteAB(again.Status.ID).GetStatus() != iamv1.AccessBinding_ACTIVE {
		t.Fatalf("rewitness did not restore the binding without a spec change: generation %d (was %d), status %+v", again.Generation, gen, again.Status)
	}
	if len(recorded.of(ab, "Rewitnessed")) == 0 {
		t.Fatal("no Rewitnessed event")
	}
}

// Свидетельство пишется в status с проверкой resourceVersion: проход,
// прочитавший объект до смены spec, а политики — после неё, записал бы, что
// политики стояли при прежнем поколении, хотя spec сменён, пока их не было.
// Смена spec вклинивается детерминированно — посреди чтения политик (снятие,
// смена spec, установка), оператор стоит, проходы идут прямо. Запись без
// проверки версии (Patch без OptimisticLock) этой пробой краснеет:
// следующий проход принял бы spec, записанный без политик, и завёл бы выдачу.
func TestABWitnessWriteLosesToAConcurrentSpecChange(t *testing.T) {
	stopOperator()
	t.Cleanup(func() { restartOperator(t, testCfg) })
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	ab := userAB(tn, "guard-race", "usr-race")
	createAB(t, ab)

	base, err := client.NewWithWatch(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	var fired atomic.Bool
	reader := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, isPolicy := obj.(*admissionv1.ValidatingAdmissionPolicy); isPolicy && fired.CompareAndSwap(false, true) {
				respec(t, ab, "written-without-the-guard")
				afterCreation(t, ab)
				installAdmissionGuard(t)
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	r := &AccessBindingReconciler{Client: k8s, Mapper: k8s.RESTMapper(), Reader: reader, Deps: &Deps{
		Kaname: kanameCli, Vault: vaultCli, Config: testCfg, Recorder: recorded, Clock: clk, DriftInterval: time.Minute,
	}}
	creates := countCalls("POST /iam/v1/accessBindings")
	for i := range 6 {
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ab)}); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	if !fired.Load() {
		t.Fatal("precondition: the spec change never ran between the reads")
	}
	cur := getAB(t, ab)
	if n := countCalls("POST /iam/v1/accessBindings"); n != creates {
		t.Fatalf("kaname called %d times for a spec written while the admission policies were absent: status %+v", n-creates, cur.Status)
	}
	if err := wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonForbidden); err != nil {
		t.Fatal(err)
	}
}
