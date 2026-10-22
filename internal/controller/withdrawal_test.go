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
// они стоят сейчас, при текущем поколении spec: запись о каждой называет uid
// и metadata.generation и политики, и привязки — те же, что у стоящих
// объектов (признак, по которому платформа ставит rewitness).
func seenGuard(t *testing.T, ab *iamv1alpha1.AccessBinding) {
	t.Helper()
	ctx := context.Background()
	eventually(t, waitReady, func() error {
		cur := getAB(t, ab)
		if cur.Status.ObservedGeneration != cur.Generation || cur.Status.AdmissionWitness == nil {
			return fmt.Errorf("%s: generation %d observed %d, witness %+v", ab.Name, cur.Generation, cur.Status.ObservedGeneration, cur.Status.AdmissionWitness)
		}
		for _, name := range testCfg.Policy.AdmissionGuard {
			vap, bnd := &admissionv1.ValidatingAdmissionPolicy{}, &admissionv1.ValidatingAdmissionPolicyBinding{}
			if err := k8s.Get(ctx, client.ObjectKey{Name: name}, vap); err != nil {
				return err
			}
			if err := k8s.Get(ctx, client.ObjectKey{Name: name}, bnd); err != nil {
				return err
			}
			rec := witnessRecord(cur, name)
			if rec == nil || rec.PolicyUID != vap.UID || rec.PolicyGeneration != vap.Generation || rec.BindingUID != bnd.UID || rec.BindingGeneration != bnd.Generation {
				return fmt.Errorf("%s: witness record %+v does not name policy %s %s/%d and binding %s/%d",
					ab.Name, rec, name, vap.UID, vap.Generation, bnd.UID, bnd.Generation)
			}
		}
		return nil
	})
}

// witnessRecord — запись свидетельства ab о политике name.
func witnessRecord(ab *iamv1alpha1.AccessBinding, name string) *iamv1alpha1.AdmissionPolicyUIDs {
	if ab.Status.AdmissionWitness == nil {
		return nil
	}
	for i := range ab.Status.AdmissionWitness.Policies {
		if p := &ab.Status.AdmissionWitness.Policies[i]; p.Name == name {
			return p
		}
	}
	return nil
}

// inForce переводит часы оператора за срок вступления в силу увиденных
// версий политик и ждёт, что записи свидетельства каждого из abs закреплены:
// ни одна не несёт pendingSince.
func inForce(t *testing.T, abs ...*iamv1alpha1.AccessBinding) {
	t.Helper()
	clk.SetTime(clk.Now().Add(testCfg.Policy.AdmissionEnforcementDelay.Duration + time.Second))
	for _, ab := range abs {
		touch(t, ab)
		eventually(t, waitReady, func() error {
			cur := getAB(t, ab)
			for _, name := range testCfg.Policy.AdmissionGuard {
				if rec := witnessRecord(cur, name); rec == nil || rec.PendingSince != nil {
					return fmt.Errorf("%s: witness record of %s = %+v, want it in force", ab.Name, name, rec)
				}
			}
			return nil
		})
	}
}

// editGuardPolicy правит политику допуска name на месте, как helm upgrade со
// сменой values: uid тот же, metadata.generation растёт.
func editGuardPolicy(t *testing.T, name, message string) {
	t.Helper()
	vap := &admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: name}}
	patchObj(t, vap, func(o client.Object) {
		o.(*admissionv1.ValidatingAdmissionPolicy).Spec.Validations[0].Message = message
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
	predate(t, extra)
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	ab := userAB(tn, "guard-grow", "usr-grow")
	createAB(t, ab)
	refusedForbidden(t, ab)
	afterCreation(t, ab)
	installAdmissionGuard(t)
	touch(t, ab)
	seenGuard(t, ab)
	inForce(t, ab)
	respec(t, ab, "2")
	granted := waitABReady(t, ab).Status.ID

	withPolicy(t, func(p *config.Policy) {
		p.AdmissionGuard = append(append([]string{}, testCfg.Policy.AdmissionGuard...), extra)
	})
	consistently(t, 3*time.Second, func() error { return stillGranted(ab, granted) })
}

// Правка политики допуска на месте (uid тот же, metadata.generation вырос —
// так её правит helm upgrade со сменой values) выдачу, чью гарантию оператор
// подтвердил до правки, не отзывает: её spec записан при прежней, уже
// действовавшей версии. Отрицание меняет один факт: spec второй выдачи
// сменён после правки, пока новая версия не вступила в силу, — какой версией
// он записан, неизвестно, и выдача отозвана как потерявшая гарантию; после
// срока вступления в силу её принимает только следующая смена spec. Близнец
// — выдача учётке, которой гарантия не нужна, действует.
func TestABAdmissionPolicyChangedInPlaceKeepsTheConfirmedBinding(t *testing.T) {
	installAdmissionGuard(t)
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	readySA(t, tn, "zot-edit")
	kept := userAB(tn, "guard-edit", "usr-edit")
	moved := userAB(tn, "guard-edit-moved", "usr-edit-moved")
	twin := newAB(tn, "guard-edit-sa", "zot-edit", "registry.pusher", "abc123")
	ids := map[string]string{}
	for _, ab := range []*iamv1alpha1.AccessBinding{kept, moved, twin} {
		createAB(t, ab)
	}
	for _, ab := range []*iamv1alpha1.AccessBinding{kept, moved, twin} {
		ids[ab.Name] = waitABReady(t, ab).Status.ID
	}

	editGuardPolicy(t, testCfg.Policy.AdmissionGuard[0], "changed by an upgrade")
	respec(t, moved, "2")
	narrowedAway(t, moved, ids[moved.Name])
	if len(recorded.of(moved, iamv1alpha1.ReasonAdmissionGuaranteeLost)) == 0 {
		t.Fatalf("no %s event for a binding whose spec changed under a policy changed in place", iamv1alpha1.ReasonAdmissionGuaranteeLost)
	}
	keep := func() error {
		for _, ab := range []*iamv1alpha1.AccessBinding{kept, twin} {
			if err := stillGranted(ab, ids[ab.Name]); err != nil {
				return err
			}
		}
		return nil
	}
	consistently(t, 2*time.Second, keep)
	if len(recorded.of(kept, iamv1alpha1.ReasonAdmissionGuaranteeLost)) != 0 {
		t.Fatalf("%s reported for the confirmed binding kept through the in-place change", iamv1alpha1.ReasonAdmissionGuaranteeLost)
	}

	inForce(t, kept, moved)
	regrant := noRegrant(t, moved)
	consistently(t, time.Second, func() error {
		if err := regrant(); err != nil {
			return err
		}
		return keep()
	})
	respec(t, moved, "3")
	if id := waitABReady(t, moved).Status.ID; id == "" || remoteAB(id).GetStatus() != iamv1.AccessBinding_ACTIVE {
		t.Fatalf("spec change under the changed policy in force: binding %q", id)
	}
}

// Свидетельство пишется с первого прохода, хотя выдаче учётки на перечень
// объектов гарантия не нужна: правка политики на месте ДО того, как выдача
// перешла на цель «всю область» (её принимают только при гарантии; субъекты
// неизменяемы, поэтому это единственный переход), обнаружена — выдача
// отозвана. Без записи с первого прохода оператор встретил бы политику
// впервые при переходе и счёл бы её, старшую объекта, стоявшей при любой
// записи. Близнец меняет один факт: тот же переход при неправленой политике
// — выдача на всю область заведена, и правка на месте после перехода её не
// отзывает (гарантия перехода подтверждена до правки).
func TestABWitnessIsKeptBeforeTheBindingNeedsTheGuarantee(t *testing.T) {
	installAdmissionGuard(t)
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	readySA(t, tn, "zot-early")
	named := func(name string) *iamv1alpha1.AccessBinding {
		ab := newAB(tn, name, "zot-early", "registry.pusher", "abc123")
		ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: platformPrincipal}
		ab.Spec.Scope.Type = iamv1alpha1.ScopeAccount
		return ab
	}
	early, twin := named("witness-early"), named("witness-early-twin")
	createAB(t, early)
	createAB(t, twin)
	earlyID, twinID := waitABReady(t, early).Status.ID, waitABReady(t, twin).Status.ID
	toWhole := func(ab *iamv1alpha1.AccessBinding) {
		patchObj(t, ab, func(o client.Object) {
			o.(*iamv1alpha1.AccessBinding).Spec.Target = iamv1alpha1.Target{AllInScope: &iamv1alpha1.AllInScope{}}
		})
	}

	toWhole(twin)
	var whole string
	eventually(t, waitReady, func() error {
		cur := getAB(t, twin)
		if cur.Status.ObservedGeneration != cur.Generation || cur.Status.ID == "" || cur.Status.ID == twinID || cur.Status.Replaced != nil {
			return fmt.Errorf("%s: status %+v", twin.Name, cur.Status)
		}
		if b := remoteAB(cur.Status.ID); b == nil || b.GetTarget().GetAllInScope() == nil || b.GetStatus() != iamv1.AccessBinding_ACTIVE {
			return fmt.Errorf("%s: kaname binding %v, want an active allInScope one", twin.Name, b)
		}
		whole = cur.Status.ID
		return wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})

	editGuardPolicy(t, testCfg.Policy.AdmissionGuard[1], "changed before the transition")
	toWhole(early)
	narrowedAway(t, early, earlyID)
	if len(recorded.of(early, iamv1alpha1.ReasonAdmissionGuaranteeLost)) == 0 {
		t.Fatalf("no %s event for the transition after a policy changed in place", iamv1alpha1.ReasonAdmissionGuaranteeLost)
	}
	consistently(t, time.Second, func() error { return stillGranted(twin, whole) })
}

// deletionPolicy: Orphan судит выдачу, а тип цели может перестать
// разрешаться (снят CRD объекта цели): судить её нечем, и Orphan её не
// оставляет — удаление CR отзывает выдачу по её id и завершается, а не
// держит CR (и namespace) в Terminating вечно. Близнец — Orphan допустимой
// выдачи (orphan-kept в TestABOrphanDeletionWithdrawsAForbiddenBinding).
func TestABOrphanDeletionWithAnUnresolvableTargetTypeCompletes(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	readySA(t, tn, "zot-ghost")
	ab := newAB(tn, "orphan-ghost", "zot-ghost", "registry.pusher", "abc123")
	ab.Spec.DeletionPolicy = iamv1alpha1.DeletionPolicyOrphan
	createAB(t, ab)
	granted := waitABReady(t, ab).Status.ID

	withPolicy(t, func(p *config.Policy) {
		r := p.TargetResolvers["registry.registries"]
		r.Group = "ghost.kaname.in-cloud.io"
		p.TargetResolvers = map[string]config.TargetResolver{"registry.registries": r}
	})
	if err := k8s.Delete(context.Background(), ab); err != nil {
		t.Fatal(err)
	}
	waitGone(t, ab)
	if got := remoteAB(granted).GetStatus(); got != iamv1.AccessBinding_REVOKED {
		t.Fatalf("Orphan deletion of a binding whose target type does not resolve left it %s", got)
	}
	if len(recorded.of(ab, iamv1alpha1.ReasonPolicyNarrowed)) == 0 {
		t.Fatalf("no %s event for the withdrawal of a binding that cannot be judged", iamv1alpha1.ReasonPolicyNarrowed)
	}
}

// deletionPolicy: Orphan касается только удаления CR: выдача, которую
// политика оператора запрещает, отзывается и при удалении CR. Три пути:
// сужение уже увидено и отзыв идёт (kaname отвечает 503 — удаление CR
// повторяет отзыв до успеха); то же для выдачи, потерявшей гарантию допуска
// переустановкой политик (на удалении поколение объекта растёт, и запрет
// по гарантии держит уже начатый отзыв, а не новая сверка); сужение впервые
// увидено на удалении (CR удалён, пока оператор стоял). Близнец — Orphan
// допустимой выдачи: после удаления CR выдача действует.
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
	lost := orphan(userAB(tn, "orphan-lost", "usr-lost"))
	lost.Annotations[iamv1alpha1.AnnotationCreatedBy] = otherPlatform
	unseen := orphan(userAB(tn, "orphan-unseen", "usr-unseen"))
	kept := orphan(newAB(tn, "orphan-kept", "zot-orphan", "registry.pusher", "abc123"))
	all := []*iamv1alpha1.AccessBinding{retried, lost, unseen, kept}
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
	failing := []*iamv1alpha1.AccessBinding{retried, lost}
	for _, ab := range failing {
		fakeK.Fail("POST", "^/iam/v1/accessBindings/"+ids[ab.Name]+":revoke$", codes.Unavailable, 2)
	}
	removeAdmissionGuard(t)
	installAdmissionGuard(t)
	withPolicy(t, func(p *config.Policy) { p.PlatformPrincipals = []string{otherPlatform} })

	for _, ab := range failing {
		eventually(t, waitReady, func() error {
			return wantCondition(getAB(t, ab).Status.Conditions, iamv1alpha1.ConditionRejected, metav1.ConditionTrue, iamv1alpha1.ReasonPolicyNarrowed)
		})
	}
	for _, ab := range failing {
		if got := remoteAB(ids[ab.Name]).GetStatus(); got != iamv1.AccessBinding_ACTIVE {
			t.Fatalf("precondition: %s is to be deleted while its revoke fails, yet its binding is %s", ab.Name, got)
		}
	}
	for _, ab := range []*iamv1alpha1.AccessBinding{retried, lost, kept} {
		if err := k8s.Delete(context.Background(), ab); err != nil {
			t.Fatal(err)
		}
	}
	for _, ab := range all {
		waitGone(t, ab)
	}
	for _, ab := range []*iamv1alpha1.AccessBinding{retried, lost, unseen} {
		if got := remoteAB(ids[ab.Name]).GetStatus(); got != iamv1.AccessBinding_REVOKED {
			t.Errorf("%s: Orphan deletion left the forbidden binding %s %s", ab.Name, ids[ab.Name], got)
		}
	}
	for _, ab := range failing {
		if n := countCalls("POST /iam/v1/accessBindings/" + ids[ab.Name] + ":revoke"); n < 3 {
			t.Errorf("%s: revoke called %d times, want the two refused calls repeated until it succeeds", ab.Name, n)
		}
	}
	if got := remoteAB(ids[kept.Name]).GetStatus(); got != iamv1.AccessBinding_ACTIVE {
		t.Errorf("Orphan deletion of a permitted binding revoked it: %s", got)
	}
}

// Переустановка политик допуска (новые uid) отзывает выдачи пользователю:
// spec мог быть записан, пока политик не было. Отзыв сообщается событием
// AdmissionGuaranteeLost и счётчиком отзывов по этой причине. Платформа,
// сверив spec, восстанавливает выдачу аннотацией rewitness без смены spec —
// значением, поставленным после того, как увиденные оператором политики
// вступили в силу. Отрицания меняют по одному факту: значение, стоявшее
// раньше, чем политики увидены (его мог поставить кто угодно, пока политик
// не было), не исполняется; значение и смена spec, поставленные после
// встречи с политиками, но до срока их вступления в силу, — тоже.
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

	// Увиденные политики ещё не вступили в силу (часы оператора стоят):
	// kube-apiserver мог их ещё не исполнять, и ни значение rewitness, ни
	// смена spec в этом окне выдачи не дают — их мог поставить кто угодно.
	ignored := len(recorded.of(ab, "RewitnessIgnored"))
	setAnnotation(t, ab, iamv1alpha1.AnnotationRewitness, "early-"+randSuffix())
	eventually(t, waitReady, func() error {
		if len(recorded.of(ab, "RewitnessIgnored")) == ignored {
			return fmt.Errorf("%s: the value set before the policies took effect is not reported ignored", ab.Name)
		}
		return nil
	})
	respec(t, ab, "early")
	consistently(t, 2*time.Second, regrant)
	gen = getAB(t, ab).Generation

	inForce(t, ab)
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
// политики стояли в силе при прежнем поколении, хотя spec сменён после
// чтения объекта. Опасен проход, закрепляющий запись по истечении срока
// вступления в силу: он ставит ей текущее поколение. Смена spec вклинивается
// детерминированно — посреди чтения политик этим проходом, оператор стоит,
// проходы идут прямо. Запись без проверки версии (Patch без OptimisticLock)
// этой пробой краснеет: следующий проход принял бы spec, записанный мимо
// закрепляющего прохода, и завёл бы выдачу.
func TestABWitnessWriteLosesToAConcurrentSpecChange(t *testing.T) {
	stopOperator()
	t.Cleanup(func() { restartOperator(t, testCfg) })
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	ab := userAB(tn, "guard-race", "usr-race")
	createAB(t, ab)
	afterCreation(t, ab)
	installAdmissionGuard(t)

	base, err := client.NewWithWatch(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	var armed, fired atomic.Bool
	reader := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, isPolicy := obj.(*admissionv1.ValidatingAdmissionPolicy); isPolicy && armed.Load() && fired.CompareAndSwap(false, true) {
				respec(t, ab, "written-while-the-record-settles")
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	r := &AccessBindingReconciler{Client: k8s, Mapper: k8s.RESTMapper(), Reader: reader, Deps: &Deps{
		Kaname: kanameCli, Vault: vaultCli, Config: testCfg, Recorder: recorded, Clock: clk, DriftInterval: time.Minute,
	}}
	pass := func(i int) {
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ab)}); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	creates := countCalls("POST /iam/v1/accessBindings")
	// Первая встреча с политиками, моложе объекта; затем срок их вступления
	// в силу истекает, и смена spec вклинивается в закрепляющий проход.
	pass(0)
	clk.SetTime(clk.Now().Add(testCfg.Policy.AdmissionEnforcementDelay.Duration + time.Second))
	armed.Store(true)
	for i := 1; i < 7; i++ {
		pass(i)
	}
	if !fired.Load() {
		t.Fatal("precondition: the spec change never ran between the reads")
	}
	cur := getAB(t, ab)
	if n := countCalls("POST /iam/v1/accessBindings"); n != creates {
		t.Fatalf("kaname called %d times for a spec written past the settling pass: status %+v", n-creates, cur.Status)
	}
	if err := wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonForbidden); err != nil {
		t.Fatal(err)
	}
}
