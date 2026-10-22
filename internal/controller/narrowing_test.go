// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
)

// otherPlatform — второй принципал платформы: его выдачи переживают сужение,
// снимающее первого.
const otherPlatform = "system:serviceaccount:platform-system:provisioner"

// narrowedAway ждёт, что выдача объекта отозвана в kaname по сужению политики:
// Rejected/PolicyNarrowed, Ready=False, id выдачи снят, своих действующих
// выдач в kaname нет.
func narrowedAway(t *testing.T, ab *iamv1alpha1.AccessBinding, granted string) {
	t.Helper()
	eventually(t, waitReady, func() error {
		cur := getAB(t, ab)
		if err := wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionRejected, metav1.ConditionTrue, iamv1alpha1.ReasonPolicyNarrowed); err != nil {
			return fmt.Errorf("%s: %w", ab.Name, err)
		}
		if err := wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonPolicyNarrowed); err != nil {
			return fmt.Errorf("%s: %w", ab.Name, err)
		}
		if cur.Status.ID != "" || cur.Status.Replaced != nil || cur.Status.PendingOperation != nil || cur.Status.PendingHash != "" {
			return fmt.Errorf("%s still holds a binding: %+v", ab.Name, cur.Status)
		}
		if got := remoteAB(granted).GetStatus(); got != iamv1.AccessBinding_REVOKED {
			return fmt.Errorf("%s: kaname binding %s is %s, want REVOKED", ab.Name, granted, got)
		}
		if live := activeBindingsOf(string(cur.UID)); len(live) > 0 {
			return fmt.Errorf("%s: %d live bindings in kaname", ab.Name, len(live))
		}
		return nil
	})
}

// stillGranted — выдача, оставшаяся допустимой: та же выдача действует, CR
// Ready, Rejected=False.
func stillGranted(ab *iamv1alpha1.AccessBinding, granted string) error {
	cur := &iamv1alpha1.AccessBinding{}
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(ab), cur); err != nil {
		return err
	}
	if cur.Status.ID != granted {
		return fmt.Errorf("%s: binding %q, want the same %q", ab.Name, cur.Status.ID, granted)
	}
	if got := remoteAB(granted).GetStatus(); got != iamv1.AccessBinding_ACTIVE {
		return fmt.Errorf("%s: kaname binding %s is %s, want ACTIVE", ab.Name, granted, got)
	}
	if err := wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionRejected, metav1.ConditionFalse, iamv1alpha1.ReasonPolicySatisfied); err != nil {
		return fmt.Errorf("%s: %w", ab.Name, err)
	}
	return wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, "")
}

// noRegrant держит окно: у отозванных объектов выдача в kaname не заводится
// вновь, пока политика их запрещает.
func noRegrant(t *testing.T, abs ...*iamv1alpha1.AccessBinding) func() error {
	t.Helper()
	return func() error {
		for _, ab := range abs {
			cur := getAB(t, ab)
			if live := activeBindingsOf(string(cur.UID)); len(live) > 0 || cur.Status.ID != "" {
				return fmt.Errorf("%s granted again while the policy forbids it: status %+v, live %d", ab.Name, cur.Status, len(live))
			}
		}
		return nil
	}
}

// Сужение принципалов платформы: выдачи, принятые только от снятого
// принципала (субъект user, субъект group, цель allInScope), отозваны в
// kaname, CR — Rejected/PolicyNarrowed, и новая выдача не заводится. Политика
// удаления Orphan касается только удаления CR и отзыва не отменяет. Законные
// близнецы, каждый отличается одним фактом: субъект user от принципала,
// оставшегося в перечне, и субъект-учётка, которой принципал не нужен, —
// их выдачи действуют.
func TestABNarrowedPlatformPrincipalsWithdrawUserGroupAndAllInScope(t *testing.T) {
	installAdmissionGuard(t)
	withPolicy(t, func(p *config.Policy) { p.PlatformPrincipals = []string{platformPrincipal, otherPlatform} })
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	readySA(t, tn, "zot-narrow")
	byPlatform := func(name, author string, s iamv1alpha1.Subject) *iamv1alpha1.AccessBinding {
		ab := newAB(tn, name, "zot-narrow", "registry.pusher", "abc123")
		ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: author}
		ab.Spec.Subjects = []iamv1alpha1.Subject{s}
		return ab
	}
	user := byPlatform("narrow-user", platformPrincipal, iamv1alpha1.Subject{User: &iamv1alpha1.PrincipalRef{ID: "usr-narrow"}})
	group := byPlatform("narrow-group", platformPrincipal, iamv1alpha1.Subject{Group: &iamv1alpha1.PrincipalRef{ID: "grp-narrow"}})
	whole := newWholeAB(tn, "narrow-whole", "zot-narrow", "registry.pusher")
	orphan := byPlatform("narrow-orphan", platformPrincipal, iamv1alpha1.Subject{User: &iamv1alpha1.PrincipalRef{ID: "usr-orphan"}})
	orphan.Spec.DeletionPolicy = iamv1alpha1.DeletionPolicyOrphan
	keptUser := byPlatform("kept-user", otherPlatform, iamv1alpha1.Subject{User: &iamv1alpha1.PrincipalRef{ID: "usr-kept"}})
	keptSA := newAB(tn, "kept-sa", "zot-narrow", "registry.pusher", "abc123")
	keptSA.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: platformPrincipal}

	narrowed := []*iamv1alpha1.AccessBinding{user, group, whole, orphan}
	kept := []*iamv1alpha1.AccessBinding{keptUser, keptSA}
	granted := map[string]string{}
	for _, ab := range append(append([]*iamv1alpha1.AccessBinding{}, narrowed...), kept...) {
		createAB(t, ab)
	}
	for _, ab := range append(append([]*iamv1alpha1.AccessBinding{}, narrowed...), kept...) {
		granted[ab.Name] = waitABReady(t, ab).Status.ID
	}

	withPolicy(t, func(p *config.Policy) { p.PlatformPrincipals = []string{otherPlatform} })
	for _, ab := range narrowed {
		narrowedAway(t, ab, granted[ab.Name])
	}
	regrant := noRegrant(t, narrowed...)
	consistently(t, 2*time.Second, func() error {
		if err := regrant(); err != nil {
			return err
		}
		for _, ab := range kept {
			if err := stillGranted(ab, granted[ab.Name]); err != nil {
				return err
			}
		}
		return nil
	})
}

// Сужение перечня ролей: выдача роли, снятой с перечня, отозвана, CR —
// Rejected/PolicyNarrowed, новая не заводится. Близнец — выдача роли,
// оставшейся в перечне, действует. Расширение перечня обратно снова делает
// выдачу допустимой — она заводится заново: Rejected не залипает.
func TestABNarrowedAllowedRolesWithdrawTheBinding(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	readySA(t, tn, "zot-roles")
	pusher := newAB(tn, "roles-pusher", "zot-roles", "registry.pusher", "abc123")
	puller := newAB(tn, "roles-puller", "zot-roles", "registry.puller", "abc123")
	createAB(t, pusher)
	createAB(t, puller)
	first := waitABReady(t, pusher).Status.ID
	kept := waitABReady(t, puller).Status.ID

	withPolicy(t, func(p *config.Policy) { p.AllowedRoles = []string{"registry.puller", "registry.public.read"} })
	narrowedAway(t, pusher, first)
	regrant := noRegrant(t, pusher)
	consistently(t, 2*time.Second, func() error {
		if err := regrant(); err != nil {
			return err
		}
		return stillGranted(puller, kept)
	})

	restartOperator(t, testCfg)
	again := waitABReady(t, pusher)
	if again.Status.ID == "" || again.Status.ID == first || remoteAB(again.Status.ID).GetStatus() != iamv1.AccessBinding_ACTIVE {
		t.Fatalf("widened back: status %+v, want a new active binding", again.Status)
	}
	if err := wantCondition(again.Status.Conditions, iamv1alpha1.ConditionRejected, metav1.ConditionFalse, iamv1alpha1.ReasonPolicySatisfied); err != nil {
		t.Fatal(err)
	}
}

// removeAdmissionGuard снимает политики допуска пробы и ждёт, что их нет.
func removeAdmissionGuard(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, name := range testCfg.Policy.AdmissionGuard {
		for _, obj := range []client.Object{
			&admissionv1.ValidatingAdmissionPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: name}},
			&admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: name}},
		} {
			if err := k8s.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
				t.Fatalf("remove admission guard %s: %v", name, err)
			}
			eventually(t, waitReady, func() error {
				if err := k8s.Get(ctx, client.ObjectKeyFromObject(obj), obj); !apierrors.IsNotFound(err) {
					return fmt.Errorf("%s still present: %v", name, err)
				}
				return nil
			})
		}
	}
}

// witnessed ждёт, что оператор увидел политики допуска при поколении gen.
func witnessed(t *testing.T, ab *iamv1alpha1.AccessBinding, gen int64) {
	t.Helper()
	eventually(t, waitReady, func() error {
		w := getAB(t, ab).Status.AdmissionWitness
		if w == nil || w.Generation != gen || len(w.Policies) != len(testCfg.Policy.AdmissionGuard) {
			return fmt.Errorf("%s: admission witness %+v, want generation %d", ab.Name, w, gen)
		}
		return nil
	})
}

func respec(t *testing.T, ab *iamv1alpha1.AccessBinding, rev string) {
	t.Helper()
	patchObj(t, ab, func(o client.Object) {
		o.(*iamv1alpha1.AccessBinding).Spec.Labels = map[string]string{"rev": rev}
	})
}

func refusedForbidden(t *testing.T, ab *iamv1alpha1.AccessBinding) {
	t.Helper()
	eventually(t, waitReady, func() error {
		cur := getAB(t, ab)
		if cur.Status.ObservedGeneration != cur.Generation {
			return fmt.Errorf("%s: observedGeneration %d of %d", ab.Name, cur.Status.ObservedGeneration, cur.Generation)
		}
		return wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonForbidden)
	})
}

// Гарантия допуска судится на последнюю смену spec, а не на создание CR.
// Политики поставлены ПОСЛЕ создания обоих CR (оба отвергнуты) и увидены
// оператором при поколении 1. Положительный: spec сменён при увиденных
// политиках — гарантия есть, выдача заведена. Её потеря (политики сняты)
// отзывает выдачу. Отрицательный — меняет один факт: spec сменён, пока
// политик не было, и они переустановлены после смены — гарантии нет, kaname
// не зовётся. Близнец отрицательного: следующая смена spec при новых,
// уже увиденных политиках — гарантия есть.
func TestABAdmissionGuaranteeIsJudgedAtTheLastSpecChange(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	byPlatform := func(name, id string) *iamv1alpha1.AccessBinding {
		ab := newAB(tn, name, "unused", "registry.pusher", "abc123")
		ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: platformPrincipal}
		ab.Spec.Subjects = []iamv1alpha1.Subject{{User: &iamv1alpha1.PrincipalRef{ID: id}}}
		return ab
	}
	pos, neg := byPlatform("guard-later", "usr-later"), byPlatform("guard-gap", "usr-gap")
	createAB(t, pos)
	createAB(t, neg)
	refusedForbidden(t, pos)
	refusedForbidden(t, neg)

	installAdmissionGuard(t)
	touch(t, pos)
	touch(t, neg)
	witnessed(t, pos, 1)
	witnessed(t, neg, 1)
	refusedForbidden(t, pos)

	respec(t, pos, "2")
	granted := waitABReady(t, pos).Status.ID
	if remoteAB(granted).GetStatus() != iamv1.AccessBinding_ACTIVE {
		t.Fatalf("binding after a spec change under witnessed policies = %v", remoteAB(granted))
	}

	removeAdmissionGuard(t)
	narrowedAway(t, pos, granted)
	respec(t, neg, "2")
	refusedForbidden(t, neg)
	creates := countCalls("POST /iam/v1/accessBindings")
	installAdmissionGuard(t)
	touch(t, neg)
	witnessed(t, neg, 2)
	refusedForbidden(t, neg)
	consistently(t, time.Second, func() error {
		if countCalls("POST /iam/v1/accessBindings") != creates {
			return fmt.Errorf("kaname called for a spec written while the admission policies were absent")
		}
		return nil
	})

	respec(t, neg, "3")
	if id := waitABReady(t, neg).Status.ID; remoteAB(id).GetStatus() != iamv1.AccessBinding_ACTIVE {
		t.Fatalf("binding after a spec change under the reinstalled, witnessed policies = %v", remoteAB(id))
	}
}
