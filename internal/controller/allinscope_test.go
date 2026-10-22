// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

const platformPrincipal = "system:serviceaccount:platform-system:onboarding"

// newWholeAB — выдача на всю область аккаунта от принципала платформы.
func newWholeAB(tn tenant, name, saName, role string) *iamv1alpha1.AccessBinding {
	ab := newAB(tn, name, saName, role, "")
	ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: platformPrincipal}
	ab.Spec.Scope.Type = iamv1alpha1.ScopeAccount
	ab.Spec.Target = iamv1alpha1.Target{AllInScope: &iamv1alpha1.AllInScope{}}
	return ab
}

func wholeTarget() *iamv1.AccessTarget {
	return &iamv1.AccessTarget{Target: &iamv1.AccessTarget_AllInScope{AllInScope: &iamv1.AccessTargetAllInScope{}}}
}

// Выдача на всю область от принципала платформы при гарантии допуска: в
// kaname — выдача с целью allInScope на аккаунт namespace, с метками владения.
// Удаление CR её отзывает.
func TestABAllInScopeFromThePlatformGrantsTheWholeAccount(t *testing.T) {
	installAdmissionGuard(t)
	tn := newTenant(t, true)
	sa := readySA(t, tn, "zot-whole")
	ab := newWholeAB(tn, "whole", "zot-whole", "registry.pusher")
	createAB(t, ab)
	cur := waitABReady(t, ab)
	b := remoteAB(cur.Status.ID)
	if b == nil || b.GetStatus() != iamv1.AccessBinding_ACTIVE {
		t.Fatalf("kaname binding = %v", b)
	}
	if b.GetTarget().GetAllInScope() == nil || len(b.GetTarget().GetResources().GetResources()) != 0 {
		t.Fatalf("target = %v, want allInScope", b.GetTarget())
	}
	if b.GetScopeType() != "iam.account" || b.GetScopeId() != tn.account || b.GetRoleId() != testRole["registry.pusher"] {
		t.Fatalf("role/scope = %s %s:%s", b.GetRoleId(), b.GetScopeType(), b.GetScopeId())
	}
	if s := b.GetSubjects(); len(s) != 1 || s[0].GetId() != sa.Status.ID {
		t.Fatalf("subjects = %v", s)
	}
	if b.GetLabels()[iamv1alpha1.LabelOwnerUID] != string(cur.UID) || b.GetLabels()[iamv1alpha1.LabelCluster] != clusterName {
		t.Fatalf("labels = %v", b.GetLabels())
	}
	if err := k8s.Delete(context.Background(), ab); err != nil {
		t.Fatal(err)
	}
	eventually(t, waitReady, func() error {
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(ab), &iamv1alpha1.AccessBinding{}); !apierrors.IsNotFound(err) {
			return fmt.Errorf("CR still present: %w", err)
		}
		return nil
	})
	if remoteAB(cur.Status.ID).GetStatus() != iamv1.AccessBinding_REVOKED {
		t.Fatal("deleted CR left its allInScope binding active")
	}
}

// Отрицания выдачи на всю область — каждое меняет один факт против
// TestABAllInScopeFromThePlatformGrantsTheWholeAccount; kaname не зовётся.
func TestABAllInScopeRefusals(t *testing.T) {
	tn := newTenant(t, true)
	readySA(t, tn, "zot-wneg")
	refusedWithoutCall := func(t *testing.T, ab *iamv1alpha1.AccessBinding) {
		t.Helper()
		creates := countCalls("POST /iam/v1/accessBindings")
		createAB(t, ab)
		eventually(t, waitReady, func() error {
			return wantCondition(getAB(t, ab).Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonForbidden)
		})
		consistently(t, time.Second, func() error {
			if countCalls("POST /iam/v1/accessBindings") != creates {
				return fmt.Errorf("kaname called for a refused allInScope binding")
			}
			return nil
		})
	}
	t.Run("from a non-platform writer", func(t *testing.T) {
		installAdmissionGuard(t)
		ab := newWholeAB(tn, "whole-writer", "zot-wneg", "registry.pusher")
		ab.Annotations[iamv1alpha1.AnnotationCreatedBy] = "system:serviceaccount:registry-system:registry-operator"
		refusedWithoutCall(t, ab)
	})
	t.Run("from the platform without the admission guarantee", func(t *testing.T) {
		refusedWithoutCall(t, newWholeAB(tn, "whole-unguarded", "zot-wneg", "registry.pusher"))
	})
	t.Run("to a system class", func(t *testing.T) {
		installAdmissionGuard(t)
		ab := newWholeAB(tn, "whole-public", "zot-wneg", "registry.public.read")
		ab.Spec.Subjects = []iamv1alpha1.Subject{{SystemClass: &iamv1alpha1.SystemClassRef{Name: "anonymous"}}}
		refusedWithoutCall(t, ab)
	})
}

// Своя выдача на всю область (метки владения этого CR) усыновляется без
// Create; чужая с тем же ключом — Conflict, и оператор её не трогает: ни
// усыновления, ни отзыва.
func TestABAdoptsOwnAllInScopeBindingAndLeavesForeignAlone(t *testing.T) {
	installAdmissionGuard(t)
	tn := newTenant(t, true)
	foreignSA := readySA(t, tn, "zot-wforeign")
	foreignID := fakeK.PutBinding(&iamv1.AccessBinding{
		Subjects: []*iamv1.Subject{{Type: iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, Id: foreignSA.Status.ID}},
		RoleId:   testRole["registry.pusher"], ScopeType: "iam.account", ScopeId: tn.account, Target: wholeTarget(),
		Labels: map[string]string{iamv1alpha1.LabelOwnerUID: "someone-else", iamv1alpha1.LabelCluster: clusterName},
	})
	creates, revokes := countCalls("POST /iam/v1/accessBindings"), countCalls("POST /iam/v1/accessBindings/"+foreignID+":revoke")
	foreign := newWholeAB(tn, "whole-foreign", "zot-wforeign", "registry.pusher")
	createAB(t, foreign)
	eventually(t, waitReady, func() error {
		return wantCondition(getAB(t, foreign).Status.Conditions, iamv1alpha1.ConditionConflict, metav1.ConditionTrue, iamv1alpha1.ReasonNotOwned)
	})
	consistently(t, time.Second, func() error {
		if countCalls("POST /iam/v1/accessBindings") != creates {
			return fmt.Errorf("binding created over a foreign allInScope one")
		}
		if countCalls("POST /iam/v1/accessBindings/"+foreignID+":revoke") != revokes {
			return fmt.Errorf("foreign allInScope binding revoked")
		}
		return nil
	})
	if getAB(t, foreign).Status.ID != "" || remoteAB(foreignID).GetStatus() != iamv1.AccessBinding_ACTIVE {
		t.Fatalf("foreign allInScope binding adopted or touched: status %+v, remote %v", getAB(t, foreign).Status, remoteAB(foreignID))
	}

	// Законный близнец: своя выдача с тем же видом цели. uid известен только
	// после создания CR, поэтому CR сначала ждёт аннотаций namespace; субъект —
	// пользователь, его id известен заранее.
	own := newTenant(t, false)
	ab := newWholeAB(own, "whole-own", "unused", "registry.pusher")
	ab.Spec.Subjects = []iamv1alpha1.Subject{{User: &iamv1alpha1.PrincipalRef{ID: "usr-whole-own"}}}
	createAB(t, ab)
	eventually(t, waitReady, func() error {
		return wantCondition(getAB(t, ab).Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonScopeUnresolved)
	})
	ownID := fakeK.PutBinding(&iamv1.AccessBinding{
		Subjects: []*iamv1.Subject{{Type: iamv1.SubjectType_SUBJECT_TYPE_USER, Id: "usr-whole-own"}},
		RoleId:   testRole["registry.pusher"], ScopeType: "iam.account", ScopeId: own.account, Target: wholeTarget(),
		Labels: map[string]string{iamv1alpha1.LabelOwnerUID: string(getAB(t, ab).UID), iamv1alpha1.LabelCluster: clusterName},
	})
	creates = countCalls("POST /iam/v1/accessBindings")
	annotateTenant(t, own)
	touch(t, ab)
	cur := waitABReady(t, ab)
	if cur.Status.ID != ownID {
		t.Fatalf("adopted %q, want %q", cur.Status.ID, ownID)
	}
	if countCalls("POST /iam/v1/accessBindings") != creates {
		t.Fatal("create called although the own allInScope binding exists")
	}
}

// Выдача на всю область, отозванная в kaname мимо оператора, остаётся
// Drifted до resync; смена цели на перечень — новая выдача, прежняя отозвана.
func TestABAllInScopeDriftAndTargetChange(t *testing.T) {
	installAdmissionGuard(t)
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	readySA(t, tn, "zot-wdrift")
	ab := newWholeAB(tn, "whole-drift", "zot-wdrift", "registry.pusher")
	createAB(t, ab)
	first := waitABReady(t, ab)
	creates := countCalls("POST /iam/v1/accessBindings")
	fakeK.RevokeBindingExternally(first.Status.ID)
	eventually(t, waitReady, func() error {
		return wantCondition(getAB(t, ab).Status.Conditions, iamv1alpha1.ConditionDrifted, metav1.ConditionTrue, iamv1alpha1.ReasonRevokedExternally)
	})
	consistently(t, time.Second, func() error {
		if countCalls("POST /iam/v1/accessBindings") != creates {
			return fmt.Errorf("allInScope binding recreated after a revocation in kaname")
		}
		return nil
	})
	patchObj(t, ab, func(o client.Object) {
		o.SetAnnotations(map[string]string{
			iamv1alpha1.AnnotationCreatedBy:   platformPrincipal,
			iamv1alpha1.AnnotationResyncDrift: "regrant-1",
		})
	})
	again := waitABReady(t, ab)
	if again.Status.ID == first.Status.ID || remoteAB(again.Status.ID).GetTarget().GetAllInScope() == nil {
		t.Fatalf("not regranted as allInScope: %+v", again.Status)
	}

	patchObj(t, ab, func(o client.Object) {
		o.(*iamv1alpha1.AccessBinding).Spec.Target = iamv1alpha1.Target{
			Resources: []iamv1alpha1.ResourceRef{{Type: "registry.registries", ID: "abc123"}},
		}
	})
	var named *iamv1alpha1.AccessBinding
	eventually(t, waitReady, func() error {
		named = getAB(t, ab)
		if named.Status.ID == again.Status.ID || named.Status.Replaced != nil || named.Status.ObservedGeneration != named.Generation {
			return fmt.Errorf("status = %+v", named.Status)
		}
		return wantCondition(named.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	if remoteAB(again.Status.ID).GetStatus() != iamv1.AccessBinding_REVOKED {
		t.Fatal("the replaced allInScope binding stays active")
	}
	if res := remoteAB(named.Status.ID).GetTarget().GetResources().GetResources(); len(res) != 1 || res[0].GetId() != "abc123" {
		t.Fatalf("new target = %v", remoteAB(named.Status.ID).GetTarget())
	}
}
