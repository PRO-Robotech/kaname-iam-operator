// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/grpc/codes"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

var reservationGVK = schema.GroupVersionKind{Group: "registry.in-cloud.io", Version: "v1alpha1", Kind: "RegistryIDReservation"}

// reserve заводит резерв id реестра в namespace арендатора (Active).
func reserve(t *testing.T, tn tenant, id string) {
	t.Helper()
	reserveIn(t, tn.ns, id)
}

func reserveIn(t *testing.T, ns, id string) {
	t.Helper()
	ctx := context.Background()
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(reservationGVK)
	u.SetName(id)
	_ = unstructured.SetNestedField(u.Object, ns, "spec", "registryRef", "namespace")
	if err := k8s.Create(ctx, u); err != nil {
		t.Fatalf("create reservation: %v", err)
	}
	t.Cleanup(func() { _ = k8s.Delete(context.Background(), u) })
	_ = unstructured.SetNestedField(u.Object, "Active", "status", "phase")
	if err := k8s.Status().Update(ctx, u); err != nil {
		t.Fatalf("reservation status: %v", err)
	}
}

func newAB(tn tenant, name, saName, role, target string) *iamv1alpha1.AccessBinding {
	return &iamv1alpha1.AccessBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tn.ns},
		Spec: iamv1alpha1.AccessBindingSpec{
			Subjects: []iamv1alpha1.Subject{{ServiceAccountRef: &iamv1alpha1.LocalServiceAccountRef{Name: saName}}},
			RoleRef:  iamv1alpha1.RoleRef{Name: role},
			Target:   iamv1alpha1.Target{Resources: []iamv1alpha1.ResourceRef{{Type: "registry.registries", ID: target}}},
		},
	}
}

func createAB(t *testing.T, ab *iamv1alpha1.AccessBinding) {
	t.Helper()
	if err := k8s.Create(context.Background(), ab); err != nil {
		t.Fatalf("create AB: %v", err)
	}
	t.Cleanup(func() { forceDelete(t, ab) })
}

func getAB(t *testing.T, ab *iamv1alpha1.AccessBinding) *iamv1alpha1.AccessBinding {
	t.Helper()
	out := &iamv1alpha1.AccessBinding{}
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(ab), out); err != nil {
		t.Fatalf("get AB: %v", err)
	}
	return out
}

func waitABReady(t *testing.T, ab *iamv1alpha1.AccessBinding) *iamv1alpha1.AccessBinding {
	t.Helper()
	var cur *iamv1alpha1.AccessBinding
	eventually(t, waitReady, func() error {
		cur = getAB(t, ab)
		if cur.Status.ObservedGeneration != cur.Generation {
			return fmt.Errorf("observedGeneration %d of %d", cur.Status.ObservedGeneration, cur.Generation)
		}
		return wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	return cur
}

func remoteAB(id string) *iamv1.AccessBinding {
	for _, b := range fakeK.Bindings() {
		if b.GetId() == id {
			return b
		}
	}
	return nil
}

func activeBindingsOf(uid string) []*iamv1.AccessBinding {
	var out []*iamv1.AccessBinding
	for _, b := range fakeK.Bindings() {
		if b.GetLabels()[iamv1alpha1.LabelOwnerUID] == uid && b.GetStatus() == iamv1.AccessBinding_ACTIVE {
			out = append(out, b)
		}
	}
	return out
}

// readySA — учётка арендатора, доведённая до Ready.
func readySA(t *testing.T, tn tenant, name string) *iamv1alpha1.ServiceAccount {
	t.Helper()
	sa := newSA(tn, name)
	createSA(t, sa)
	return waitSAReady(t, sa)
}

func TestABCreatesTheBindingInKaname(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	sa := readySA(t, tn, "zot-ci")
	ab := newAB(tn, "zot-ci-pusher", "zot-ci", "registry.pusher", "abc123")
	createAB(t, ab)
	cur := waitABReady(t, ab)
	b := remoteAB(cur.Status.ID)
	if b == nil || b.GetStatus() != iamv1.AccessBinding_ACTIVE {
		t.Fatalf("kaname binding = %v", b)
	}
	if len(b.GetSubjects()) != 1 || b.GetSubjects()[0].GetType() != iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT ||
		b.GetSubjects()[0].GetId() != sa.Status.ID {
		t.Fatalf("subjects = %v", b.GetSubjects())
	}
	if b.GetRoleId() != testRole["registry.pusher"] || b.GetScopeType() != "iam.project" || b.GetScopeId() != tn.project {
		t.Fatalf("role/scope = %s %s:%s", b.GetRoleId(), b.GetScopeType(), b.GetScopeId())
	}
	res := b.GetTarget().GetResources().GetResources()
	if len(res) != 1 || res[0].GetType() != "registry.registries" || res[0].GetId() != "abc123" {
		t.Fatalf("target = %v", b.GetTarget())
	}
	if b.GetLabels()[iamv1alpha1.LabelOwnerUID] != string(cur.UID) || b.GetLabels()[iamv1alpha1.LabelCluster] != clusterName {
		t.Fatalf("labels = %v", b.GetLabels())
	}
	if cur.Status.Resolved == nil || cur.Status.Resolved.ScopeID != tn.project || cur.Status.BindingHash == "" {
		t.Fatalf("status = %+v", cur.Status)
	}
}

func TestABPolicyRefusalsHaveLawfulTwins(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	readySA(t, tn, "zot-pol")
	cases := []struct {
		name   string
		mutate func(ab *iamv1alpha1.AccessBinding)
		reason string
	}{
		{"role outside the allowed list", func(ab *iamv1alpha1.AccessBinding) { ab.Spec.RoleRef.Name = "registry.admin" }, iamv1alpha1.ReasonForbidden},
		{"system class with an ordinary role", func(ab *iamv1alpha1.AccessBinding) {
			ab.Spec.Subjects = []iamv1alpha1.Subject{{SystemClass: &iamv1alpha1.SystemClassRef{Name: "anonymous"}}}
		}, iamv1alpha1.ReasonForbidden},
		{"user subject from a non-platform author", func(ab *iamv1alpha1.AccessBinding) {
			ab.Spec.Subjects = []iamv1alpha1.Subject{{User: &iamv1alpha1.PrincipalRef{ID: "usr1"}}}
		}, iamv1alpha1.ReasonForbidden},
		{"target type without a resolver", func(ab *iamv1alpha1.AccessBinding) {
			ab.Spec.Target.Resources[0].Type = "registry.repositories"
		}, iamv1alpha1.ReasonForbidden},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			creates := countCalls("POST /iam/v1/accessBindings")
			ab := newAB(tn, fmt.Sprintf("neg-%d", i), "zot-pol", "registry.pusher", "abc123")
			tc.mutate(ab)
			createAB(t, ab)
			eventually(t, waitReady, func() error {
				return wantCondition(getAB(t, ab).Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, tc.reason)
			})
			consistently(t, time.Second, func() error {
				if countCalls("POST /iam/v1/accessBindings") != creates {
					return fmt.Errorf("kaname called for a refused binding")
				}
				return nil
			})
		})
	}
	t.Run("twin: system class with the system class role", func(t *testing.T) {
		ab := newAB(tn, "twin-public", "zot-pol", "registry.public.read", "abc123")
		ab.Spec.Subjects = []iamv1alpha1.Subject{{SystemClass: &iamv1alpha1.SystemClassRef{Name: "anonymous"}}}
		createAB(t, ab)
		cur := waitABReady(t, ab)
		if s := remoteAB(cur.Status.ID).GetSubjects(); len(s) != 1 || s[0].GetType() != iamv1.SubjectType_SUBJECT_TYPE_SYSTEM_CLASS || s[0].GetId() != "anonymous" {
			t.Fatalf("subjects = %v", s)
		}
	})
	t.Run("twin: user subject from a platform principal", func(t *testing.T) {
		ab := newAB(tn, "twin-user", "zot-pol", "registry.pusher", "abc123")
		ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: "system:serviceaccount:platform-system:onboarding"}
		ab.Spec.Subjects = []iamv1alpha1.Subject{{User: &iamv1alpha1.PrincipalRef{ID: "usr1"}}}
		createAB(t, ab)
		waitABReady(t, ab)
	})
}

func TestABTargetOfAnotherNamespaceIsForbiddenAndOwnIsLawful(t *testing.T) {
	tn := newTenant(t, true)
	other := newTenant(t, true)
	reserveIn(t, other.ns, "foreign1")
	reserve(t, tn, "own1")
	readySA(t, tn, "zot-tgt")
	creates := countCalls("POST /iam/v1/accessBindings")
	bad := newAB(tn, "foreign", "zot-tgt", "registry.pusher", "foreign1")
	createAB(t, bad)
	eventually(t, waitReady, func() error {
		c := condition(getAB(t, bad).Status.Conditions, iamv1alpha1.ConditionReady)
		if c == nil || c.Reason != iamv1alpha1.ReasonForbidden || !strings.Contains(c.Message, "foreign1") {
			return fmt.Errorf("ready = %+v", c)
		}
		return nil
	})
	if countCalls("POST /iam/v1/accessBindings") != creates {
		t.Fatal("kaname called for a foreign target")
	}
	good := newAB(tn, "own", "zot-tgt", "registry.pusher", "own1")
	createAB(t, good)
	waitABReady(t, good)
}

func TestABTargetAppearsLater(t *testing.T) {
	tn := newTenant(t, true)
	readySA(t, tn, "zot-late")
	ab := newAB(tn, "late", "zot-late", "registry.pusher", "late1")
	createAB(t, ab)
	eventually(t, waitReady, func() error {
		return wantCondition(getAB(t, ab).Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonTargetUnresolved)
	})
	reserve(t, tn, "late1")
	touch(t, ab)
	waitABReady(t, ab)
}

func TestABWaitsForItsSubject(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	ab := newAB(tn, "early", "zot-later", "registry.pusher", "abc123")
	createAB(t, ab)
	eventually(t, waitReady, func() error {
		return wantCondition(getAB(t, ab).Status.Conditions, iamv1alpha1.ConditionSubjectPending, metav1.ConditionTrue, iamv1alpha1.ReasonSubjectNotReady)
	})
	readySA(t, tn, "zot-later")
	cur := waitABReady(t, ab)
	if err := wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionSubjectPending, metav1.ConditionFalse, ""); err != nil {
		t.Fatal(err)
	}
}

func TestABAdoptsOwnBindingAndRefusesForeignIdentical(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	sa := readySA(t, tn, "zot-abad")
	target := func(id string) *iamv1.AccessTarget {
		return &iamv1.AccessTarget{Target: &iamv1.AccessTarget_Resources{Resources: &iamv1.AccessTargetResources{
			Resources: []*iamv1.ResourceRef{{Type: "registry.registries", Id: id}},
		}}}
	}
	subj := []*iamv1.Subject{{Type: iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, Id: sa.Status.ID}}
	// Чужая выдача с тем же ключом: Conflict, без вызовов.
	fakeK.PutBinding(&iamv1.AccessBinding{
		Subjects: subj, RoleId: testRole["registry.pusher"], ScopeType: "iam.project", ScopeId: tn.project, Target: target("abc123"),
		Labels: map[string]string{iamv1alpha1.LabelOwnerUID: "someone-else"},
	})
	creates := countCalls("POST /iam/v1/accessBindings")
	foreign := newAB(tn, "foreign", "zot-abad", "registry.pusher", "abc123")
	createAB(t, foreign)
	eventually(t, waitReady, func() error {
		return wantCondition(getAB(t, foreign).Status.Conditions, iamv1alpha1.ConditionConflict, metav1.ConditionTrue, iamv1alpha1.ReasonNotOwned)
	})
	if countCalls("POST /iam/v1/accessBindings") != creates {
		t.Fatal("binding created over a foreign identical one")
	}
	// Законный близнец: своя выдача (метка uid CR) усыновляется без Create.
	// uid известен только после создания CR, поэтому CR сначала ждёт цель.
	own := newAB(tn, "own", "zot-abad", "registry.pusher", "def999")
	createAB(t, own)
	eventually(t, waitReady, func() error {
		return wantCondition(getAB(t, own).Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonTargetUnresolved)
	})
	ownID := fakeK.PutBinding(&iamv1.AccessBinding{
		Subjects: subj, RoleId: testRole["registry.pusher"], ScopeType: "iam.project", ScopeId: tn.project, Target: target("def999"),
		Labels: map[string]string{iamv1alpha1.LabelOwnerUID: string(getAB(t, own).UID), iamv1alpha1.LabelCluster: clusterName},
	})
	creates = countCalls("POST /iam/v1/accessBindings")
	reserve(t, tn, "def999")
	touch(t, own)
	cur := waitABReady(t, own)
	if cur.Status.ID != ownID {
		t.Fatalf("adopted %q, want %q", cur.Status.ID, ownID)
	}
	if countCalls("POST /iam/v1/accessBindings") != creates {
		t.Fatal("create called although the own binding exists")
	}
}

func TestABTargetChangeCreatesNewBindingBeforeRevokingTheOld(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	reserve(t, tn, "def456")
	readySA(t, tn, "zot-move")
	ab := newAB(tn, "move", "zot-move", "registry.pusher", "abc123")
	createAB(t, ab)
	first := waitABReady(t, ab)
	patchObj(t, ab, func(o client.Object) {
		o.(*iamv1alpha1.AccessBinding).Spec.Target.Resources[0].ID = "def456"
	})
	var second *iamv1alpha1.AccessBinding
	eventually(t, waitReady, func() error {
		second = getAB(t, ab)
		if second.Status.ID == first.Status.ID || second.Status.Replaced != nil || second.Status.ObservedGeneration != second.Generation {
			return fmt.Errorf("status = %+v", second.Status)
		}
		return wantCondition(second.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	if b := remoteAB(first.Status.ID); b.GetStatus() != iamv1.AccessBinding_REVOKED {
		t.Fatalf("old binding status = %s", b.GetStatus())
	}
	nb := remoteAB(second.Status.ID)
	if nb.GetStatus() != iamv1.AccessBinding_ACTIVE || nb.GetTarget().GetResources().GetResources()[0].GetId() != "def456" {
		t.Fatalf("new binding = %v", nb)
	}
	if n := len(activeBindingsOf(string(second.UID))); n != 1 {
		t.Fatalf("active bindings = %d, want 1", n)
	}
	// Порядок: новая заведена раньше, чем отозвана прежняя.
	calls := strings.Join(fakeK.Calls(), "\n")
	revokeAt := strings.Index(calls, "POST /iam/v1/accessBindings/"+first.Status.ID+":revoke")
	if revokeAt < 0 {
		t.Fatal("old binding never revoked")
	}
	if !strings.Contains(calls[:revokeAt], "POST /iam/v1/accessBindings\n") {
		t.Fatal("old binding revoked before the new one was created")
	}
}

// Вторая смена цели, пока прежняя выдача ещё не отозвана (отзыв отказывает),
// не теряет её: каждая заменённая выдача отзывается, действует ровно одна.
func TestABSecondTargetChangeDoesNotForgetTheReplacedBinding(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "tga")
	reserve(t, tn, "tgb")
	reserve(t, tn, "tgc")
	readySA(t, tn, "zot-twice")
	ab := newAB(tn, "twice", "zot-twice", "registry.pusher", "tga")
	createAB(t, ab)
	first := waitABReady(t, ab).Status.ID
	fakeK.FailOperation("POST", "^/iam/v1/accessBindings/"+first+":revoke$", codes.Unavailable, 2)
	patchObj(t, ab, func(o client.Object) { o.(*iamv1alpha1.AccessBinding).Spec.Target.Resources[0].ID = "tgb" })
	eventually(t, waitReady, func() error {
		cur := getAB(t, ab)
		if cur.Status.ID == "" || cur.Status.ID == first || cur.Status.Replaced == nil {
			return fmt.Errorf("status = %+v", cur.Status)
		}
		return nil
	})
	patchObj(t, ab, func(o client.Object) { o.(*iamv1alpha1.AccessBinding).Spec.Target.Resources[0].ID = "tgc" })
	eventually(t, waitReady, func() error {
		cur := getAB(t, ab)
		if cur.Status.Replaced != nil || cur.Status.ObservedGeneration != cur.Generation {
			return fmt.Errorf("status = %+v", cur.Status)
		}
		if err := wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, ""); err != nil {
			return err
		}
		active := activeBindingsOf(string(cur.UID))
		if len(active) != 1 || active[0].GetTarget().GetResources().GetResources()[0].GetId() != "tgc" {
			return fmt.Errorf("active bindings = %v", active)
		}
		return nil
	})
	if remoteAB(first).GetStatus() != iamv1.AccessBinding_REVOKED {
		t.Fatal("the first binding was forgotten and stays active")
	}
}

func TestABRevokedInKanameStaysDriftedUntilResync(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	readySA(t, tn, "zot-abdrift")
	ab := newAB(tn, "drift", "zot-abdrift", "registry.pusher", "abc123")
	createAB(t, ab)
	cur := waitABReady(t, ab)
	creates := countCalls("POST /iam/v1/accessBindings")
	fakeK.RevokeBindingExternally(cur.Status.ID)
	eventually(t, waitReady, func() error {
		return wantCondition(getAB(t, ab).Status.Conditions, iamv1alpha1.ConditionDrifted, metav1.ConditionTrue, iamv1alpha1.ReasonRevokedExternally)
	})
	consistently(t, 2*time.Second, func() error {
		if countCalls("POST /iam/v1/accessBindings") != creates {
			return fmt.Errorf("binding recreated after a revocation in kaname")
		}
		return nil
	})
	patchObj(t, ab, func(o client.Object) {
		o.SetAnnotations(map[string]string{iamv1alpha1.AnnotationResyncDrift: "regrant-1"})
	})
	again := waitABReady(t, ab)
	if again.Status.ID == cur.Status.ID || remoteAB(again.Status.ID).GetStatus() != iamv1.AccessBinding_ACTIVE {
		t.Fatalf("not regranted: %+v", again.Status)
	}
}

func TestABDeletionRevokesAndOrphanDoesNot(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	reserve(t, tn, "def456")
	readySA(t, tn, "zot-abdel")
	ab := newAB(tn, "del", "zot-abdel", "registry.pusher", "abc123")
	createAB(t, ab)
	cur := waitABReady(t, ab)
	orphan := newAB(tn, "keep", "zot-abdel", "registry.pusher", "def456")
	orphan.Spec.DeletionPolicy = iamv1alpha1.DeletionPolicyOrphan
	createAB(t, orphan)
	kept := waitABReady(t, orphan)
	for _, obj := range []client.Object{ab, orphan} {
		if err := k8s.Delete(context.Background(), obj); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, waitReady, func() error {
		for _, obj := range []client.Object{ab, orphan} {
			if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(obj), &iamv1alpha1.AccessBinding{}); !apierrors.IsNotFound(err) {
				return fmt.Errorf("%s still present", obj.GetName())
			}
		}
		return nil
	})
	if remoteAB(cur.Status.ID).GetStatus() != iamv1.AccessBinding_REVOKED {
		t.Fatal("deleted CR left its binding active")
	}
	if remoteAB(kept.Status.ID).GetStatus() != iamv1.AccessBinding_ACTIVE {
		t.Fatal("orphan deletion revoked the binding")
	}
}
