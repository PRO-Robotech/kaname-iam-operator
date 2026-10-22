// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
)

func testPolicy() config.Policy {
	return config.Policy{
		AllowedRoles:       []string{"registry.pusher", "registry.public.read"},
		SystemClassRoles:   []string{"registry.public.read"},
		PlatformPrincipals: []string{"system:serviceaccount:platform-system:onboarding"},
		TargetResolvers: map[string]config.TargetResolver{
			"registry.registries": {
				Group: "registry.in-cloud.io", Version: "v1alpha1", Resource: "registryidreservations",
				Match: []config.FieldMatch{
					{Path: "spec.registryRef.namespace", Equals: config.NamespacePlaceholder},
					{Path: "status.phase", Equals: "Active"},
				},
			},
		},
	}
}

// lawful — законный близнец: каждый отрицательный случай меняет один факт.
func lawful() *iamv1alpha1.AccessBinding {
	return &iamv1alpha1.AccessBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "ci-pusher", Namespace: "cust01"},
		Spec: iamv1alpha1.AccessBindingSpec{
			Subjects: []iamv1alpha1.Subject{{ServiceAccountRef: &iamv1alpha1.LocalServiceAccountRef{Name: "zot-ci"}}},
			RoleRef:  iamv1alpha1.RoleRef{Name: "registry.pusher"},
			Target:   iamv1alpha1.Target{Resources: []iamv1alpha1.ResourceRef{{Type: "registry.registries", ID: "abc123"}}},
		},
	}
}

func TestEvaluateLawfulBindingPasses(t *testing.T) {
	if v := Evaluate(testPolicy(), lawful()); v != nil {
		t.Fatalf("lawful binding refused: %v", v)
	}
}

func TestEvaluateRefusesEachBrokenFact(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(ab *iamv1alpha1.AccessBinding)
		want   string
	}{
		{"role not allowed", func(ab *iamv1alpha1.AccessBinding) { ab.Spec.RoleRef.Name = "registry.admin" }, "registry.admin"},
		{"system class with an ordinary role", func(ab *iamv1alpha1.AccessBinding) {
			ab.Spec.Subjects = []iamv1alpha1.Subject{{SystemClass: &iamv1alpha1.SystemClassRef{Name: "anonymous"}}}
		}, "system class"},
		{"user without a platform creator", func(ab *iamv1alpha1.AccessBinding) {
			ab.Spec.Subjects = []iamv1alpha1.Subject{{User: &iamv1alpha1.PrincipalRef{ID: "usr1"}}}
		}, "platform"},
		{"group with a foreign creator", func(ab *iamv1alpha1.AccessBinding) {
			ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: "system:serviceaccount:cust01:default"}
			ab.Spec.Subjects = []iamv1alpha1.Subject{{Group: &iamv1alpha1.PrincipalRef{ID: "grp1"}}}
		}, "platform"},
		{"subject with no field", func(ab *iamv1alpha1.AccessBinding) {
			ab.Spec.Subjects = []iamv1alpha1.Subject{{}}
		}, "exactly one"},
		{"target type without a resolver", func(ab *iamv1alpha1.AccessBinding) {
			ab.Spec.Target.Resources[0].Type = "registry.repositories"
		}, "registry.repositories"},
		// Вся область — каскад на все объекты области, включая будущие: ставит
		// только платформа. Каждый случай меняет один факт против близнеца
		// platformAllInScope из TestEvaluateTwinsOfTheRestrictedSubjects.
		{"allInScope without a creator", func(ab *iamv1alpha1.AccessBinding) {
			ab.Spec.Target = iamv1alpha1.Target{AllInScope: &iamv1alpha1.AllInScope{}}
		}, "allInScope is accepted only from a platform principal"},
		{"allInScope from a non-platform writer", func(ab *iamv1alpha1.AccessBinding) {
			ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: "system:serviceaccount:registry-system:registry-operator"}
			ab.Spec.Target = iamv1alpha1.Target{AllInScope: &iamv1alpha1.AllInScope{}}
		}, "allInScope is accepted only from a platform principal"},
		{"allInScope to a system class", func(ab *iamv1alpha1.AccessBinding) {
			platformAllInScope(ab)
			ab.Spec.RoleRef.Name = "registry.public.read"
			ab.Spec.Subjects = []iamv1alpha1.Subject{{SystemClass: &iamv1alpha1.SystemClassRef{Name: "anonymous"}}}
		}, "a system class is never granted allInScope"},
		{"allInScope outside a project or account scope", func(ab *iamv1alpha1.AccessBinding) {
			platformAllInScope(ab)
			ab.Spec.Scope.Type = "iam.cluster"
		}, "allInScope is accepted only with scope iam.project or iam.account"},
		{"both target arms", func(ab *iamv1alpha1.AccessBinding) {
			platformAllInScope(ab)
			ab.Spec.Target.Resources = []iamv1alpha1.ResourceRef{{Type: "registry.registries", ID: "abc123"}}
		}, "exactly one of resources, allInScope"},
		{"neither target arm", func(ab *iamv1alpha1.AccessBinding) {
			ab.Spec.Target = iamv1alpha1.Target{}
		}, "exactly one of resources, allInScope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ab := lawful()
			tc.mutate(ab)
			v := Evaluate(testPolicy(), ab)
			if v == nil {
				t.Fatal("refusal expected")
			}
			if v.Reason != iamv1alpha1.ReasonForbidden || !strings.Contains(v.Message, tc.want) {
				t.Fatalf("violation %+v does not name %q", v, tc.want)
			}
		})
	}
}

func TestEvaluateTwinsOfTheRestrictedSubjects(t *testing.T) {
	ab := lawful()
	ab.Spec.RoleRef.Name = "registry.public.read"
	ab.Spec.Subjects = []iamv1alpha1.Subject{{SystemClass: &iamv1alpha1.SystemClassRef{Name: "anonymous"}}}
	if v := Evaluate(testPolicy(), ab); v != nil {
		t.Errorf("system class with a system class role refused: %v", v)
	}
	ab = lawful()
	ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: "system:serviceaccount:platform-system:onboarding"}
	ab.Spec.Subjects = []iamv1alpha1.Subject{{User: &iamv1alpha1.PrincipalRef{ID: "usr1"}}}
	if v := Evaluate(testPolicy(), ab); v != nil {
		t.Errorf("user from a platform principal refused: %v", v)
	}
	for _, scope := range []iamv1alpha1.ScopeType{"", iamv1alpha1.ScopeProject, iamv1alpha1.ScopeAccount} {
		ab = lawful()
		platformAllInScope(ab)
		ab.Spec.Scope.Type = scope
		if v := Evaluate(testPolicy(), ab); v != nil {
			t.Errorf("allInScope from a platform principal on scope %q refused: %v", scope, v)
		}
	}
}

// platformAllInScope — законная выдача на всю область: автор — принципал
// платформы, субъект — учётка, область — аккаунт.
func platformAllInScope(ab *iamv1alpha1.AccessBinding) {
	ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: "system:serviceaccount:platform-system:onboarding"}
	ab.Spec.Scope.Type = iamv1alpha1.ScopeAccount
	ab.Spec.Target = iamv1alpha1.Target{AllInScope: &iamv1alpha1.AllInScope{}}
}

type staticMapper map[schema.GroupVersionResource]schema.GroupVersionKind

func (m staticMapper) KindFor(r schema.GroupVersionResource) (schema.GroupVersionKind, error) {
	return m[r], nil
}

func reservation(name, ns, phase string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: "registry.in-cloud.io", Version: "v1alpha1", Kind: "RegistryIDReservation"})
	u.SetName(name)
	_ = unstructured.SetNestedField(u.Object, ns, "spec", "registryRef", "namespace")
	_ = unstructured.SetNestedField(u.Object, phase, "status", "phase")
	return u
}

func TestResolveTargets(t *testing.T) {
	gvk := schema.GroupVersionKind{Group: "registry.in-cloud.io", Version: "v1alpha1", Kind: "RegistryIDReservation"}
	mapper := staticMapper{{Group: "registry.in-cloud.io", Version: "v1alpha1", Resource: "registryidreservations"}: gvk}
	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(gvk.GroupVersion().WithKind(gvk.Kind+"List"), &unstructured.UnstructuredList{})
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		reservation("abc123", "cust01", "Active"),
		reservation("foreign1", "cust02", "Active"),
		reservation("pending1", "cust01", "Reserved"),
	).Build()
	refs := func(id string) []iamv1alpha1.ResourceRef {
		return []iamv1alpha1.ResourceRef{{Type: "registry.registries", ID: id}}
	}
	ctx := context.Background()
	if v, err := ResolveTargets(ctx, c, mapper, testPolicy(), "cust01", refs("abc123")); err != nil || v != nil {
		t.Fatalf("own active target: v=%v err=%v", v, err)
	}
	v, err := ResolveTargets(ctx, c, mapper, testPolicy(), "cust01", refs("foreign1"))
	if err != nil || v == nil || v.Reason != iamv1alpha1.ReasonForbidden || !strings.Contains(v.Message, "foreign1") {
		t.Errorf("foreign target: v=%v err=%v", v, err)
	}
	v, err = ResolveTargets(ctx, c, mapper, testPolicy(), "cust01", refs("pending1"))
	if err != nil || v == nil || v.Reason != iamv1alpha1.ReasonTargetUnresolved {
		t.Errorf("not ready target: v=%v err=%v", v, err)
	}
	v, err = ResolveTargets(ctx, c, mapper, testPolicy(), "cust01", refs("absent"))
	if err != nil || v == nil || v.Reason != iamv1alpha1.ReasonTargetUnresolved {
		t.Errorf("absent target: v=%v err=%v", v, err)
	}
	v, err = ResolveTargets(ctx, c, mapper, testPolicy(), "cust01", []iamv1alpha1.ResourceRef{{Type: "unknown.type", ID: "x"}})
	if err != nil || v == nil || v.Reason != iamv1alpha1.ReasonForbidden {
		t.Errorf("unknown type: v=%v err=%v", v, err)
	}
}
