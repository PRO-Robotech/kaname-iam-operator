// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

var guardNames = []string{"kio-writers", "kio-bindings"}

// guard — законный близнец: обе политики и привязки стоят, отказывают и
// установлены за час до создания объекта. Каждый случай ниже меняет один факт.
func guard(installed time.Time) []client.Object {
	var out []client.Object
	fail := admissionv1.Fail
	for _, n := range guardNames {
		out = append(out,
			&admissionv1.ValidatingAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: n, CreationTimestamp: metav1.NewTime(installed)},
				Spec:       admissionv1.ValidatingAdmissionPolicySpec{FailurePolicy: &fail},
			},
			&admissionv1.ValidatingAdmissionPolicyBinding{
				ObjectMeta: metav1.ObjectMeta{Name: n, CreationTimestamp: metav1.NewTime(installed)},
				Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: n,
					ValidationActions: []admissionv1.ValidationAction{admissionv1.Deny},
					// Сервер заполняет выборку пустыми селекторами — охват это не сужает.
					MatchResources: &admissionv1.MatchResources{NamespaceSelector: &metav1.LabelSelector{}, ObjectSelector: &metav1.LabelSelector{}}},
			})
	}
	return out
}

func TestAdmissionGuaranteeHoldsOnlyWhenEveryFactHolds(t *testing.T) {
	created := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	check := func(names []string, mutate func([]client.Object) []client.Object) (*Violation, error) {
		objs := guard(created.Add(-time.Hour))
		if mutate != nil {
			objs = mutate(objs)
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
		return CheckAdmissionGuarantee(context.Background(), c, names, created)
	}
	if v, err := check(guardNames, nil); v != nil || err != nil {
		t.Fatalf("lawful twin refused: %v %v", v, err)
	}
	ignore := admissionv1.Ignore
	cases := []struct {
		name   string
		names  []string
		mutate func([]client.Object) []client.Object
		want   string
	}{
		{"no policy configured", nil, nil, "policy.admissionGuard"},
		{"policy absent", guardNames, func(o []client.Object) []client.Object { return o[1:] }, "admission policy kio-writers is absent"},
		{"binding absent", guardNames, func(o []client.Object) []client.Object { return append(o[:1], o[2:]...) }, "binding kio-writers is absent"},
		{"policy fails open", guardNames, func(o []client.Object) []client.Object {
			o[0].(*admissionv1.ValidatingAdmissionPolicy).Spec.FailurePolicy = &ignore
			return o
		}, "failurePolicy Ignore"},
		{"binding only warns", guardNames, func(o []client.Object) []client.Object {
			o[3].(*admissionv1.ValidatingAdmissionPolicyBinding).Spec.ValidationActions = []admissionv1.ValidationAction{admissionv1.Warn}
			return o
		}, "does not deny"},
		{"binding binds another policy", guardNames, func(o []client.Object) []client.Object {
			o[3].(*admissionv1.ValidatingAdmissionPolicyBinding).Spec.PolicyName = "other"
			return o
		}, `binds policy "other"`},
		{"binding narrowed by a namespace selector", guardNames, func(o []client.Object) []client.Object {
			o[3].(*admissionv1.ValidatingAdmissionPolicyBinding).Spec.MatchResources.NamespaceSelector.MatchLabels = map[string]string{"x": "y"}
			return o
		}, "narrowed"},
		{"policy installed after the object", guardNames, func(o []client.Object) []client.Object {
			o[2].(*admissionv1.ValidatingAdmissionPolicy).CreationTimestamp = metav1.NewTime(created.Add(time.Minute))
			return o
		}, "kio-bindings was installed after"},
		{"binding installed after the object", guardNames, func(o []client.Object) []client.Object {
			o[1].(*admissionv1.ValidatingAdmissionPolicyBinding).CreationTimestamp = metav1.NewTime(created.Add(time.Minute))
			return o
		}, "binding kio-writers was installed after"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := check(tc.names, tc.mutate)
			if err != nil {
				t.Fatalf("error instead of a refusal: %v", err)
			}
			if v == nil || v.Reason != iamv1alpha1.ReasonForbidden || !strings.Contains(v.Message, tc.want) {
				t.Fatalf("violation = %+v, want Forbidden naming %q", v, tc.want)
			}
		})
	}
}

func TestNeedsAdmissionGuaranteeOnlyForUserGroupAndAllInScope(t *testing.T) {
	ab := &iamv1alpha1.AccessBinding{Spec: iamv1alpha1.AccessBindingSpec{Subjects: []iamv1alpha1.Subject{
		{ServiceAccountRef: &iamv1alpha1.LocalServiceAccountRef{Name: "a"}},
		{SystemClass: &iamv1alpha1.SystemClassRef{Name: "anonymous"}},
	}}}
	if NeedsAdmissionGuarantee(ab) {
		t.Fatal("service account and system class subjects need no admission guarantee")
	}
	for _, s := range []iamv1alpha1.Subject{{User: &iamv1alpha1.PrincipalRef{ID: "u"}}, {Group: &iamv1alpha1.PrincipalRef{ID: "g"}}} {
		withPrincipal := ab.DeepCopy()
		withPrincipal.Spec.Subjects = append(withPrincipal.Spec.Subjects, s)
		if !NeedsAdmissionGuarantee(withPrincipal) {
			t.Fatalf("subject %+v needs the admission guarantee", s)
		}
	}
	// Вся область принимается только от принципала платформы, а автора
	// оператор знает из аннотации created-by — значит, тоже только при допуске.
	whole := ab.DeepCopy()
	whole.Spec.Target = iamv1alpha1.Target{AllInScope: &iamv1alpha1.AllInScope{}}
	if !NeedsAdmissionGuarantee(whole) {
		t.Fatal("an allInScope target needs the admission guarantee")
	}
	named := ab.DeepCopy()
	named.Spec.Target = iamv1alpha1.Target{Resources: []iamv1alpha1.ResourceRef{{Type: "registry.registries", ID: "abc123"}}}
	if NeedsAdmissionGuarantee(named) {
		t.Fatal("a named target of service account and system class subjects needs no admission guarantee")
	}
}
