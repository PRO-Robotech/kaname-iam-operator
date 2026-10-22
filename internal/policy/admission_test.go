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
	"k8s.io/apimachinery/pkg/types"
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
				ObjectMeta: metav1.ObjectMeta{Name: n, UID: policyUID(n), CreationTimestamp: metav1.NewTime(installed)},
				Spec:       admissionv1.ValidatingAdmissionPolicySpec{FailurePolicy: &fail},
			},
			&admissionv1.ValidatingAdmissionPolicyBinding{
				ObjectMeta: metav1.ObjectMeta{Name: n, UID: bindingUID(n), CreationTimestamp: metav1.NewTime(installed)},
				Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: n,
					ValidationActions: []admissionv1.ValidationAction{admissionv1.Deny},
					// Сервер заполняет выборку пустыми селекторами — охват это не сужает.
					MatchResources: &admissionv1.MatchResources{NamespaceSelector: &metav1.LabelSelector{}, ObjectSelector: &metav1.LabelSelector{}}},
			})
	}
	return out
}

func policyUID(name string) types.UID  { return types.UID("policy-" + name) }
func bindingUID(name string) types.UID { return types.UID("binding-" + name) }

// seen — свидетельство тех политик, что ставит guard, при поколении gen.
func seen(gen int64) *iamv1alpha1.AdmissionWitness {
	w := &iamv1alpha1.AdmissionWitness{Generation: gen}
	for _, n := range guardNames {
		w.Policies = append(w.Policies, iamv1alpha1.AdmissionPolicyUIDs{Name: n, PolicyUID: policyUID(n), BindingUID: bindingUID(n)})
	}
	return w
}

// binding — объект поколения gen, созданный в created, со свидетельством w.
func binding(created time.Time, gen int64, w *iamv1alpha1.AdmissionWitness) *iamv1alpha1.AccessBinding {
	return &iamv1alpha1.AccessBinding{
		ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(created), Generation: gen},
		Status:     iamv1alpha1.AccessBindingStatus{AdmissionWitness: w},
	}
}

func guardClient(objs []client.Object) client.Reader {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func TestAdmissionGuaranteeHoldsOnlyWhenEveryFactHolds(t *testing.T) {
	created := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	check := func(names []string, mutate func([]client.Object) []client.Object) (*Violation, error) {
		objs := guard(created.Add(-time.Hour))
		if mutate != nil {
			objs = mutate(objs)
		}
		v, _, err := CheckAdmissionGuarantee(context.Background(), guardClient(objs), names, binding(created, 1, nil))
		return v, err
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

// Гарантия судится на последнюю смену spec: политика, поставленная ПОСЛЕ
// создания объекта, держит его spec, если оператор видел её (тот же uid) при
// прежнем поколении spec — объект с тем же uid существует непрерывно, значит,
// стоял и при смене. Законный близнец — свидетельство поколения 1 у объекта
// поколения 2; каждое отрицание меняет один факт.
func TestAdmissionGuaranteeIsJudgedAtTheLastSpecChange(t *testing.T) {
	created := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	objs := func() []client.Object { return guard(created.Add(time.Hour)) }
	ab := binding(created, 2, seen(1))
	v, w, err := CheckAdmissionGuarantee(context.Background(), guardClient(objs()), guardNames, ab)
	if v != nil || err != nil {
		t.Fatalf("lawful twin refused: policies seen at generation 1, spec changed to generation 2: %v %v", v, err)
	}
	if w == nil || w.Generation != 1 {
		t.Fatalf("witness = %+v, want the generation-1 witness kept: it still proves every later spec change", w)
	}

	cases := []struct {
		name    string
		witness *iamv1alpha1.AdmissionWitness
		want    string
	}{
		{"no witness, policies installed after the object", nil, "kio-writers was installed after"},
		{"witness of the current generation", seen(2), "kio-writers was installed after"},
		{"policy reinstalled since the witness", func() *iamv1alpha1.AdmissionWitness {
			w := seen(1)
			w.Policies[1].PolicyUID = "policy-kio-bindings-before"
			return w
		}(), "admission policy kio-bindings was installed after"},
		{"binding reinstalled since the witness", func() *iamv1alpha1.AdmissionWitness {
			w := seen(1)
			w.Policies[0].BindingUID = "binding-kio-writers-before"
			return w
		}(), "admission policy binding kio-writers was installed after"},
		{"witness of another policy set", &iamv1alpha1.AdmissionWitness{Generation: 1, Policies: seen(1).Policies[:1]}, "kio-bindings was installed after"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, w, err := CheckAdmissionGuarantee(context.Background(), guardClient(objs()), guardNames, binding(created, 2, tc.witness))
			if err != nil {
				t.Fatalf("error instead of a refusal: %v", err)
			}
			if v == nil || v.Reason != iamv1alpha1.ReasonForbidden || !strings.Contains(v.Message, tc.want) {
				t.Fatalf("violation = %+v, want Forbidden naming %q", v, tc.want)
			}
			// Свидетельство, которое ничего не доказывает, заменяется увиденным
			// сейчас: оно докажет следующую смену spec.
			if want := seen(2); w == nil || w.Generation != 2 || !equalWitness(w, want) {
				t.Fatalf("witness = %+v, want %+v", w, want)
			}
		})
	}

	t.Run("policies predating the object need no witness and are witnessed", func(t *testing.T) {
		v, w, err := CheckAdmissionGuarantee(context.Background(), guardClient(guard(created.Add(-time.Hour))), guardNames, binding(created, 5, nil))
		if v != nil || err != nil {
			t.Fatalf("refused: %v %v", v, err)
		}
		if want := seen(5); !equalWitness(w, want) {
			t.Fatalf("witness = %+v, want %+v", w, want)
		}
	})
	t.Run("an absent policy is not witnessed", func(t *testing.T) {
		v, w, err := CheckAdmissionGuarantee(context.Background(), guardClient(objs()[1:]), guardNames, binding(created, 2, seen(1)))
		if err != nil || v == nil || !strings.Contains(v.Message, "kio-writers is absent") {
			t.Fatalf("violation = %+v, %v", v, err)
		}
		if w != nil {
			t.Fatalf("witness = %+v, want none: the witnessed policy is gone and its uid never returns", w)
		}
	})
}

func equalWitness(a, b *iamv1alpha1.AdmissionWitness) bool {
	if a == nil || b == nil || a.Generation != b.Generation || len(a.Policies) != len(b.Policies) {
		return a == b
	}
	for i := range a.Policies {
		if a.Policies[i] != b.Policies[i] {
			return false
		}
	}
	return true
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
