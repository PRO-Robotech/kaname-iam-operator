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

// guard — законный близнец: обе политики и привязки стоят, отказывают, не
// правлены (поколение 1) и установлены в installed. Каждый случай ниже
// меняет один факт.
func guard(installed time.Time, names ...string) []client.Object {
	if len(names) == 0 {
		names = guardNames
	}
	var out []client.Object
	fail := admissionv1.Fail
	for _, n := range names {
		out = append(out,
			&admissionv1.ValidatingAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: n, UID: policyUID(n), Generation: 1, CreationTimestamp: metav1.NewTime(installed)},
				Spec:       admissionv1.ValidatingAdmissionPolicySpec{FailurePolicy: &fail},
			},
			&admissionv1.ValidatingAdmissionPolicyBinding{
				ObjectMeta: metav1.ObjectMeta{Name: n, UID: bindingUID(n), Generation: 1, CreationTimestamp: metav1.NewTime(installed)},
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

// entry — запись свидетельства о политике name, как её ставит guard,
// увиденной при поколении spec gen.
func entry(name string, gen int64) iamv1alpha1.AdmissionPolicyUIDs {
	return iamv1alpha1.AdmissionPolicyUIDs{Name: name, PolicyUID: policyUID(name), PolicyGeneration: 1,
		BindingUID: bindingUID(name), BindingGeneration: 1, Generation: gen}
}

// seen — свидетельство тех политик, что ставит guard, увиденных при поколении
// spec gen.
func seen(gen int64, names ...string) *iamv1alpha1.AdmissionWitness {
	if len(names) == 0 {
		names = guardNames
	}
	w := &iamv1alpha1.AdmissionWitness{}
	for _, n := range names {
		w.Policies = append(w.Policies, entry(n, gen))
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

// refused — отказ гарантии допуска, названный want: Forbidden и признак
// гарантии (её потеря отзывает выдачу как потеря гарантии, а не как сужение
// конфигурации).
func refused(t *testing.T, g Guarantee, err error, want string) {
	t.Helper()
	if err != nil {
		t.Fatalf("error instead of a refusal: %v", err)
	}
	v := g.Violation
	if v == nil || v.Reason != iamv1alpha1.ReasonForbidden || !strings.Contains(v.Message, want) {
		t.Fatalf("violation = %+v, want Forbidden naming %q", v, want)
	}
	if !v.Admission {
		t.Fatalf("violation %q does not carry the admission mark", v.Message)
	}
}

func check(objs []client.Object, names []string, ab *iamv1alpha1.AccessBinding) (Guarantee, error) {
	return CheckAdmissionGuarantee(context.Background(), guardClient(objs), names, ab)
}

func TestAdmissionGuaranteeHoldsOnlyWhenEveryFactHolds(t *testing.T) {
	created := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	run := func(names []string, mutate func([]client.Object) []client.Object) (Guarantee, error) {
		objs := guard(created.Add(-time.Hour))
		if mutate != nil {
			objs = mutate(objs)
		}
		return check(objs, names, binding(created, 1, nil))
	}
	if g, err := run(guardNames, nil); g.Violation != nil || err != nil {
		t.Fatalf("lawful twin refused: %v %v", g.Violation, err)
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
			g, err := run(tc.names, tc.mutate)
			refused(t, g, err, tc.want)
		})
	}
}

// Гарантия судится на последнюю смену spec: политика, поставленная ПОСЛЕ
// создания объекта, держит его spec, если оператор видел её (тот же uid и то
// же поколение) при прежнем поколении spec — объект с тем же uid существует
// непрерывно, а не правленный с тех пор — тот же, значит, стоял и при смене.
// Законный близнец — запись поколения 1 у объекта поколения 2; каждое
// отрицание меняет один факт.
func TestAdmissionGuaranteeIsJudgedAtTheLastSpecChange(t *testing.T) {
	created := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	later := func() []client.Object { return guard(created.Add(time.Hour)) }
	g, err := check(later(), guardNames, binding(created, 2, seen(1)))
	if g.Violation != nil || err != nil {
		t.Fatalf("lawful twin refused: policies seen at generation 1, spec changed to generation 2: %v %v", g.Violation, err)
	}
	if want := seen(1); !equalWitness(g.Witness, want) {
		t.Fatalf("witness = %+v, want the generation-1 records kept: they still prove every later spec change", g.Witness)
	}

	editPolicy := func(name string) func([]client.Object) []client.Object {
		return func(o []client.Object) []client.Object {
			for _, obj := range o {
				if p, ok := obj.(*admissionv1.ValidatingAdmissionPolicy); ok && p.Name == name {
					p.Generation = 2
				}
			}
			return o
		}
	}
	editBinding := func(name string) func([]client.Object) []client.Object {
		return func(o []client.Object) []client.Object {
			for _, obj := range o {
				if b, ok := obj.(*admissionv1.ValidatingAdmissionPolicyBinding); ok && b.Name == name {
					b.Generation = 2
				}
			}
			return o
		}
	}
	cases := []struct {
		name    string
		witness *iamv1alpha1.AdmissionWitness
		mutate  func([]client.Object) []client.Object
		want    string
		// record — запись о политике kio-writers, которую сверка обязана
		// оставить: увиденное сейчас, при текущем поколении 2.
		record iamv1alpha1.AdmissionPolicyUIDs
	}{
		{"no witness, policies installed after the object", nil, nil, "kio-writers was installed after", entry("kio-writers", 2)},
		{"witness of the current generation", seen(2), nil, "kio-writers was installed", entry("kio-writers", 2)},
		{"policy reinstalled since the witness", func() *iamv1alpha1.AdmissionWitness {
			w := seen(1)
			w.Policies[1].PolicyUID = "policy-kio-bindings-before"
			return w
		}(), nil, "admission policy kio-bindings was", entry("kio-writers", 1)},
		{"binding reinstalled since the witness", func() *iamv1alpha1.AdmissionWitness {
			w := seen(1)
			w.Policies[0].BindingUID = "binding-kio-writers-before"
			return w
		}(), nil, "admission policy binding kio-writers was", entry("kio-writers", 2)},
		// Правка на месте: uid тот же, поколение выросло — какой версией
		// политики записан текущий spec, неизвестно.
		{"policy changed in place since the witness", seen(1), editPolicy("kio-writers"),
			"admission policy kio-writers was changed in place", func() iamv1alpha1.AdmissionPolicyUIDs {
				e := entry("kio-writers", 2)
				e.PolicyGeneration = 2
				return e
			}()},
		{"binding changed in place since the witness", seen(1), editBinding("kio-writers"),
			"admission policy binding kio-writers was changed in place", func() iamv1alpha1.AdmissionPolicyUIDs {
				e := entry("kio-writers", 2)
				e.BindingGeneration = 2
				return e
			}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs := later()
			if tc.mutate != nil {
				objs = tc.mutate(objs)
			}
			g, err := check(objs, guardNames, binding(created, 2, tc.witness))
			refused(t, g, err, tc.want)
			// Запись, которая ничего не доказывает, заменяется увиденным
			// сейчас: она докажет следующую смену spec.
			if got := find(g.Witness, "kio-writers"); got == nil || *got != tc.record {
				t.Fatalf("witness record of kio-writers = %+v, want %+v", got, tc.record)
			}
		})
	}

	t.Run("policies predating the object need no witness and are witnessed", func(t *testing.T) {
		g, err := check(guard(created.Add(-time.Hour)), guardNames, binding(created, 5, nil))
		if g.Violation != nil || err != nil {
			t.Fatalf("refused: %v %v", g.Violation, err)
		}
		if want := seen(0); !equalWitness(g.Witness, want) {
			t.Fatalf("witness = %+v, want %+v: a policy older than the object proves every generation", g.Witness, want)
		}
	})
	// Политика старше объекта, но правлена на месте после того, как оператор
	// её видел: старшинство больше ничего не доказывает — правка могла
	// случиться до последней смены spec. И не доказывает на следующем проходе:
	// запись, оставленная отказом, не открывает выдачу, пока spec не сменён.
	t.Run("a predating policy changed in place proves nothing, on this pass and the next", func(t *testing.T) {
		objs := editPolicy("kio-writers")(guard(created.Add(-time.Hour)))
		g, err := check(objs, guardNames, binding(created, 3, seen(0)))
		refused(t, g, err, "admission policy kio-writers was changed in place")
		g, err = check(objs, guardNames, binding(created, 3, g.Witness))
		refused(t, g, err, "kio-writers was installed or changed after")
		g, err = check(objs, guardNames, binding(created, 4, g.Witness))
		if g.Violation != nil || err != nil {
			t.Fatalf("next spec change under the changed, already seen policy refused: %v %v", g.Violation, err)
		}
	})
	t.Run("an absent policy is not witnessed", func(t *testing.T) {
		g, err := check(later()[1:], guardNames, binding(created, 2, seen(1)))
		refused(t, g, err, "kio-writers is absent")
		if got := find(g.Witness, "kio-writers"); got != nil {
			t.Fatalf("witness record %+v, want none: the witnessed policy is gone and its uid never returns", got)
		}
		if got := find(g.Witness, "kio-bindings"); got == nil || *got != entry("kio-bindings", 1) {
			t.Fatalf("witness record of kio-bindings = %+v, want it kept: it still stands", got)
		}
	})
}

// Свидетельство — по каждой политике: смена состава policy.admissionGuard не
// переписывает записи прочих политик, и выдача, допустимая до смены, остаётся
// допустимой и после — на этом проходе и на следующих. Отрицание меняет один
// факт: добавленная политика моложе объекта и прежде не увидена — её запись
// при текущем поколении ничего не доказывает.
func TestAdmissionGuaranteeKeepsEachPolicyWitness(t *testing.T) {
	created := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	three := append(append([]string{}, guardNames...), "kio-status")
	objs := append(guard(created.Add(time.Hour)), guard(created.Add(-time.Hour), "kio-status")...)

	g, err := check(objs, three, binding(created, 2, seen(1)))
	if g.Violation != nil || err != nil {
		t.Fatalf("a policy older than the object added to the guard refused: %v %v", g.Violation, err)
	}
	want := &iamv1alpha1.AdmissionWitness{Policies: []iamv1alpha1.AdmissionPolicyUIDs{
		entry("kio-writers", 1), entry("kio-bindings", 1), entry("kio-status", 0)}}
	if !equalWitness(g.Witness, want) {
		t.Fatalf("witness = %+v, want %+v: the records of the kept policies are not rewritten", g.Witness, want)
	}
	for pass := range 2 {
		if g, err = check(objs, three, binding(created, 2, g.Witness)); g.Violation != nil || err != nil {
			t.Fatalf("pass %d after the guard grew: %v %v", pass+2, g.Violation, err)
		}
	}
	// Политика убрана из перечня и возвращена: её запись не теряется.
	g, err = check(objs, guardNames, binding(created, 2, g.Witness))
	if g.Violation != nil || err != nil {
		t.Fatalf("guard shrunk: %v %v", g.Violation, err)
	}
	if got := find(g.Witness, "kio-status"); got == nil || *got != entry("kio-status", 0) {
		t.Fatalf("record of kio-status, left out of the guard, = %+v, want it kept", got)
	}
	if g, err = check(objs, three, binding(created, 2, g.Witness)); g.Violation != nil || err != nil {
		t.Fatalf("guard grown back: %v %v", g.Violation, err)
	}

	late := append(guard(created.Add(time.Hour)), guard(created.Add(time.Hour), "kio-status")...)
	g, err = check(late, three, binding(created, 2, seen(1)))
	refused(t, g, err, "admission policy kio-status was installed after")
	if got := find(g.Witness, "kio-writers"); got == nil || *got != entry("kio-writers", 1) {
		t.Fatalf("record of kio-writers = %+v, want it kept at generation 1", got)
	}
}

// Аннотация rewitness — платформа просит засвидетельствовать стоящие
// политики для текущего spec (после переустановки политик, без смены spec).
// Исполняется только значение, поставленное ПОСЛЕ того, как оператор увидел
// эти политики: его подлинность держат они же (ставит только платформа).
// Отрицания меняют по одному факту: значение уже учтено; политики при
// значении ещё не увидены; политика не отказывает.
func TestAdmissionGuaranteeRewitnessByThePlatform(t *testing.T) {
	created := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	objs := guard(created.Add(time.Hour))
	withNonce := func(gen int64, w *iamv1alpha1.AdmissionWitness, nonce string) *iamv1alpha1.AccessBinding {
		ab := binding(created, gen, w)
		ab.Annotations = map[string]string{iamv1alpha1.AnnotationRewitness: nonce}
		return ab
	}
	// Переустановленные политики увидены при поколении 2, spec не менялся.
	g, err := check(objs, guardNames, withNonce(2, seen(2), "n1"))
	if g.Violation != nil || err != nil {
		t.Fatalf("rewitness of seen policies refused: %v %v", g.Violation, err)
	}
	if g.Rewitness != "n1" || !g.Rewitnessed {
		t.Fatalf("rewitness = %q honoured %v, want n1 honoured", g.Rewitness, g.Rewitnessed)
	}
	want := seen(0)
	want.RewitnessNonce = "n1"
	if !equalWitness(g.Witness, want) {
		t.Fatalf("witness = %+v, want %+v", g.Witness, want)
	}
	if g, err = check(objs, guardNames, withNonce(2, g.Witness, "n1")); g.Violation != nil || err != nil || g.Rewitness != "" {
		t.Fatalf("next pass after the rewitness: %v %v, new value %q", g.Violation, err, g.Rewitness)
	}

	t.Run("a value already accounted for does nothing", func(t *testing.T) {
		w := seen(2)
		w.RewitnessNonce = "n1"
		g, err := check(objs, guardNames, withNonce(2, w, "n1"))
		refused(t, g, err, "kio-writers was installed")
		if g.Rewitness != "" {
			t.Fatalf("rewitness %q reported anew", g.Rewitness)
		}
	})
	// Значение стояло раньше, чем оператор увидел политики: его мог поставить
	// кто угодно, пока политик не было. Оно учитывается (не исполняется и
	// впредь), политики записываются — новое значение платформы исполнится.
	t.Run("a value set before the policies were seen is not honoured", func(t *testing.T) {
		g, err := check(objs, guardNames, withNonce(2, nil, "n1"))
		refused(t, g, err, "kio-writers was installed after")
		if g.Rewitness != "n1" || g.Rewitnessed {
			t.Fatalf("rewitness = %q honoured %v, want n1 refused", g.Rewitness, g.Rewitnessed)
		}
		if g.Witness == nil || g.Witness.RewitnessNonce != "n1" {
			t.Fatalf("witness %+v does not account for n1", g.Witness)
		}
		g, err = check(objs, guardNames, withNonce(2, g.Witness, "n1"))
		refused(t, g, err, "kio-writers was installed or changed after")
		g, err = check(objs, guardNames, withNonce(2, g.Witness, "n2"))
		if g.Violation != nil || err != nil || !g.Rewitnessed {
			t.Fatalf("a new value after the policies were seen: %v %v honoured %v", g.Violation, err, g.Rewitnessed)
		}
	})
	t.Run("a policy reinstalled since it was seen is not rewitnessed", func(t *testing.T) {
		w := seen(2)
		w.Policies[0].PolicyUID = "policy-kio-writers-before"
		g, err := check(objs, guardNames, withNonce(2, w, "n1"))
		refused(t, g, err, "admission policy kio-writers was")
		if g.Rewitnessed {
			t.Fatal("rewitness honoured for a policy the operator had not seen")
		}
	})
	t.Run("a policy that does not deny is not rewitnessed", func(t *testing.T) {
		warn := guard(created.Add(time.Hour))
		warn[1].(*admissionv1.ValidatingAdmissionPolicyBinding).Spec.ValidationActions = []admissionv1.ValidationAction{admissionv1.Warn}
		g, err := check(warn, guardNames, withNonce(2, seen(2), "n1"))
		refused(t, g, err, "does not deny")
		if g.Rewitnessed {
			t.Fatal("rewitness honoured for a policy that does not deny")
		}
	})
}

func find(w *iamv1alpha1.AdmissionWitness, name string) *iamv1alpha1.AdmissionPolicyUIDs {
	if w == nil {
		return nil
	}
	for i := range w.Policies {
		if w.Policies[i].Name == name {
			return &w.Policies[i]
		}
	}
	return nil
}

func equalWitness(a, b *iamv1alpha1.AdmissionWitness) bool {
	if a == nil || b == nil || a.RewitnessNonce != b.RewitnessNonce || len(a.Policies) != len(b.Policies) {
		return a == b
	}
	for _, p := range b.Policies {
		if got := find(a, p.Name); got == nil || *got != p {
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
