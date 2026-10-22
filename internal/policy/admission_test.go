// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
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
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
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

// binding — объект поколения gen, созданный в created, со свидетельством w,
// записанным оператором: с его печатью.
func binding(created time.Time, gen int64, w *iamv1alpha1.AdmissionWitness) *iamv1alpha1.AccessBinding {
	if w != nil {
		w = w.DeepCopy()
		w.Seal = testSeal.sign("", w)
	}
	return &iamv1alpha1.AccessBinding{
		ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(created), Generation: gen},
		Status:     iamv1alpha1.AccessBindingStatus{AdmissionWitness: w},
	}
}

// t0 — время создания объекта проб; farNow — сверка спустя сутки: сроки
// вступления в силу всех версий, увиденных раньше, истекли.
var (
	t0     = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	farNow = t0.Add(24 * time.Hour)
)

// delay — срок вступления в силу версии политики (policy.admissionEnforcementDelay) проб.
const delay = 10 * time.Second

func guardPolicy(names []string) config.Policy {
	return config.Policy{AdmissionGuard: names, AdmissionEnforcementDelay: config.Duration{Duration: delay}}
}

// pending — запись e, версия которой увидена в since и ещё не вступила в силу.
func pending(e iamv1alpha1.AdmissionPolicyUIDs, since time.Time) iamv1alpha1.AdmissionPolicyUIDs {
	t := metav1.NewTime(since)
	e.PendingSince = &t
	return e
}

// confirmedAt — свидетельство w с подтверждением гарантии поколения gen при
// значении created-by by.
func confirmedAt(w *iamv1alpha1.AdmissionWitness, gen int64, by string) *iamv1alpha1.AdmissionWitness {
	w.ConfirmedGeneration, w.ConfirmedCreatedBy = gen, by
	return w
}

// sameRecord — записи равны, отметка pendingSince — по моменту.
func sameRecord(a, b iamv1alpha1.AdmissionPolicyUIDs) bool {
	pa, pb := a.PendingSince, b.PendingSince
	a.PendingSince, b.PendingSince = nil, nil
	if a != b || (pa == nil) != (pb == nil) {
		return false
	}
	return pa == nil || pa.Equal(pb)
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

// checkAt — сверка в момент now.
func checkAt(objs []client.Object, names []string, ab *iamv1alpha1.AccessBinding, now time.Time) (Guarantee, error) {
	return CheckAdmissionGuarantee(context.Background(), guardClient(objs), guardPolicy(names), testSeal, ab, now)
}

// check — сверка в farNow.
func check(objs []client.Object, names []string, ab *iamv1alpha1.AccessBinding) (Guarantee, error) {
	return checkAt(objs, names, ab, farNow)
}

// holds — гарантия есть.
func holds(t *testing.T, g Guarantee, err error, what string) {
	t.Helper()
	if g.Violation != nil || err != nil {
		t.Fatalf("%s: refused: %v %v", what, g.Violation, err)
	}
}

// edited — objs, где политика (policy) либо привязка name правлена на месте:
// uid тот же, metadata.generation вырос.
func edited(objs []client.Object, name string, policy bool) []client.Object {
	for _, obj := range objs {
		switch o := obj.(type) {
		case *admissionv1.ValidatingAdmissionPolicy:
			if policy && o.Name == name {
				o.Generation++
			}
		case *admissionv1.ValidatingAdmissionPolicyBinding:
			if !policy && o.Name == name {
				o.Generation++
			}
		}
	}
	return objs
}

// reinstalled — objs, где политика name переустановлена: новый uid.
func reinstalled(objs []client.Object, name string) []client.Object {
	for _, obj := range objs {
		if p, ok := obj.(*admissionv1.ValidatingAdmissionPolicy); ok && p.Name == name {
			p.UID += "-again"
		}
	}
	return objs
}

func TestAdmissionGuaranteeHoldsOnlyWhenEveryFactHolds(t *testing.T) {
	created := t0
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
// же поколение, срок вступления в силу истёк) при прежнем поколении spec —
// объект с тем же uid существует непрерывно, а не правленный с тех пор — тот
// же, значит, стоял и при смене. Законный близнец — запись поколения 1 у
// объекта поколения 2; каждое отрицание меняет один факт.
func TestAdmissionGuaranteeIsJudgedAtTheLastSpecChange(t *testing.T) {
	created := t0
	later := func() []client.Object { return guard(created.Add(time.Hour)) }
	g, err := check(later(), guardNames, binding(created, 2, seen(1)))
	holds(t, g, err, "lawful twin: policies seen at generation 1, spec changed to generation 2")
	if want := confirmedAt(seen(1), 2, ""); !equalWitness(g.Witness, want) {
		t.Fatalf("witness = %+v, want the generation-1 records kept and generation 2 confirmed", g.Witness)
	}

	cases := []struct {
		name    string
		witness *iamv1alpha1.AdmissionWitness
		mutate  func([]client.Object) []client.Object
		want    string
		// record — запись о политике kio-writers, которую сверка обязана
		// оставить: увиденное сейчас, при текущем поколении 2; новая версия —
		// с отметкой pendingSince, пока срок вступления в силу не истёк.
		record iamv1alpha1.AdmissionPolicyUIDs
	}{
		{"no witness, policies installed after the object", nil, nil, "kio-writers was installed after", pending(entry("kio-writers", 2), farNow)},
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
		}(), nil, "admission policy binding kio-writers was", pending(entry("kio-writers", 2), farNow)},
		// Правка на месте: uid тот же, поколение выросло — какой версией
		// политики записан текущий spec, неизвестно.
		{"policy changed in place since the witness", seen(1), func(o []client.Object) []client.Object { return edited(o, "kio-writers", true) },
			"admission policy kio-writers was changed in place", func() iamv1alpha1.AdmissionPolicyUIDs {
				e := entry("kio-writers", 2)
				e.PolicyGeneration = 2
				return pending(e, farNow)
			}()},
		{"binding changed in place since the witness", seen(1), func(o []client.Object) []client.Object { return edited(o, "kio-writers", false) },
			"admission policy binding kio-writers was changed in place", func() iamv1alpha1.AdmissionPolicyUIDs {
				e := entry("kio-writers", 2)
				e.BindingGeneration = 2
				return pending(e, farNow)
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
			if got := find(g.Witness, "kio-writers"); got == nil || !sameRecord(*got, tc.record) {
				t.Fatalf("witness record of kio-writers = %+v, want %+v", got, tc.record)
			}
		})
	}

	t.Run("policies predating the object need no witness and are witnessed", func(t *testing.T) {
		g, err := check(guard(created.Add(-time.Hour)), guardNames, binding(created, 5, nil))
		holds(t, g, err, "policies predating the object")
		if want := confirmedAt(seen(0), 5, ""); !equalWitness(g.Witness, want) {
			t.Fatalf("witness = %+v, want %+v: a policy older than the object proves every generation", g.Witness, want)
		}
	})
	// Политика старше объекта, но правлена на месте после того, как оператор
	// её видел, а подтверждения гарантии у объекта нет: старшинство больше
	// ничего не доказывает — правка могла случиться до последней смены spec.
	// И не доказывает ни до срока вступления новой версии в силу, ни после
	// него: запись, оставленная отказом, не открывает выдачу, пока spec не
	// сменён при действующей версии.
	t.Run("a predating policy changed in place proves nothing, on this pass and the next", func(t *testing.T) {
		objs := edited(guard(created.Add(-time.Hour)), "kio-writers", true)
		g, err := check(objs, guardNames, binding(created, 3, seen(0)))
		refused(t, g, err, "admission policy kio-writers was changed in place")
		g, err = checkAt(objs, guardNames, binding(created, 3, g.Witness), farNow.Add(delay))
		refused(t, g, err, "kio-writers was installed or changed after")
		g, err = checkAt(objs, guardNames, binding(created, 4, g.Witness), farNow.Add(delay+time.Second))
		holds(t, g, err, "next spec change under the changed policy in force")
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
	created := t0
	three := append(append([]string{}, guardNames...), "kio-status")
	objs := append(guard(created.Add(time.Hour)), guard(created.Add(-time.Hour), "kio-status")...)

	g, err := check(objs, three, binding(created, 2, seen(1)))
	if g.Violation != nil || err != nil {
		t.Fatalf("a policy older than the object added to the guard refused: %v %v", g.Violation, err)
	}
	want := &iamv1alpha1.AdmissionWitness{Policies: []iamv1alpha1.AdmissionPolicyUIDs{
		entry("kio-writers", 1), entry("kio-bindings", 1), entry("kio-status", 0)}, ConfirmedGeneration: 2}
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

// withNonce — объект поколения gen со свидетельством w и значением nonce
// аннотации rewitness.
func withNonce(gen int64, w *iamv1alpha1.AdmissionWitness, nonce string) *iamv1alpha1.AccessBinding {
	ab := binding(t0, gen, w)
	ab.Annotations = map[string]string{iamv1alpha1.AnnotationRewitness: nonce}
	return ab
}

// Аннотация rewitness — платформа просит засвидетельствовать стоящие
// политики для текущего spec (после переустановки политик, без смены spec).
// Исполняется только значение, поставленное ПОСЛЕ того, как оператор увидел
// эти политики вступившими в силу: его подлинность держат они же (ставит
// только платформа). Отрицания меняют по одному факту: значение уже учтено;
// политики при значении ещё не увидены; политика не отказывает.
func TestAdmissionGuaranteeRewitnessByThePlatform(t *testing.T) {
	created := t0
	objs := guard(created.Add(time.Hour))
	// Переустановленные политики увидены при поколении 2, spec не менялся.
	g, err := check(objs, guardNames, withNonce(2, seen(2), "n1"))
	holds(t, g, err, "rewitness of seen policies")
	if g.Rewitness != "n1" || !g.Rewitnessed {
		t.Fatalf("rewitness = %q honoured %v, want n1 honoured", g.Rewitness, g.Rewitnessed)
	}
	want := confirmedAt(seen(0), 2, "")
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
	// впредь), политики записываются — новое значение платформы, поставленное
	// после того, как они вступили в силу, исполнится.
	t.Run("a value set before the policies were seen is not honoured", func(t *testing.T) {
		g, err := check(objs, guardNames, withNonce(2, nil, "n1"))
		refused(t, g, err, "kio-writers was installed after")
		if g.Rewitness != "n1" || g.Rewitnessed {
			t.Fatalf("rewitness = %q honoured %v, want n1 refused", g.Rewitness, g.Rewitnessed)
		}
		if g.Witness == nil || g.Witness.RewitnessNonce != "n1" {
			t.Fatalf("witness %+v does not account for n1", g.Witness)
		}
		g, err = checkAt(objs, guardNames, withNonce(2, g.Witness, "n1"), farNow.Add(delay))
		refused(t, g, err, "kio-writers was installed or changed after")
		g, err = checkAt(objs, guardNames, withNonce(2, g.Witness, "n2"), farNow.Add(delay+time.Second))
		if g.Violation != nil || err != nil || !g.Rewitnessed {
			t.Fatalf("a new value after the policies took effect: %v %v honoured %v", g.Violation, err, g.Rewitnessed)
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

// Окно между тем, как оператор увидел версию политики, и тем, как её
// исполняет kube-apiserver (он перечитывает политики периодически, раз в
// секунду, каждый экземпляр — со своим отставанием): запись о версии не
// доказывает ничего, пока от первой встречи с ней не истёк срок
// policy.admissionEnforcementDelay. P1–P4 — четыре пути через окно; близнецы
// — те же входы спустя срок.
func TestAdmissionGuaranteeWaitsUntilThePolicyTakesEffect(t *testing.T) {
	created := t0
	installed := created.Add(time.Hour)
	objs := guard(installed)
	// Записи прежних политик U1; поставлены новые U2.
	before := seen(1)
	for i := range before.Policies {
		before.Policies[i].PolicyUID += "-before"
		before.Policies[i].BindingUID += "-before"
	}
	// Проход через 0,1 с после установки U2, при поколении spec 5: переустановка увидена.
	seenAt := installed.Add(100 * time.Millisecond)
	first, err := checkAt(objs, guardNames, binding(created, 5, before), seenAt)
	refused(t, first, err, "reinstalled")

	t.Run("P1 a spec change before the policy takes effect is not proven", func(t *testing.T) {
		now := installed.Add(600 * time.Millisecond)
		g, err := checkAt(objs, guardNames, binding(created, 6, first.Witness), now)
		refused(t, g, err, "admissionEnforcementDelay")
		if want := sightMark(seenAt).Add(delay).Sub(now); g.RecheckAfter != want {
			t.Fatalf("recheck after %s, want %s: the version takes effect then", g.RecheckAfter, want)
		}
	})
	t.Run("P2 a rewitness before the policy takes effect is accounted, not honoured", func(t *testing.T) {
		g, err := checkAt(objs, guardNames, withNonce(5, first.Witness, "n1"), installed.Add(600*time.Millisecond))
		refused(t, g, err, "admissionEnforcementDelay")
		if g.Rewitness != "n1" || g.Rewitnessed {
			t.Fatalf("rewitness = %q honoured %v, want n1 accounted and not honoured", g.Rewitness, g.Rewitnessed)
		}
	})
	// Близнецы P1 и P2: проход после срока закрепляет записи при текущем
	// поколении (оно само не доказано); смена spec и значение rewitness после
	// него — при действующей политике.
	settled, err := checkAt(objs, guardNames, binding(created, 5, first.Witness), sightMark(seenAt).Add(delay))
	refused(t, settled, err, "installed or changed after")
	for _, p := range settled.Witness.Policies {
		if p.PendingSince != nil || p.Generation != 5 {
			t.Fatalf("record %+v after the delay, want it in force at generation 5", p)
		}
	}
	t.Run("twin P1: a spec change after the policy took effect is proven", func(t *testing.T) {
		g, err := checkAt(objs, guardNames, binding(created, 6, settled.Witness), seenAt.Add(delay+time.Second))
		holds(t, g, err, "spec change after the delay")
	})
	t.Run("twin P2: a rewitness after the policy took effect is honoured", func(t *testing.T) {
		g, err := checkAt(objs, guardNames, withNonce(5, settled.Witness, "n1"), seenAt.Add(delay+time.Second))
		holds(t, g, err, "rewitness after the delay")
		if !g.Rewitnessed {
			t.Fatal("rewitness after the delay not honoured")
		}
	})

	// P3, P4: политика не старше объекта, если создана меньше чем за срок (и
	// секунду точности отметок времени) до него. Записи нет — одна запись
	// объекта, наблюдать status не нужно.
	for _, tc := range []struct {
		name   string
		object time.Time
	}{
		{"P3 an object created half a second after the policy", installed.Add(500 * time.Millisecond)},
		{"P4 an object created within the second of the policy", installed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := checkAt(objs, guardNames, binding(tc.object, 1, nil), tc.object.Add(100*time.Millisecond))
			refused(t, g, err, "was installed after")
		})
	}
	t.Run("twin P3 P4: an object created longer than the delay after the policy", func(t *testing.T) {
		object := installed.Add(delay + time.Second + 500*time.Millisecond)
		g, err := checkAt(objs, guardNames, binding(object, 1, nil), object.Add(100*time.Millisecond))
		holds(t, g, err, "object created after the delay")
	})
}

// Смена values чарта правит политики допуска на месте (uid тот же,
// metadata.generation растёт). spec, гарантию которого проход уже подтвердил
// при прежней, действовавшей версии, правка не отзывает — ни до срока
// вступления новой версии в силу, ни после. Отрицания меняют по одному факту
// против законного близнеца: spec сменён после подтверждения; сменилось
// значение created-by; политика переустановлена (пока её не было, status мог
// писать кто угодно — подтверждение в нём ничего не доказывает).
func TestAdmissionGuaranteeConfirmedSpecSurvivesAnInPlaceChange(t *testing.T) {
	const platform, other = "system:serviceaccount:platform-system:onboarding", "system:serviceaccount:platform-system:other"
	created := t0
	at := created.Add(time.Hour)
	byPlatform := func(gen int64, w *iamv1alpha1.AdmissionWitness) *iamv1alpha1.AccessBinding {
		ab := binding(created, gen, w)
		ab.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: platform}
		return ab
	}
	g, err := checkAt(guard(created.Add(-time.Hour)), guardNames, byPlatform(1, nil), at)
	holds(t, g, err, "policies predating the object")
	confirmed := g.Witness
	if confirmed == nil || confirmed.ConfirmedGeneration != 1 || confirmed.ConfirmedCreatedBy != platform {
		t.Fatalf("witness %+v does not confirm generation 1 by %s", confirmed, platform)
	}
	upgraded := func() []client.Object { return edited(guard(created.Add(-time.Hour)), "kio-bindings", true) }

	t.Run("the confirmed spec is kept while the new version takes effect and after it", func(t *testing.T) {
		g, err := checkAt(upgraded(), guardNames, byPlatform(1, confirmed.DeepCopy()), at.Add(time.Second))
		holds(t, g, err, "in-place change, before the delay")
		if rec := find(g.Witness, "kio-bindings"); rec == nil || rec.PendingSince == nil || rec.PolicyGeneration != 2 {
			t.Fatalf("record of the changed policy = %+v, want the new version pending", rec)
		}
		g, err = checkAt(upgraded(), guardNames, byPlatform(1, g.Witness), at.Add(time.Second+delay))
		holds(t, g, err, "in-place change, after the delay")
		g, err = checkAt(upgraded(), guardNames, byPlatform(2, g.Witness), at.Add(2*time.Second+delay))
		holds(t, g, err, "spec change under the new version in force")
	})
	t.Run("a spec changed after the confirmation is refused", func(t *testing.T) {
		g, err := checkAt(upgraded(), guardNames, byPlatform(2, confirmed.DeepCopy()), at.Add(time.Second))
		refused(t, g, err, "admission policy kio-bindings was changed in place")
	})
	t.Run("a created-by changed after the confirmation is refused", func(t *testing.T) {
		ab := byPlatform(1, confirmed.DeepCopy())
		ab.Annotations[iamv1alpha1.AnnotationCreatedBy] = other
		g, err := checkAt(upgraded(), guardNames, ab, at.Add(time.Second))
		refused(t, g, err, "admission policy kio-bindings was changed in place")
	})
	t.Run("a reinstalled policy drops the confirmation", func(t *testing.T) {
		objs := reinstalled(guard(created.Add(-time.Hour)), "kio-bindings")
		g, err := checkAt(objs, guardNames, byPlatform(1, confirmed.DeepCopy()), at.Add(time.Second))
		refused(t, g, err, "admission policy kio-bindings was reinstalled")
		if g.Witness.ConfirmedGeneration != 0 {
			t.Fatalf("confirmation %d survived a reinstall", g.Witness.ConfirmedGeneration)
		}
		g, err = checkAt(objs, guardNames, byPlatform(1, g.Witness), at.Add(2*time.Second+delay))
		refused(t, g, err, "installed or changed after")
	})
}

// stored — свидетельство w после записи в status и чтения обратно (круг
// через JSON): k8s хранит время с точностью до секунды.
func stored(t *testing.T, w *iamv1alpha1.AdmissionWitness) *iamv1alpha1.AdmissionWitness {
	t.Helper()
	if w == nil {
		return nil
	}
	raw, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	out := &iamv1alpha1.AdmissionWitness{}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// written — объект uid поколения gen, созданный в created, с аннотациями
// created-by by и rewitness nonce (пустое — нет) и status, каким его читает
// оператор: свидетельство w — ровно то, что в status записано, кем бы то ни
// было.
func written(t *testing.T, uid types.UID, created time.Time, gen int64, by, nonce string, w *iamv1alpha1.AdmissionWitness) *iamv1alpha1.AccessBinding {
	t.Helper()
	ab := &iamv1alpha1.AccessBinding{ObjectMeta: metav1.ObjectMeta{UID: uid, CreationTimestamp: metav1.NewTime(created), Generation: gen,
		Annotations: map[string]string{}}}
	if by != "" {
		ab.Annotations[iamv1alpha1.AnnotationCreatedBy] = by
	}
	if nonce != "" {
		ab.Annotations[iamv1alpha1.AnnotationRewitness] = nonce
	}
	ab.Status.AdmissionWitness = stored(t, w)
	return ab
}

// Свидетельство лежит в status, а status держит политика status из того же
// перечня admissionGuard. Политики переустановлены вместе (в installed), и у
// новой версии политики status есть своё окно до вступления в силу: status в
// нём пишет любой, кому RBAC даёт accessbindings/status. Записанное так не
// оператором гарантии не даёт — ни в окне, ни после него (SD-K3-9, P5):
// доверие свидетельству не выводится из того, что может записать писатель
// status. Законные близнецы — те же поля, записанные самим оператором после
// вступления политик в силу; запись оператора о другом объекте гарантии не
// даёт.
func TestAdmissionGuaranteeTrustsOnlyTheWitnessTheOperatorWrote(t *testing.T) {
	const platform = "system:serviceaccount:platform-system:onboarding"
	const gen = 3
	const uid = types.UID("ab-1")
	three := []string{"kio-writers", "kio-bindings", "kio-status"}
	created := t0
	installed := created.Add(time.Hour)
	objs := guard(installed, three...)
	// Поля, которые оператор пишет выдаче платформы, когда та засвидетельствовала
	// политики (rewitness) после их вступления в силу.
	fields := &iamv1alpha1.AdmissionWitness{RewitnessNonce: "n1", ConfirmedGeneration: gen, ConfirmedCreatedBy: platform}
	for _, n := range three {
		fields.Policies = append(fields.Policies, entry(n, 0))
	}
	// confirmed — цепочка проходов оператора по объекту id: первая встреча с
	// переустановленными политиками, закрепление записей после срока,
	// rewitness платформы.
	confirmed := func(t *testing.T, id types.UID) *iamv1alpha1.AdmissionWitness {
		t.Helper()
		g, err := checkAt(objs, three, written(t, id, created, gen, platform, "", nil), installed.Add(100*time.Millisecond))
		refused(t, g, err, "was installed after")
		g, err = checkAt(objs, three, written(t, id, created, gen, platform, "", g.Witness), installed.Add(delay+2*time.Second))
		refused(t, g, err, "installed or changed after")
		g, err = checkAt(objs, three, written(t, id, created, gen, platform, "n1", g.Witness), installed.Add(delay+3*time.Second))
		holds(t, g, err, "platform rewitness after the policies took effect")
		if !equalWitness(g.Witness, fields) {
			t.Fatalf("witness = %+v, want %+v", g.Witness, fields)
		}
		return g.Witness
	}

	t.Run("SD-K3-9 the fields written by another writer of status", func(t *testing.T) {
		for _, at := range []time.Duration{500 * time.Millisecond, delay + 5*time.Second} {
			g, err := checkAt(objs, three, written(t, uid, created, gen, platform, "n1", fields), installed.Add(at))
			refused(t, g, err, "carries no valid seal")
		}
	})
	t.Run("twin SD-K3-9: the same fields written by the operator", func(t *testing.T) {
		w := confirmed(t, uid)
		g, err := checkAt(objs, three, written(t, uid, created, gen, platform, "n1", w), installed.Add(delay+5*time.Second))
		holds(t, g, err, "the operator's own witness read back")
	})
	t.Run("P5 pendingSince stripped from the operator's records while the status policy is younger than the delay", func(t *testing.T) {
		first, err := checkAt(objs, three, written(t, uid, created, gen, platform, "", nil), installed.Add(100*time.Millisecond))
		refused(t, first, err, "was installed after")
		forged := stored(t, first.Witness)
		for i := range forged.Policies {
			forged.Policies[i].PendingSince, forged.Policies[i].Generation = nil, 0
		}
		g, err := checkAt(objs, three, written(t, uid, created, gen, platform, "", forged), installed.Add(500*time.Millisecond))
		refused(t, g, err, "carries no valid seal")
	})
	t.Run("twin P5: the operator's records read back after the delay from its first sight", func(t *testing.T) {
		g, err := checkAt(objs, three, written(t, uid, created, gen, platform, "", nil), installed.Add(100*time.Millisecond))
		refused(t, g, err, "was installed after")
		g, err = checkAt(objs, three, written(t, uid, created, gen, platform, "", g.Witness), installed.Add(delay+2*time.Second))
		refused(t, g, err, "installed or changed after")
		g, err = checkAt(objs, three, written(t, uid, created, gen+1, platform, "", g.Witness), installed.Add(delay+3*time.Second))
		holds(t, g, err, "spec change after the policies took effect")
	})
	t.Run("the operator's witness of another object", func(t *testing.T) {
		w := confirmed(t, "ab-other")
		g, err := checkAt(objs, three, written(t, uid, created, gen, platform, "n1", w), installed.Add(delay+5*time.Second))
		refused(t, g, err, "carries no valid seal")
	})
}

// Отметка первой встречи с версией политики (pendingSince) хранится в status
// с точностью до секунды: срок вступления в силу отсчитывается не раньше
// настоящей встречи. Версия увидена в installed+0,9 с, запись прочитана
// обратно; смена spec в installed+срок+0,7 с — раньше срока от настоящей
// встречи — не доказана. Близнец — та же цепочка после срока от неё.
func TestAdmissionGuaranteeCountsTheDelayFromTheActualSight(t *testing.T) {
	created := t0
	installed := created.Add(time.Hour)
	objs := guard(installed)
	first, err := checkAt(objs, guardNames, written(t, "", created, 5, "", "", nil), installed.Add(900*time.Millisecond))
	refused(t, first, err, "was installed after")
	chain := func(settle, change time.Duration) (Guarantee, error) {
		g, err := checkAt(objs, guardNames, written(t, "", created, 5, "", "", first.Witness), installed.Add(settle))
		if err != nil {
			return g, err
		}
		return checkAt(objs, guardNames, written(t, "", created, 6, "", "", g.Witness), installed.Add(change))
	}
	g, err := chain(delay+500*time.Millisecond, delay+700*time.Millisecond)
	refused(t, g, err, "admissionEnforcementDelay")
	g, err = chain(delay+time.Second, delay+1200*time.Millisecond)
	holds(t, g, err, "spec change after the delay from the actual sight")
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
	if a == nil || b == nil || a.RewitnessNonce != b.RewitnessNonce || len(a.Policies) != len(b.Policies) ||
		a.ConfirmedGeneration != b.ConfirmedGeneration || a.ConfirmedCreatedBy != b.ConfirmedCreatedBy {
		return a == b
	}
	for _, p := range b.Policies {
		if got := find(a, p.Name); got == nil || !sameRecord(*got, p) {
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
