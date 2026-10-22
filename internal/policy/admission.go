// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
)

// NeedsAdmissionGuarantee — несёт ли выдача то, что допустимо только от
// принципала платформы (субъект user или group, цель allInScope): решение о
// нём читает аннотацию created-by, а её пишет клиент.
func NeedsAdmissionGuarantee(ab *iamv1alpha1.AccessBinding) bool {
	return ab.Spec.Target.AllInScope != nil ||
		slices.ContainsFunc(ab.Spec.Subjects, func(s iamv1alpha1.Subject) bool { return s.User != nil || s.Group != nil })
}

// Guarantee — исход сверки гарантии допуска.
type Guarantee struct {
	// Violation — гарантии нет; nil — есть.
	Violation *Violation
	// Witness — свидетельство, которое объекту следует хранить.
	Witness *iamv1alpha1.AdmissionWitness
	// Rewitness — новое значение аннотации rewitness, учтённое этой сверкой;
	// пусто — нового значения нет.
	Rewitness string
	// Rewitnessed — значение Rewitness исполнено: политики засвидетельствованы
	// для текущего spec. Ложь при непустом Rewitness — отклонено.
	Rewitnessed bool
	// RecheckAfter — через сколько истекает срок вступления в силу ближайшей
	// увиденной версии политики; 0 — ждать нечего.
	RecheckAfter time.Duration
}

// CheckAdmissionGuarantee подтверждает, что подлинность аннотации created-by
// и субъектов user/group объекта ab держит допуск: каждая политика из
// p.AdmissionGuard (ValidatingAdmissionPolicy) и её привязка с тем же именем
// стоят в кластере, отказывают (failurePolicy Fail, validationActions Deny),
// не сужены параметрами и выборками и исполнялись — той же версией — уже
// тогда, когда записан текущий spec объекта (его последняя смена, поколение
// ab.Generation). seal — печать оператора; now — часы оператора.
//
// Без этого аннотация — слово клиента: тот, кто вправе писать AccessBinding,
// пишет в created-by имя принципала платформы, а смену spec, пока политик
// нет (или пока они правлены в пропускающие), не судит никто. Исполнение
// политики при записи spec доказывает запись свидетельства о ней
// (ab.Status.AdmissionWitness), по одной на политику: объект k8s с тем же uid
// существует непрерывно, а metadata.generation растёт при каждой правке его
// spec, поэтому политика и привязка с записанными uid и поколениями стояли
// неизменными от записи до сейчас.
//
// Стоять — ещё не исполняться: kube-apiserver перечитывает политики
// периодически (раз в секунду), каждый экземпляр — со своим отставанием, а
// оператор читает их мимо него. Поэтому версия, впервые увиденная оператором,
// вступает в силу по истечении p.AdmissionEnforcementDelay от первой встречи
// с ней: до того её запись несёт pendingSince (момент встречи, округлённый
// вверх до секунды — с такой точностью его хранит k8s) и не доказывает ни
// одного поколения spec, а значение rewitness при ней не исполняется. Первый
// проход после срока снимает pendingSince и ставит записи текущее поколение — со
// следующей смены spec запись его доказывает. Политика старше объекта, только
// если создана раньше него больше чем на срок и секунду (точность отметок
// времени k8s — секунда; равные отметки старшинства не доказывают).
//
// Запись доказывает смены spec после поколения, при котором поставлена;
// запись поколения 0 — любые. Пишется она:
//   - при первой встрече с политикой, старшей самого объекта, — поколения 0:
//     исполнялась при любой записи объекта;
//   - при первой встрече с политикой, моложе объекта, при переустановке
//     (новый uid) и при правке на месте (новое поколение) — с pendingSince, а
//     по истечении срока — текущего поколения: текущий spec мог быть записан
//     без неё либо при другой её версии, и гарантию даёт только следующая
//     смена spec;
//   - по аннотации rewitness (ставит только платформа, сверив spec) —
//     поколения 0, но лишь когда все политики уже записаны в силе и стоят
//     теми же, а значение аннотации новое против учтённого при той записи:
//     значит, оно поставлено после неё, при исполнявшихся политиках, и
//     подлинно. Значение, стоявшее раньше, учитывается без исполнения.
//
// Проход, нашедший гарантию, подтверждает её для текущего поколения spec и
// значения created-by (ConfirmedGeneration, ConfirmedCreatedBy). Правка
// политики на месте (смена values чарта) подтверждённый spec не отзывает: он
// записан при прежней версии, которая тогда исполнялась, а смены spec и
// created-by после правки подтверждение не покрывает. Переустановку, снятие
// и отказ политики подтверждение не переживает: выдачу после них заново
// подтверждает смена spec при стоящих в силе политиках либо rewitness
// платформы.
//
// Источник доверия — печать оператора (seal), а не status. Свидетельство
// лежит в status, и status держит политика status из того же перечня, но
// держит не всегда. Окно — от переустановки политики status (новый uid) до
// p.AdmissionEnforcementDelay после первой встречи оператора с новой
// версией: как и прочие политики, она до того может не исполняться; снятая
// или правленная в пропускающую не держит status вовсе. В эти окна status
// пишет любой, кому RBAC даёт accessbindings/status. Поэтому свидетельство
// читается, только если несёт печать: HMAC по uid объекта и всему его
// содержимому на ключе из Secret в namespace оператора (WitnessSeal) — ключ
// писателям CR и status недоступен.
// Свидетельство без верной печати (записанное не оператором, запись
// оператора о другом объекте, ключ сменён) читается как его отсутствие:
// гарантию тогда держат только политики старше объекта, отказ —
// fail-closed. Каждое записанное свидетельство несёт печать.
//
// Записи политик, не названных в перечне, не трогаются: смена состава перечня
// не переписывает свидетельство прочих политик. Запись снятой политики
// снимается — её uid не вернётся. Пустой перечень — гарантии нет вовсе, и не
// принимаются ни user/group, ни цель allInScope.
//
// Свидетельство пишется в status с проверкой resourceVersion, поэтому
// поколение в записи — то, что было у объекта, когда политики читались, а
// значение аннотации в нём — то, что стояло до записи. RecheckAfter — когда
// истекает срок ближайшей ещё не вступившей версии.
//
// Предел гарантии. (1) Правку на месте политики, старшей объекта, между
// созданием объекта и первым проходом оператора по нему (свидетельство
// пишется с первого прохода и тогда, когда выдаче гарантия не нужна либо её
// отказывает политика оператора) старшинство политики не отличает; то же —
// после того, как свидетельство снято: снять его может писатель status в
// окно политики status, а отсутствие печатью не удостоверяется. (2) Срок
// вступления в силу держит, только пока он не короче настоящего отставания
// каждого экземпляра kube-apiserver и расхождения часов реплик оператора при
// смене лидера. (3) Печать держит, пока ключ знает один оператор: кто читает
// Secret ключа, тот печать подделывает. Прежнюю запись оператора о том же
// объекте, возвращённую в status в окно политики status, печать от нынешней
// не отличает; но в такое окно стоящая версия политики status отличается от
// записанной там (переустановка, правка) либо не отказывает, и прежняя запись
// доказывает не больше, чем доказывала.
// (4) Политика судится по устройству (наличие, отказ, охват), а не по
// содержанию выражений.
func CheckAdmissionGuarantee(ctx context.Context, c client.Reader, p config.Policy, seal *WitnessSeal, ab *iamv1alpha1.AccessBinding, now time.Time) (Guarantee, error) {
	names := p.AdmissionGuard
	if len(names) == 0 {
		return Guarantee{Violation: lost("user and group subjects and an allInScope target need the admission guarantee of annotation %s, and the operator configuration names no admission policy (policy.admissionGuard)", iamv1alpha1.AnnotationCreatedBy)}, nil
	}
	if seal == nil {
		return Guarantee{}, errors.New("admission witness seal is not configured")
	}
	createdBy := ab.Annotations[iamv1alpha1.AnnotationCreatedBy]
	w := ab.Status.AdmissionWitness
	distrusted := w != nil && !seal.verify(ab.UID, w)
	if w == nil || distrusted {
		w = &iamv1alpha1.AdmissionWitness{}
	}
	accounted, confirmedGen, confirmedBy := w.RewitnessNonce, w.ConfirmedGeneration, w.ConfirmedCreatedBy
	sw := &sweep{now: now, created: ab.CreationTimestamp.Time, delay: p.AdmissionEnforcementDelay.Duration, gen: ab.Generation, inForce: true}
	// bad — политика не на месте либо не отказывает: её не исправит ни
	// свидетельство, ни аннотация; late — политика стоит, но не доказано, что
	// исполнялась при последней смене spec.
	var bad, late *Violation
	next := make([]iamv1alpha1.AdmissionPolicyUIDs, 0, len(w.Policies)+len(names))
	for _, rec := range w.Policies {
		if !slices.Contains(names, rec.Name) {
			next = append(next, rec)
		}
	}
	for _, name := range names {
		vap, bnd, v, err := readPolicy(ctx, c, name)
		if err != nil {
			return Guarantee{}, err
		}
		if v != nil && bad == nil {
			bad = v
		}
		if vap == nil {
			sw.inForce = false
			continue
		}
		prev, seen := recordOf(w.Policies, name)
		live, why := sw.judge(name, vap, bnd, prev, seen)
		if why != nil && late == nil {
			late = why
		}
		next = append(next, live)
	}
	g := Guarantee{RecheckAfter: sw.recheck}
	if nonce := ab.Annotations[iamv1alpha1.AnnotationRewitness]; nonce != accounted {
		g.Rewitness = nonce
		if nonce != "" && sw.inForce && bad == nil {
			// Все политики записаны прежде в силе и стоят теми же, значение
			// новое против учтённого при записи: поставлено после неё, при них.
			g.Rewitnessed, late = true, nil
			for i := range next {
				if slices.Contains(names, next[i].Name) {
					next[i].Generation = 0
				}
			}
		}
		accounted = nonce
	}
	// Подтверждение не переживает переустановки, снятия и отказа политики;
	// правку на месте переживает — для того же spec и того же created-by.
	if sw.reinstalled || bad != nil {
		confirmedGen, confirmedBy = 0, ""
	}
	if late != nil && confirmedGen != 0 && confirmedGen == sw.gen && confirmedBy == createdBy {
		late = nil
	}
	if bad == nil && late == nil {
		confirmedGen, confirmedBy = sw.gen, createdBy
	}
	if len(next) > 0 || accounted != "" || confirmedGen != 0 {
		g.Witness = &iamv1alpha1.AdmissionWitness{Policies: next, RewitnessNonce: accounted,
			ConfirmedGeneration: confirmedGen, ConfirmedCreatedBy: confirmedBy}
		g.Witness.Seal = seal.sign(ab.UID, g.Witness)
	}
	g.Violation = bad
	if g.Violation == nil {
		g.Violation = late
	}
	if distrusted && g.Violation != nil {
		g.Violation.Message += "; status.admissionWitness carries no valid seal of this operator and was read as absent"
	}
	return g, nil
}

// sweep — состояние одной сверки гарантии по всем политикам перечня.
type sweep struct {
	now, created time.Time
	delay        time.Duration
	// gen — поколение spec объекта.
	gen int64
	// inForce — каждая политика уже записана прежним проходом в силе и стоит
	// той же версией; reinstalled — увиденная политика переустановлена.
	inForce, reinstalled bool
	// recheck — через сколько вступает в силу ближайшая увиденная версия.
	recheck time.Duration
}

// wait учитывает версию, увиденную в since: она вступает в силу через delay.
func (s *sweep) wait(since time.Time) {
	if d := since.Add(s.delay).Sub(s.now); d > 0 && (s.recheck == 0 || d < s.recheck) {
		s.recheck = d
	}
}

// judge — запись о стоящей политике name (vap, bnd) по прежней записи prev
// (seen — она есть) и отказ, если запись не доказывает текущий spec.
func (s *sweep) judge(name string, vap *admissionv1.ValidatingAdmissionPolicy, bnd *admissionv1.ValidatingAdmissionPolicyBinding,
	prev iamv1alpha1.AdmissionPolicyUIDs, seen bool) (iamv1alpha1.AdmissionPolicyUIDs, *Violation) {
	live := iamv1alpha1.AdmissionPolicyUIDs{Name: name, PolicyUID: vap.UID, PolicyGeneration: vap.Generation,
		BindingUID: bnd.UID, BindingGeneration: bnd.Generation, Generation: s.gen}
	seenNow := sightMark(s.now)
	switch {
	case seen && sameVersion(prev, live) && prev.PendingSince != nil:
		s.inForce = false
		if since := prev.PendingSince.Time; s.now.Before(since.Add(s.delay)) {
			// Ещё не в силе: запись не доказывает и текущий spec.
			live.PendingSince = prev.PendingSince
			s.wait(since)
			return live, notInForce(name, since, s.delay, s.gen)
		}
		// В силе: текущий spec прочитан до этого прохода, запись докажет его
		// следующие смены.
		return live, lateFor(name, s.gen)
	case seen && sameVersion(prev, live):
		live.Generation = prev.Generation
		if prev.Generation >= s.gen {
			return live, lateFor(name, s.gen)
		}
		return live, nil
	case seen:
		s.inForce = false
		s.reinstalled = s.reinstalled || prev.PolicyUID != live.PolicyUID || prev.BindingUID != live.BindingUID
		live.PendingSince = &seenNow
		s.wait(seenNow.Time)
		return live, changedSince(prev, live, s.gen)
	}
	s.inForce = false
	var why *Violation
	switch {
	case !predates(vap.CreationTimestamp.Time, s.created, s.delay):
		why = lost("admission policy %s was installed after this object was created, or less than policy.admissionEnforcementDelay (%s) before it, and the operator had not seen it in force before the last spec change (generation %d)", name, s.delay, s.gen)
	case !predates(bnd.CreationTimestamp.Time, s.created, s.delay):
		why = lost("admission policy binding %s was installed after this object was created, or less than policy.admissionEnforcementDelay (%s) before it, and the operator had not seen it in force before the last spec change (generation %d)", name, s.delay, s.gen)
	default:
		// Старше объекта на срок вступления в силу: исполнялась при любой
		// его записи.
		live.Generation = 0
		return live, nil
	}
	live.PendingSince = &seenNow
	s.wait(seenNow.Time)
	return live, why
}

// sightMark — отметка первой встречи с версией политики в момент now. k8s
// хранит время в status с точностью до секунды и доли отбрасывает: отметка
// округляется вверх, чтобы срок вступления в силу, отсчитанный от прочитанной
// обратно отметки, не начинался раньше настоящей встречи.
func sightMark(now time.Time) metav1.Time {
	t := now.Truncate(time.Second)
	if t.Before(now) {
		t = t.Add(time.Second)
	}
	return metav1.NewTime(t)
}

// predates — создан ли объект с отметкой policy раньше объекта с отметкой
// object настолько, что исполнялся уже при его создании: на срок вступления в
// силу и секунду точности отметок времени.
func predates(policy, object time.Time, delay time.Duration) bool {
	return object.Sub(policy) >= delay+time.Second
}

// lateFor — политика name стоит, но не доказано, что исполнялась при
// последней смене spec (поколение gen).
func lateFor(name string, gen int64) *Violation {
	return lost("admission policy %s was installed or changed after this object was created and the operator had not seen it in force before the last spec change (generation %d)", name, gen)
}

// notInForce — версия политики name увидена в since, срок вступления в силу
// delay ещё не истёк.
func notInForce(name string, since time.Time, delay time.Duration, gen int64) *Violation {
	return lost("admission policy %s was seen at %s and may not be enforced by the kube-apiserver until policy.admissionEnforcementDelay (%s) passes: the current spec (generation %d) is not proven by it",
		name, since.UTC().Format(time.RFC3339), delay, gen)
}

// readPolicy читает политику name и её привязку. Нет одной из них — обе nil и
// отказ; стоят, но не отказывают или сужены — обе и отказ.
func readPolicy(ctx context.Context, c client.Reader, name string) (*admissionv1.ValidatingAdmissionPolicy, *admissionv1.ValidatingAdmissionPolicyBinding, *Violation, error) {
	vap := &admissionv1.ValidatingAdmissionPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, vap); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, lost("admission policy %s is absent: user and group subjects and an allInScope target are not accepted without it", name), nil
		}
		return nil, nil, nil, fmt.Errorf("admission policy %s: %w", name, err)
	}
	bnd := &admissionv1.ValidatingAdmissionPolicyBinding{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, bnd); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, lost("admission policy binding %s is absent: user and group subjects and an allInScope target are not accepted without it", name), nil
		}
		return nil, nil, nil, fmt.Errorf("admission policy binding %s: %w", name, err)
	}
	var v *Violation
	switch {
	case vap.Spec.FailurePolicy != nil && *vap.Spec.FailurePolicy != admissionv1.Fail:
		v = lost("admission policy %s has failurePolicy %s, not Fail", name, *vap.Spec.FailurePolicy)
	case bnd.Spec.PolicyName != name:
		v = lost("admission policy binding %s binds policy %q, not %q", name, bnd.Spec.PolicyName, name)
	case !slices.Contains(bnd.Spec.ValidationActions, admissionv1.Deny):
		v = lost("admission policy binding %s does not deny (validationActions %v)", name, bnd.Spec.ValidationActions)
	case bnd.Spec.ParamRef != nil || narrows(bnd.Spec.MatchResources):
		v = lost("admission policy binding %s is narrowed by parameters or match resources", name)
	}
	return vap, bnd, v, nil
}

// lost — отказ гарантии допуска.
func lost(format string, a ...any) *Violation {
	v := forbidden(format, a...)
	v.Admission = true
	return v
}

// recordOf — запись свидетельства о политике name.
func recordOf(w []iamv1alpha1.AdmissionPolicyUIDs, name string) (iamv1alpha1.AdmissionPolicyUIDs, bool) {
	for _, p := range w {
		if p.Name == name {
			return p, true
		}
	}
	return iamv1alpha1.AdmissionPolicyUIDs{}, false
}

// sameVersion — та ли это политика и привязка (uid) и не правлены ли они с
// записи (поколение). Пустой uid не свидетельствует ни о чём.
func sameVersion(rec, live iamv1alpha1.AdmissionPolicyUIDs) bool {
	return rec.PolicyUID != "" && rec.PolicyUID == live.PolicyUID && rec.PolicyGeneration == live.PolicyGeneration &&
		rec.BindingUID != "" && rec.BindingUID == live.BindingUID && rec.BindingGeneration == live.BindingGeneration
}

// changedSince — чем политика, записанная rec, отличается от стоящей live.
func changedSince(rec, live iamv1alpha1.AdmissionPolicyUIDs, gen int64) *Violation {
	const tail = "since the operator saw it: the current spec (generation %d) may have been written without it"
	switch {
	case rec.PolicyUID != live.PolicyUID:
		return lost("admission policy %s was reinstalled "+tail, rec.Name, gen)
	case rec.BindingUID != live.BindingUID:
		return lost("admission policy binding %s was reinstalled "+tail, rec.Name, gen)
	case rec.PolicyGeneration != live.PolicyGeneration:
		return lost("admission policy %s was changed in place (generation %d, seen %d) "+tail, rec.Name, live.PolicyGeneration, rec.PolicyGeneration, gen)
	default:
		return lost("admission policy binding %s was changed in place (generation %d, seen %d) "+tail, rec.Name, live.BindingGeneration, rec.BindingGeneration, gen)
	}
}

// narrows — сужает ли выборка привязки охват политики. Пустые селекторы,
// которыми сервер умолчанием заполняет выборку, охвата не сужают.
func narrows(m *admissionv1.MatchResources) bool {
	if m == nil {
		return false
	}
	if m.NamespaceSelector != nil && (len(m.NamespaceSelector.MatchLabels) > 0 || len(m.NamespaceSelector.MatchExpressions) > 0) {
		return true
	}
	if m.ObjectSelector != nil && (len(m.ObjectSelector.MatchLabels) > 0 || len(m.ObjectSelector.MatchExpressions) > 0) {
		return true
	}
	return len(m.ResourceRules) > 0 || len(m.ExcludeResourceRules) > 0
}
