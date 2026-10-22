// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"slices"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
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
}

// CheckAdmissionGuarantee подтверждает, что подлинность аннотации created-by
// и субъектов user/group объекта ab держит допуск: каждая политика из names
// (ValidatingAdmissionPolicy) и её привязка с тем же именем стоят в кластере,
// отказывают (failurePolicy Fail, validationActions Deny), не сужены
// параметрами и выборками и стояли — той же версией — уже тогда, когда
// записан текущий spec объекта (его последняя смена, поколение ab.Generation).
//
// Без этого аннотация — слово клиента: тот, кто вправе писать AccessBinding,
// пишет в created-by имя принципала платформы, а смену spec, пока политик
// нет (или пока они правлены в пропускающие), не судит никто. Стояние
// политики при записи spec доказывает запись свидетельства о ней
// (ab.Status.AdmissionWitness), по одной на политику: объект k8s с тем же uid
// существует непрерывно, а metadata.generation растёт при каждой правке его
// spec, поэтому политика и привязка с записанными uid и поколениями стояли
// неизменными от записи до сейчас. Запись доказывает смены spec после
// поколения, при котором сделана; запись поколения 0 — любые. Пишется она:
//   - при первой встрече с политикой, старшей самого объекта, — поколения 0:
//     стояла при любой записи объекта;
//   - при первой встрече с политикой, моложе объекта, при переустановке
//     (новый uid) и при правке на месте (новое поколение) — текущего
//     поколения: текущий spec мог быть записан без неё либо при другой её
//     версии, и гарантию даёт только следующая смена spec;
//   - по аннотации rewitness (ставит только платформа, сверив spec) —
//     поколения 0, но лишь когда все политики уже записаны и стоят теми же,
//     а значение аннотации новое против учтённого при той записи: значит, оно
//     поставлено после неё, при этих политиках, и подлинно. Значение,
//     стоявшее раньше, чем политики увидены, учитывается без исполнения.
//
// Записи политик, не названных в names, не трогаются: смена состава перечня
// не переписывает свидетельство прочих политик. Запись снятой политики
// снимается — её uid не вернётся. Пустой names — гарантии нет вовсе, и не
// принимаются ни user/group, ни цель allInScope.
//
// Свидетельство пишется в status с проверкой resourceVersion, поэтому
// поколение в записи — то, что было у объекта, когда политики читались, а
// значение аннотации в нём — то, что стояло до записи.
//
// Предел гарантии: правку политики между созданием объекта и первой встречей
// оператора с ней старшинство политики не отличает — окно в один проход
// реконсиляции после создания CR.
func CheckAdmissionGuarantee(ctx context.Context, c client.Reader, names []string, ab *iamv1alpha1.AccessBinding) (Guarantee, error) {
	if len(names) == 0 {
		return Guarantee{Violation: lost("user and group subjects and an allInScope target need the admission guarantee of annotation %s, and the operator configuration names no admission policy (policy.admissionGuard)", iamv1alpha1.AnnotationCreatedBy)}, nil
	}
	created, gen := ab.CreationTimestamp.Time, ab.Generation
	var old []iamv1alpha1.AdmissionPolicyUIDs
	accounted := ""
	if w := ab.Status.AdmissionWitness; w != nil {
		old, accounted = w.Policies, w.RewitnessNonce
	}
	// bad — политика не на месте либо не отказывает: её не исправит ни
	// свидетельство, ни аннотация; late — политика стоит, но не доказано, что
	// стояла при последней смене spec.
	var bad, late *Violation
	confirmed := true
	next := make([]iamv1alpha1.AdmissionPolicyUIDs, 0, len(old)+len(names))
	for _, p := range old {
		if !slices.Contains(names, p.Name) {
			next = append(next, p)
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
			confirmed = false
			continue
		}
		live := iamv1alpha1.AdmissionPolicyUIDs{Name: name, PolicyUID: vap.UID, PolicyGeneration: vap.Generation,
			BindingUID: bnd.UID, BindingGeneration: bnd.Generation, Generation: gen}
		prev, seen := recordOf(old, name)
		var why *Violation
		switch {
		case seen && sameVersion(prev, live):
			live.Generation = prev.Generation
			if prev.Generation >= gen {
				why = lost("admission policy %s was installed or changed after this object was created and the operator had not seen it before the last spec change (generation %d)", name, gen)
			}
		case seen:
			confirmed = false
			why = changedSince(prev, live, gen)
		default:
			confirmed = false
			switch {
			case vap.CreationTimestamp.After(created):
				why = lost("admission policy %s was installed after this object was created and the operator had not seen it before the last spec change (generation %d)", name, gen)
			case bnd.CreationTimestamp.After(created):
				why = lost("admission policy binding %s was installed after this object was created and the operator had not seen it before the last spec change (generation %d)", name, gen)
			default:
				// Старше объекта: стояла при любой его записи.
				live.Generation = 0
			}
		}
		if why != nil && late == nil {
			late = why
		}
		next = append(next, live)
	}
	g := Guarantee{}
	if nonce := ab.Annotations[iamv1alpha1.AnnotationRewitness]; nonce != accounted {
		g.Rewitness = nonce
		if nonce != "" && confirmed && bad == nil {
			// Все политики записаны прежде и стоят теми же, значение новое
			// против учтённого при записи: поставлено после неё, при них.
			g.Rewitnessed, late = true, nil
			for i := range next {
				if slices.Contains(names, next[i].Name) {
					next[i].Generation = 0
				}
			}
		}
		accounted = nonce
	}
	if len(next) > 0 || accounted != "" {
		g.Witness = &iamv1alpha1.AdmissionWitness{Policies: next, RewitnessNonce: accounted}
	}
	g.Violation = bad
	if g.Violation == nil {
		g.Violation = late
	}
	return g, nil
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
