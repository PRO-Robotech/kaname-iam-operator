// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"slices"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
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

// CheckAdmissionGuarantee подтверждает, что подлинность аннотации created-by
// и субъектов user/group объекта ab держит допуск: каждая политика из names
// (ValidatingAdmissionPolicy) и её привязка с тем же именем стоят в кластере,
// отказывают (failurePolicy Fail, validationActions Deny), не сужены
// параметрами и выборками и стояли уже тогда, когда записан текущий spec
// объекта (его последняя смена, поколение ab.Generation).
//
// Без этого аннотация — слово клиента: тот, кто вправе писать AccessBinding,
// пишет в created-by имя принципала платформы, а смену spec, пока политик
// нет, не судит никто. Стояние политики при записи spec доказывается одним из
// двух фактов:
//   - политика старше самого объекта: объект k8s с тем же uid существует
//     непрерывно, значит, стоял при любой записи этого объекта;
//   - оператор уже видел политику с тем же uid при прежнем поколении spec
//     (ab.Status.AdmissionWitness): та же непрерывность от момента, когда
//     spec был ещё прежним, то есть до его смены.
//
// Ни одного — гарантии нет: spec, записанный, пока политики не было (снята,
// переустановлена), отвергается и после её возвращения, до следующей смены
// spec при уже увиденной политике. Пустой names — гарантии нет вовсе, и не
// принимаются ни user/group, ни цель allInScope.
//
// Второй результат — свидетельство, которое объекту следует хранить: прежнее,
// пока его uid совпадают с увиденными сейчас (оно доказывает и следующие
// смены spec), иначе увиденное сейчас при текущем поколении; nil — политики
// не на месте, и свидетельствовать нечего. Свидетельство пишется в status с
// проверкой resourceVersion, поэтому поколение в нём — то, что было у
// объекта, когда политики читались.
//
// Предел гарантии: правку политики на месте (сужение matchConstraints,
// подмена выражения) проверка не видит; её делает только тот, кому доступна
// запись ValidatingAdmissionPolicy, то есть администратор кластера.
func CheckAdmissionGuarantee(ctx context.Context, c client.Reader, names []string, ab *iamv1alpha1.AccessBinding) (*Violation, *iamv1alpha1.AdmissionWitness, error) {
	if len(names) == 0 {
		return forbidden("user and group subjects and an allInScope target need the admission guarantee of annotation %s, and the operator configuration names no admission policy (policy.admissionGuard)", iamv1alpha1.AnnotationCreatedBy), nil, nil
	}
	created, gen, old := ab.CreationTimestamp.Time, ab.Generation, ab.Status.AdmissionWitness
	seen := make([]iamv1alpha1.AdmissionPolicyUIDs, 0, len(names))
	var late *Violation
	for _, name := range names {
		vap := &admissionv1.ValidatingAdmissionPolicy{}
		if err := c.Get(ctx, client.ObjectKey{Name: name}, vap); err != nil {
			if apierrors.IsNotFound(err) {
				return forbidden("admission policy %s is absent: user and group subjects and an allInScope target are not accepted without it", name), nil, nil
			}
			return nil, nil, fmt.Errorf("admission policy %s: %w", name, err)
		}
		if fp := vap.Spec.FailurePolicy; fp != nil && *fp != admissionv1.Fail {
			return forbidden("admission policy %s has failurePolicy %s, not Fail", name, *fp), nil, nil
		}
		bnd := &admissionv1.ValidatingAdmissionPolicyBinding{}
		if err := c.Get(ctx, client.ObjectKey{Name: name}, bnd); err != nil {
			if apierrors.IsNotFound(err) {
				return forbidden("admission policy binding %s is absent: user and group subjects and an allInScope target are not accepted without it", name), nil, nil
			}
			return nil, nil, fmt.Errorf("admission policy binding %s: %w", name, err)
		}
		switch {
		case bnd.Spec.PolicyName != name:
			return forbidden("admission policy binding %s binds policy %q, not %q", name, bnd.Spec.PolicyName, name), nil, nil
		case !slices.Contains(bnd.Spec.ValidationActions, admissionv1.Deny):
			return forbidden("admission policy binding %s does not deny (validationActions %v)", name, bnd.Spec.ValidationActions), nil, nil
		case bnd.Spec.ParamRef != nil || narrows(bnd.Spec.MatchResources):
			return forbidden("admission policy binding %s is narrowed by parameters or match resources", name), nil, nil
		}
		if at := witnessed(old, gen, name); late == nil {
			switch {
			case vap.CreationTimestamp.After(created) && !sameUID(at.PolicyUID, vap.UID):
				late = forbidden("admission policy %s was installed after this object was created and the operator had not seen it before the last spec change (generation %d)", name, gen)
			case bnd.CreationTimestamp.After(created) && !sameUID(at.BindingUID, bnd.UID):
				late = forbidden("admission policy binding %s was installed after this object was created and the operator had not seen it before the last spec change (generation %d)", name, gen)
			}
		}
		seen = append(seen, iamv1alpha1.AdmissionPolicyUIDs{Name: name, PolicyUID: vap.UID, BindingUID: bnd.UID})
	}
	next := old
	if !sameWitness(old, gen, seen) {
		next = &iamv1alpha1.AdmissionWitness{Generation: gen, Policies: seen}
	}
	return late, next, nil
}

// witnessed — что о политике name свидетельствует w, если w увидено при
// поколении spec раньше gen; иначе пусто.
func witnessed(w *iamv1alpha1.AdmissionWitness, gen int64, name string) iamv1alpha1.AdmissionPolicyUIDs {
	if w == nil || w.Generation >= gen {
		return iamv1alpha1.AdmissionPolicyUIDs{}
	}
	for _, p := range w.Policies {
		if p.Name == name {
			return p
		}
	}
	return iamv1alpha1.AdmissionPolicyUIDs{}
}

// sameUID — тот ли это объект; пустой uid не свидетельствует ни о чём.
func sameUID(recorded, live types.UID) bool { return recorded != "" && recorded == live }

// sameWitness — свидетельствует ли w ровно о политиках seen и увидено ли не
// позже поколения gen: тогда оно сохраняется как есть.
func sameWitness(w *iamv1alpha1.AdmissionWitness, gen int64, seen []iamv1alpha1.AdmissionPolicyUIDs) bool {
	if w == nil || w.Generation > gen || len(w.Policies) != len(seen) {
		return false
	}
	for _, s := range seen {
		if !slices.Contains(w.Policies, s) {
			return false
		}
	}
	return true
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
