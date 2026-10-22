// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"slices"
	"time"

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

// CheckAdmissionGuarantee подтверждает, что подлинность аннотации created-by
// объекта, созданного в момент created, держит допуск: каждая политика из
// names (ValidatingAdmissionPolicy) и её привязка с тем же именем стоят в
// кластере, отказывают (failurePolicy Fail, validationActions Deny), не сужены
// параметрами и выборками и существовали уже тогда, когда объект создавался.
//
// Без этого аннотация — слово клиента: тот, кто вправе создавать
// AccessBinding, пишет в created-by имя принципала платформы. Объект,
// созданный, пока политики не было (снята, переустановлена), отвергается и
// после её возвращения — подделка, прошедшая в окно, гарантией не становится.
// Пустой names — гарантии нет вовсе, и не принимаются ни user/group, ни
// цель allInScope.
//
// Предел гарантии: правку политики на месте (сужение matchConstraints,
// подмена выражения) проверка не видит; её делает только тот, кому доступна
// запись ValidatingAdmissionPolicy, то есть администратор кластера.
func CheckAdmissionGuarantee(ctx context.Context, c client.Reader, names []string, created time.Time) (*Violation, error) {
	if len(names) == 0 {
		return forbidden("user and group subjects and an allInScope target need the admission guarantee of annotation %s, and the operator configuration names no admission policy (policy.admissionGuard)", iamv1alpha1.AnnotationCreatedBy), nil
	}
	for _, name := range names {
		vap := &admissionv1.ValidatingAdmissionPolicy{}
		if err := c.Get(ctx, client.ObjectKey{Name: name}, vap); err != nil {
			if apierrors.IsNotFound(err) {
				return forbidden("admission policy %s is absent: user and group subjects and an allInScope target are not accepted without it", name), nil
			}
			return nil, fmt.Errorf("admission policy %s: %w", name, err)
		}
		if fp := vap.Spec.FailurePolicy; fp != nil && *fp != admissionv1.Fail {
			return forbidden("admission policy %s has failurePolicy %s, not Fail", name, *fp), nil
		}
		if vap.CreationTimestamp.After(created) {
			return forbidden("admission policy %s was installed after this object was created", name), nil
		}
		bnd := &admissionv1.ValidatingAdmissionPolicyBinding{}
		if err := c.Get(ctx, client.ObjectKey{Name: name}, bnd); err != nil {
			if apierrors.IsNotFound(err) {
				return forbidden("admission policy binding %s is absent: user and group subjects and an allInScope target are not accepted without it", name), nil
			}
			return nil, fmt.Errorf("admission policy binding %s: %w", name, err)
		}
		switch {
		case bnd.Spec.PolicyName != name:
			return forbidden("admission policy binding %s binds policy %q, not %q", name, bnd.Spec.PolicyName, name), nil
		case !slices.Contains(bnd.Spec.ValidationActions, admissionv1.Deny):
			return forbidden("admission policy binding %s does not deny (validationActions %v)", name, bnd.Spec.ValidationActions), nil
		case bnd.Spec.ParamRef != nil || narrows(bnd.Spec.MatchResources):
			return forbidden("admission policy binding %s is narrowed by parameters or match resources", name), nil
		case bnd.CreationTimestamp.After(created):
			return forbidden("admission policy binding %s was installed after this object was created", name), nil
		}
	}
	return nil, nil
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
