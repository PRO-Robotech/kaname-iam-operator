// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package policy — ограждение выдач на стороне оператора.
//
// Роль из перечня, роль системного класса и принадлежность цели namespace CR
// оператор проверяет сам, по своей конфигурации и объектам кластера: эти три
// ограды держатся и тогда, когда допуск (ValidatingAdmissionPolicy) обойдён
// или снят.
//
// Субъект user или group и цель «вся область» (allInScope) допустимы только
// от принципала платформы, а автора CR оператор знает лишь из аннотации
// created-by — её пишет клиент, и подлинность ей даёт только допуск. Подлинного признака автора в самом
// объекте k8s нет: managedFields тоже пишет клиент (имя менеджера полей —
// параметр запроса). Поэтому эта ограда честно зависит от допуска, и
// оператор сверяет саму гарантию: политики допуска стоят, отказывают и
// стояли, когда записан текущий spec CR (CheckAdmissionGuarantee). Нет
// гарантии — нет ни выдачи user/group, ни выдачи на всю область.
//
// Ограда судит выдачу на каждой реконсиляции, а не только при заведении:
// выдачу, которую сужение конфигурации (перечень ролей, принципалов
// платформы) либо потеря гарантии сделали недопустимой, оператор отзывает в
// kaname и вновь не заводит, пока она снова не станет допустимой.
package policy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
)

// Violation — выдача запрещена конфигурацией.
type Violation struct {
	// Reason — причина условия (Forbidden либо TargetUnresolved).
	Reason string
	// Message — что именно нарушено.
	Message string
}

func (v *Violation) Error() string { return v.Reason + ": " + v.Message }

// Evaluate проверяет роль и субъектов выдачи по конфигурации. nil — разрешено.
func Evaluate(p config.Policy, ab *iamv1alpha1.AccessBinding) *Violation {
	role := ab.Spec.RoleRef.Name
	if !slices.Contains(p.AllowedRoles, role) {
		return forbidden("role %q is not in the operator's allowed roles", role)
	}
	creator := ab.Annotations[iamv1alpha1.AnnotationCreatedBy]
	whole := ab.Spec.Target.AllInScope != nil
	if whole == (len(ab.Spec.Target.Resources) > 0) {
		return forbidden("target must set exactly one of resources, allInScope")
	}
	if whole {
		// Вся область — каскад на все объекты аккаунта либо проекта, включая
		// заведённые позже: её ставит только платформа.
		if !slices.Contains(p.PlatformPrincipals, creator) {
			return forbidden("target: allInScope is accepted only from a platform principal (created by %q)", creator)
		}
		if st := ab.Spec.EffectiveScopeType(); st != iamv1alpha1.ScopeProject && st != iamv1alpha1.ScopeAccount {
			return forbidden("target: allInScope is accepted only with scope iam.project or iam.account, not %q", st)
		}
	}
	for i, s := range ab.Spec.Subjects {
		set := 0
		for _, present := range []bool{s.ServiceAccountRef != nil, s.User != nil, s.Group != nil, s.SystemClass != nil} {
			if present {
				set++
			}
		}
		if set != 1 {
			return forbidden("subjects[%d] must set exactly one of serviceAccountRef, user, group, systemClass", i)
		}
		switch {
		case s.SystemClass != nil && !slices.Contains(p.SystemClassRoles, role):
			return forbidden("subjects[%d]: a system class may be bound only to roles %v, not %q", i, p.SystemClassRoles, role)
		case s.SystemClass != nil && whole:
			// kaname сам отвергает такую выдачу; оператор не зовёт его заведомо.
			return forbidden("subjects[%d]: a system class is never granted allInScope; name its objects in target.resources", i)
		case (s.User != nil || s.Group != nil) && !slices.Contains(p.PlatformPrincipals, creator):
			return forbidden("subjects[%d]: a user or group subject is accepted only from a platform principal (created by %q)", i, creator)
		}
	}
	for i, t := range ab.Spec.Target.Resources {
		if _, ok := p.TargetResolvers[t.Type]; !ok {
			return forbidden("target.resources[%d]: type %q has no resolver in the operator configuration", i, t.Type)
		}
	}
	return nil
}

func forbidden(format string, a ...any) *Violation {
	return &Violation{Reason: iamv1alpha1.ReasonForbidden, Message: fmt.Sprintf(format, a...)}
}

// ResolveTargets подтверждает каждую цель объектом namespace CR. Объект не
// найден либо не готов — Reason TargetUnresolved (временно); объект чужого
// namespace либо тип цели без правила — Reason Forbidden.
func ResolveTargets(ctx context.Context, c client.Reader, mapper RESTMapper, p config.Policy, namespace string, targets []iamv1alpha1.ResourceRef) (*Violation, error) {
	for i, t := range targets {
		r, ok := p.TargetResolvers[t.Type]
		if !ok {
			return forbidden("target.resources[%d]: type %q has no resolver in the operator configuration", i, t.Type), nil
		}
		gvr := schema.GroupVersionResource{Group: r.Group, Version: r.Version, Resource: r.Resource}
		gvk, err := mapper.KindFor(gvr)
		if err != nil {
			return nil, fmt.Errorf("target %s: resolve kind of %s: %w", t.Type, gvr, err)
		}
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(gvk)
		key := client.ObjectKey{Name: t.ID}
		if r.Namespaced {
			key.Namespace = namespace
		}
		if err := c.Get(ctx, key, obj); err != nil {
			if apierrors.IsNotFound(err) {
				return &Violation{Reason: iamv1alpha1.ReasonTargetUnresolved,
					Message: fmt.Sprintf("target %s:%s: %s %q not found", t.Type, t.ID, gvk.Kind, t.ID)}, nil
			}
			return nil, fmt.Errorf("target %s:%s: %w", t.Type, t.ID, err)
		}
		for _, m := range r.Match {
			got, found, err := unstructured.NestedString(obj.Object, strings.Split(m.Path, ".")...)
			if err != nil {
				found = false
			}
			if m.Equals == config.NamespacePlaceholder {
				// Принадлежность цели namespace CR: расхождение — чужая цель,
				// а не «ещё не готово».
				if !found || got != namespace {
					return forbidden("target %s:%s belongs to namespace %q, not %q", t.Type, t.ID, got, namespace), nil
				}
				continue
			}
			if !found || got != m.Equals {
				return &Violation{Reason: iamv1alpha1.ReasonTargetUnresolved,
					Message: fmt.Sprintf("target %s:%s: %s is %q, want %q", t.Type, t.ID, m.Path, got, m.Equals)}, nil
			}
		}
	}
	return nil, nil
}

// RESTMapper — то из RESTMapper, что нужно разрешению целей.
type RESTMapper interface {
	KindFor(resource schema.GroupVersionResource) (schema.GroupVersionKind, error)
}
