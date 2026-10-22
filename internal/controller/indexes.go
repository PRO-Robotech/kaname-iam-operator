// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

// indexBindingSA — индекс AccessBinding по именам CR ServiceAccount субъектов.
const indexBindingSA = "spec.subjects.serviceAccountRef.name"

// SetupIndexes регистрирует индексы полей.
func SetupIndexes(ctx context.Context, mgr ctrl.Manager) error {
	return mgr.GetFieldIndexer().IndexField(ctx, &iamv1alpha1.AccessBinding{}, indexBindingSA, func(o client.Object) []string {
		ab, ok := o.(*iamv1alpha1.AccessBinding)
		if !ok {
			return nil
		}
		return referencedServiceAccounts(ab)
	})
}

// referencedServiceAccounts — имена CR ServiceAccount, на которые ссылается выдача.
func referencedServiceAccounts(ab *iamv1alpha1.AccessBinding) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ab.Spec.Subjects {
		if s.ServiceAccountRef != nil && !seen[s.ServiceAccountRef.Name] {
			seen[s.ServiceAccountRef.Name] = true
			out = append(out, s.ServiceAccountRef.Name)
		}
	}
	return out
}
