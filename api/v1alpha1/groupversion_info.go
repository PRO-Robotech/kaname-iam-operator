// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package v1alpha1 — схема API группы iam.kaname.in-cloud.io/v1alpha1:
// IAMServiceAccount и IAMAccessBinding, отражающие учётку и выдачу kaname IAM.
// +kubebuilder:object:generate=true
// +groupName=iam.kaname.in-cloud.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion — группа и версия объектов этого пакета.
	GroupVersion = schema.GroupVersion{Group: "iam.kaname.in-cloud.io", Version: "v1alpha1"}

	// SchemeBuilder регистрирует типы пакета в схеме. Пакет API зависит
	// только от apimachinery: его импортируют потребители CRD.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme добавляет типы пакета в схему.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&IAMServiceAccount{}, &IAMServiceAccountList{},
		&IAMAccessBinding{}, &IAMAccessBindingList{},
	)
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
