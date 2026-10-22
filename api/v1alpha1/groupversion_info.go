// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package v1alpha1 — схема API группы iam.kaname.in-cloud.io/v1alpha1:
// ServiceAccount и AccessBinding, отражающие учётку и выдачу kaname IAM.
// +kubebuilder:object:generate=true
// +groupName=iam.kaname.in-cloud.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion — группа и версия объектов этого пакета.
	GroupVersion = schema.GroupVersion{Group: "iam.kaname.in-cloud.io", Version: "v1alpha1"}

	// SchemeBuilder регистрирует типы пакета в схеме.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme добавляет типы пакета в схему.
	AddToScheme = SchemeBuilder.AddToScheme
)
