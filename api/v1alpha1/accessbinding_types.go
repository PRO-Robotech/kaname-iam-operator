// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LocalServiceAccountRef — ссылка на CR ServiceAccount в том же namespace.
type LocalServiceAccountRef struct {
	// Name — имя CR ServiceAccount.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// PrincipalRef — субъект kaname по id (пользователь или группа).
type PrincipalRef struct {
	// ID — id субъекта в kaname.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	ID string `json:"id"`
}

// SystemClassName — системный класс субъектов kaname.
// +kubebuilder:validation:Enum=anonymous;authenticated
type SystemClassName string

// SystemClassRef — системный класс субъектов.
type SystemClassRef struct {
	// Name — имя класса.
	Name SystemClassName `json:"name"`
}

// Subject — ровно один субъект выдачи.
// +kubebuilder:validation:XValidation:rule="[has(self.serviceAccountRef), has(self.user), has(self.group), has(self.systemClass)].filter(x, x).size() == 1",message="exactly one of serviceAccountRef, user, group, systemClass must be set"
type Subject struct {
	// ServiceAccountRef — CR ServiceAccount этого namespace; субъект — его status.id.
	// +optional
	ServiceAccountRef *LocalServiceAccountRef `json:"serviceAccountRef,omitempty"`
	// User — пользователь kaname. Допускается только от принципалов платформы.
	// +optional
	User *PrincipalRef `json:"user,omitempty"`
	// Group — группа kaname. Допускается только от принципалов платформы.
	// +optional
	Group *PrincipalRef `json:"group,omitempty"`
	// SystemClass — системный класс. Допускается только с ролями системных
	// классов из конфигурации оператора.
	// +optional
	SystemClass *SystemClassRef `json:"systemClass,omitempty"`
}

// RoleRef — роль kaname по имени.
type RoleRef struct {
	// Name — имя роли (например registry.pusher).
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9._-]{0,127}$`
	// +kubebuilder:validation:MaxLength=128
	Name string `json:"name"`
}

// ScopeType — тип области выдачи.
// +kubebuilder:validation:Enum=iam.project;iam.account
type ScopeType string

const (
	// ScopeProject — проект; id — из аннотации namespace project-id.
	ScopeProject ScopeType = "iam.project"
	// ScopeAccount — аккаунт; id — из аннотации namespace account-id.
	ScopeAccount ScopeType = "iam.account"
)

// Scope — область выдачи. Её id берётся из аннотаций namespace, своего id в
// spec нет: арендатор не называет чужую область.
type Scope struct {
	// Type — тип области.
	// +kubebuilder:default=iam.project
	// +optional
	Type ScopeType `json:"type,omitempty"`
}

// ResourceRef — объект-цель выдачи.
type ResourceRef struct {
	// Type — тип объекта kaname.
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9_.]{0,31}$`
	// +kubebuilder:validation:MaxLength=32
	Type string `json:"type"`
	// ID — id объекта.
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}$`
	// +kubebuilder:validation:MaxLength=64
	ID string `json:"id"`
}

// Target — цель выдачи: перечень объектов.
type Target struct {
	// Resources — объекты-цели. Каждый обязан разрешиться в объект ЭТОГО
	// namespace по правилам конфигурации оператора.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	Resources []ResourceRef `json:"resources"`
}

// AccessBindingSpec — желаемая выдача kaname.
type AccessBindingSpec struct {
	// Subjects — субъекты выдачи. Неизменяемы.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="subjects are immutable"
	// +listType=atomic
	Subjects []Subject `json:"subjects"`
	// RoleRef — роль. Неизменяема.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="roleRef is immutable"
	RoleRef RoleRef `json:"roleRef"`
	// Scope — область. Неизменяема.
	// +kubebuilder:default={}
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="scope is immutable"
	// +optional
	Scope Scope `json:"scope,omitempty"`
	// Target — цель. В kaname цель выдачи неизменяема, поэтому смена цели
	// здесь означает новую выдачу: оператор заводит выдачу с новой целью и
	// только после этого отзывает прежнюю.
	Target Target `json:"target"`
	// ExpiresAt — срок выдачи. Смена — тоже новая выдача.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
	// Labels — метки выдачи в kaname. Префикс k8s.in-cloud.io/ занят оператором.
	// +kubebuilder:validation:MaxProperties=32
	// +kubebuilder:validation:XValidation:rule="self.all(k, !k.startsWith('k8s.in-cloud.io/'))",message="label prefix k8s.in-cloud.io/ is reserved for the operator"
	// +kubebuilder:validation:XValidation:rule="self.all(k, k.matches('^[a-z][-_./@a-z0-9]{0,62}$'))",message="label keys must match ^[a-z][-_./@a-z0-9]{0,62}$"
	// +kubebuilder:validation:XValidation:rule="self.all(k, size(self[k]) <= 63)",message="label values must be at most 63 characters"
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// DeletionPolicy — что делать с выдачей kaname при удалении CR.
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// ResolvedSubject — субъект в терминах kaname.
type ResolvedSubject struct {
	// Type — SUBJECT_TYPE_* kaname.
	Type string `json:"type"`
	// ID — id субъекта.
	ID string `json:"id"`
}

// ResolvedBinding — выдача в терминах kaname, как её завёл оператор.
type ResolvedBinding struct {
	// Subjects — субъекты.
	// +listType=atomic
	// +optional
	Subjects []ResolvedSubject `json:"subjects,omitempty"`
	// RoleID — id роли.
	// +optional
	RoleID string `json:"roleId,omitempty"`
	// ScopeType — тип области.
	// +optional
	ScopeType string `json:"scopeType,omitempty"`
	// ScopeID — id области.
	// +optional
	ScopeID string `json:"scopeId,omitempty"`
	// AccountID — аккаунт области: по нему ищется своя выдача.
	// +optional
	AccountID string `json:"accountId,omitempty"`
}

// ReplacedBinding — прежняя выдача, ждущая отзыва после заведения новой.
type ReplacedBinding struct {
	// ID — id прежней выдачи.
	ID string `json:"id"`
}

// AccessBindingStatus — наблюдаемое состояние выдачи.
type AccessBindingStatus struct {
	// ObservedGeneration — поколение spec, по которому выставлены условия.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// ID — id действующей выдачи в kaname.
	// +optional
	ID string `json:"id,omitempty"`
	// Resolved — выдача в терминах kaname.
	// +optional
	Resolved *ResolvedBinding `json:"resolved,omitempty"`
	// BindingHash — отпечаток (субъекты, роль, область, цель, срок) действующей
	// выдачи: расхождение с желаемым означает новую выдачу.
	// +optional
	BindingHash string `json:"bindingHash,omitempty"`
	// Replaced — прежняя выдача, ждущая отзыва.
	// +optional
	Replaced *ReplacedBinding `json:"replaced,omitempty"`
	// PendingOperation — незавершённая операция kaname.
	// +optional
	PendingOperation *PendingOperation `json:"pendingOperation,omitempty"`
	// PendingHash — отпечаток выдачи, которую заводит PendingOperation Create.
	// +optional
	PendingHash string `json:"pendingHash,omitempty"`
	// ResyncNonce — значение аннотации resync-drift, по которому восстановление
	// уже выполнено.
	// +optional
	ResyncNonce string `json:"resyncNonce,omitempty"`
	// Conditions — Ready, Synced, Conflict, SubjectPending, Drifted.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AccessBinding — выдача роли kaname IAM субъектам на цели в области.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=kab,categories=kaname-iam
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=`.spec.roleRef.name`
// +kubebuilder:printcolumn:name="ID",type=string,JSONPath=`.status.id`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type AccessBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AccessBindingSpec   `json:"spec"`
	Status AccessBindingStatus `json:"status,omitempty"`
}

// AccessBindingList — список AccessBinding.
// +kubebuilder:object:root=true
type AccessBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AccessBinding{}, &AccessBindingList{})
}

// EffectiveDeletionPolicy — политика удаления с умолчанием Delete.
func (s *AccessBindingSpec) EffectiveDeletionPolicy() DeletionPolicy {
	if s.DeletionPolicy == "" {
		return DeletionPolicyDelete
	}
	return s.DeletionPolicy
}

// EffectiveScopeType — тип области с умолчанием iam.project.
func (s *AccessBindingSpec) EffectiveScopeType() ScopeType {
	if s.Scope.Type == "" {
		return ScopeProject
	}
	return s.Scope.Type
}
