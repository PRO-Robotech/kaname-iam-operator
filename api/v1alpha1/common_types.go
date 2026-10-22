// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DeletionPolicy — что делать с объектом kaname при удалении CR.
// +kubebuilder:validation:Enum=Delete;Orphan
type DeletionPolicy string

const (
	// DeletionPolicyDelete — снять объект kaname (отозвать выдачу, отключить и
	// удалить учётку с её ключами и записями Vault).
	DeletionPolicyDelete DeletionPolicy = "Delete"
	// DeletionPolicyOrphan — снять только финализатор, в kaname ничего не звать.
	// Выдачу AccessBinding, которую запрещает политика оператора, Orphan не
	// оставляет: она отзывается, как при Delete.
	DeletionPolicyOrphan DeletionPolicy = "Orphan"
)

// OperationVerb — глагол незавершённой операции kaname, записанной в status.
// +kubebuilder:validation:Enum=Create;Update;Disable;Enable;Delete;IssueKey;RevokeKey;Revoke
type OperationVerb string

// Глаголы операций kaname.
const (
	VerbCreate    OperationVerb = "Create"
	VerbUpdate    OperationVerb = "Update"
	VerbDisable   OperationVerb = "Disable"
	VerbEnable    OperationVerb = "Enable"
	VerbDelete    OperationVerb = "Delete"
	VerbIssueKey  OperationVerb = "IssueKey"
	VerbRevokeKey OperationVerb = "RevokeKey"
	VerbRevoke    OperationVerb = "Revoke"
)

// PendingOperation — операция kaname, запущенная оператором и ещё не
// дочитанная. Пишется в status ДО того, как ответ операции применён: падение
// между запуском и применением не теряет её идентификатор.
type PendingOperation struct {
	// ID — идентификатор операции kaname.
	// +kubebuilder:validation:MinLength=1
	ID string `json:"id"`
	// Verb — что делает операция.
	Verb OperationVerb `json:"verb"`
	// Subject — предмет операции внутри объекта (имя ключа, id выдачи), если он
	// не равен самому объекту.
	// +optional
	Subject string `json:"subject,omitempty"`
	// StartedAt — момент запуска операции.
	StartedAt metav1.Time `json:"startedAt"`
}

// Метки владения на объектах kaname. Поля создателя у ServiceAccount в kaname
// нет, поэтому владение выражается метками: учётка, ключ и выдача несут uid
// CR и имя кластера, и только такую оператор усыновляет.
const (
	// LabelOwnerUID — uid CR, создавшего объект kaname.
	LabelOwnerUID = "k8s.in-cloud.io/uid"
	// LabelCluster — имя кластера оператора (из конфигурации).
	LabelCluster = "k8s.in-cloud.io/cluster"
	// LabelRef — `<namespace>.<name>` CR, если помещается в 63 знака.
	LabelRef = "k8s.in-cloud.io/ref"
	// LabelKeyName — имя ключа из spec.keys[].name.
	LabelKeyName = "k8s.in-cloud.io/key"
	// LabelKeyNonce — однократный признак выпуска ключа (намерение в status).
	LabelKeyNonce = "k8s.in-cloud.io/nonce"
	// ReservedLabelPrefix — префикс меток, которые пишет только оператор.
	ReservedLabelPrefix = "k8s.in-cloud.io/"
)

// Аннотации, которые читает оператор.
const (
	// AnnotationAccountID — аннотация namespace: id аккаунта kaname арендатора.
	AnnotationAccountID = "iam.kaname.in-cloud.io/account-id"
	// AnnotationProjectID — аннотация namespace: id проекта kaname арендатора.
	AnnotationProjectID = "iam.kaname.in-cloud.io/project-id"
	// AnnotationResyncDrift — аннотация CR: новое значение разрешает ОДИН раз
	// восстановить объект, отключённый, удалённый или отозванный в kaname
	// вручную. Ставит только платформа (ограждение допуска).
	AnnotationResyncDrift = "iam.kaname.in-cloud.io/resync-drift"
	// AnnotationCreatedBy — аннотация CR: имя пользователя k8s, создавшего CR.
	// Подлинность держит ограждение допуска: на CREATE значение обязано быть
	// равно request.userInfo.username, на UPDATE — неизменно.
	AnnotationCreatedBy = "iam.kaname.in-cloud.io/created-by"
	// AnnotationRewitness — аннотация AccessBinding: новое значение просит
	// оператор засвидетельствовать стоящие политики допуска для текущего spec
	// — так платформа, сверив spec, восстанавливает выдачи после переустановки
	// политик (новый uid) без смены spec. Ставит только платформа (ограждение
	// допуска); значение, поставленное раньше, чем стоящие политики,
	// увиденные оператором, вступили в силу, не исполняется.
	AnnotationRewitness = "iam.kaname.in-cloud.io/rewitness"
)

// Finalizer — финализатор обоих видов.
const Finalizer = "iam.kaname.in-cloud.io/finalizer"

// Типы условий.
const (
	ConditionReady          = "Ready"
	ConditionSynced         = "Synced"
	ConditionKeysReady      = "KeysReady"
	ConditionDrifted        = "Drifted"
	ConditionConflict       = "Conflict"
	ConditionSubjectPending = "SubjectPending"
	// ConditionRejected — выдача запрещена политикой оператора либо не имеет
	// гарантии допуска. Причина PolicyNarrowed — выдачу, которую объект уже
	// держал в kaname, оператор отзывает (отозвал) и вновь не заводит, пока
	// выдача снова не станет допустимой.
	ConditionRejected = "Rejected"
)

// Причины условий.
const (
	ReasonReconciled         = "Reconciled"
	ReasonInProgress         = "InProgress"
	ReasonAccountUnresolved  = "AccountUnresolved"
	ReasonScopeUnresolved    = "ScopeUnresolved"
	ReasonAccountMismatch    = "AccountMismatch"
	ReasonForbidden          = "Forbidden"
	ReasonInvalid            = "Invalid"
	ReasonRetrying           = "Retrying"
	ReasonNotOwned           = "NotOwned"
	ReasonDeletedExternally  = "DeletedExternally"
	ReasonDisabledExternally = "DisabledExternally"
	ReasonRevokedExternally  = "RevokedExternally"
	ReasonKeyRevoked         = "KeyRevokedExternally"
	ReasonNoDrift            = "NoDrift"
	ReasonNoConflict         = "NoConflict"
	ReasonSubjectNotReady    = "SubjectNotReady"
	ReasonSubjectsResolved   = "SubjectsResolved"
	ReasonTargetUnresolved   = "TargetUnresolved"
	ReasonDisabled           = "Disabled"
	ReasonDeletionBlocked    = "DeletionBlocked"
	ReasonKeysIssuing        = "Issuing"
	ReasonVaultUnavailable   = "VaultUnavailable"
	ReasonPolicyNarrowed     = "PolicyNarrowed"
	ReasonPolicySatisfied    = "PolicySatisfied"
	// ReasonAdmissionGuaranteeLost — причина события об отзыве выдачи,
	// потерявшей гарантию допуска (политики сняты, переустановлены либо
	// правлены на месте).
	ReasonAdmissionGuaranteeLost = "AdmissionGuaranteeLost"
)
