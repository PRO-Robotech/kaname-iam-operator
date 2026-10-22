// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeyKind — вид удостоверения ключа учётки kaname (CredentialKind).
// +kubebuilder:validation:Enum=Secret;Keypair
type KeyKind string

const (
	// KeyKindSecret — однострочный базовый секрет (CREDENTIAL_KIND_SECRET):
	// предъявляется как есть, в том числе паролем докер-полосы. Потолок срока —
	// 90 суток, адресатов у него нет.
	KeyKindSecret KeyKind = "Secret"
	// KeyKindKeypair — ключевая пара ES256 (CREDENTIAL_KIND_KEYPAIR): закрытая
	// половина подписывает утверждение на токен-эндпоинте.
	KeyKindKeypair KeyKind = "Keypair"
)

// Пределы срока ключа в секундах.
const (
	// SecretKeyTTLCeilingSeconds — потолок срока секрета (90 суток) в kaname.
	SecretKeyTTLCeilingSeconds int64 = 7776000
	// KeyTTLCeilingSeconds — потолок срока ключевой пары (365 суток) в kaname.
	KeyTTLCeilingSeconds int64 = 31536000
)

// VaultDelivery — куда в Vault кладётся удостоверение ключа. Путь вычисляет
// ОПЕРАТОР по шаблону приложения из своей конфигурации: арендатор называет
// только приложение и экземпляр, а не путь.
type VaultDelivery struct {
	// App — приложение из перечня доставки конфигурации оператора.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	App string `json:"app"`
	// Instance — экземпляр приложения (DNS-метка).
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	Instance string `json:"instance"`
}

// KeyDelivery — доставка удостоверения ключа.
type KeyDelivery struct {
	// Vault — доставка в Vault KV v2.
	Vault VaultDelivery `json:"vault"`
}

// KeyRotation — когда выпускать замену и сколько держать прежний ключ.
// Не заданное поле вычисляет оператор от срока ключа: замена — за
// min(10 суток, срок/3) до истечения, перекрытие — min(1 сутки, окно замены).
// Умолчание схемой не ставится: постоянное умолчание противоречило бы
// короткому сроку ключа.
type KeyRotation struct {
	// RenewBeforeSeconds — за сколько секунд до истечения выпускается замена.
	// +kubebuilder:validation:Minimum=60
	// +optional
	RenewBeforeSeconds *int64 `json:"renewBeforeSeconds,omitempty"`
	// OverlapSeconds — сколько секунд прежний ключ живёт после выпуска замены;
	// 0 — прежний ключ отзывается сразу.
	// +kubebuilder:validation:Minimum=0
	// +optional
	OverlapSeconds *int64 `json:"overlapSeconds,omitempty"`
}

// KeySpec — один ключ учётки.
// +kubebuilder:validation:XValidation:rule="self.kind != 'Secret' || self.ttlSeconds <= 7776000",message="ttlSeconds of a Secret key must be <= 7776000 (90 days)"
// +kubebuilder:validation:XValidation:rule="self.kind != 'Secret' || !has(self.audience) || size(self.audience) == 0",message="audience is not meaningful for a Secret key"
// +kubebuilder:validation:XValidation:rule="!has(self.rotation) || !has(self.rotation.renewBeforeSeconds) || self.rotation.renewBeforeSeconds < self.ttlSeconds",message="rotation.renewBeforeSeconds must be less than ttlSeconds"
// +kubebuilder:validation:XValidation:rule="!has(self.rotation) || !has(self.rotation.overlapSeconds) || self.rotation.overlapSeconds < self.ttlSeconds",message="rotation.overlapSeconds must be less than ttlSeconds"
// +kubebuilder:validation:XValidation:rule="!has(self.rotation) || !has(self.rotation.overlapSeconds) || !has(self.rotation.renewBeforeSeconds) || self.rotation.overlapSeconds <= self.rotation.renewBeforeSeconds",message="rotation.overlapSeconds must not exceed rotation.renewBeforeSeconds"
type KeySpec struct {
	// Name — имя ключа внутри учётки.
	// +kubebuilder:validation:Pattern=`^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=32
	Name string `json:"name"`
	// Kind — вид удостоверения. Неизменяем: другой вид — другой ключ.
	// +kubebuilder:default=Secret
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="kind is immutable"
	// +optional
	Kind KeyKind `json:"kind,omitempty"`
	// TTLSeconds — срок ключа в секундах (ttl_seconds выпуска kaname).
	// +kubebuilder:default=2592000
	// +kubebuilder:validation:Minimum=3600
	// +kubebuilder:validation:Maximum=31536000
	// +optional
	TTLSeconds int64 `json:"ttlSeconds,omitempty"`
	// Audience — сужение адресатов ключа (audience выпуска kaname). Только для
	// ключевой пары.
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=256
	// +kubebuilder:validation:items:MinLength=1
	// +listType=atomic
	// +optional
	Audience []string `json:"audience,omitempty"`
	// Rotation — ротация с перекрытием.
	// +optional
	Rotation KeyRotation `json:"rotation,omitempty"`
	// Delivery — доставка удостоверения. Неизменяема: другой путь — другой ключ.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="delivery is immutable"
	Delivery KeyDelivery `json:"delivery"`
}

// ServiceAccountSpec — желаемое состояние учётки kaname.
type ServiceAccountSpec struct {
	// Name — имя учётки в kaname, уникальное в аккаунте. Неизменяемо.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec.name is immutable"
	Name string `json:"name"`
	// Description — описание учётки.
	// +kubebuilder:validation:MaxLength=256
	// +optional
	Description string `json:"description,omitempty"`
	// Enabled — включена ли учётка. Выключение зовёт `:disable`; включение
	// после ручного отключения в kaname оператор сам НЕ делает (Drifted).
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
	// Labels — метки учётки в kaname. Префикс k8s.in-cloud.io/ занят оператором.
	// +kubebuilder:validation:MaxProperties=32
	// +kubebuilder:validation:XValidation:rule="self.all(k, !k.startsWith('k8s.in-cloud.io/'))",message="label prefix k8s.in-cloud.io/ is reserved for the operator"
	// +kubebuilder:validation:XValidation:rule="self.all(k, k.matches('^[a-z][-_./@a-z0-9]{0,62}$'))",message="label keys must match ^[a-z][-_./@a-z0-9]{0,62}$"
	// +kubebuilder:validation:XValidation:rule="self.all(k, size(self[k]) <= 63)",message="label values must be at most 63 characters"
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// Keys — ключи учётки, доставляемые в Vault.
	// +kubebuilder:validation:MaxItems=8
	// +listType=map
	// +listMapKey=name
	// +optional
	Keys []KeySpec `json:"keys,omitempty"`
	// DeletionPolicy — что делать с учёткой kaname при удалении CR.
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// KeyIssuing — намерение выпуска: записывается в status ДО вызова kaname.
// Nonce уходит в метки ключа kaname и в запись Vault — по нему падение между
// любыми двумя шагами выпуска распознаётся и дочитывается.
type KeyIssuing struct {
	// Nonce — однократный признак выпуска.
	Nonce string `json:"nonce"`
	// At — момент записи намерения.
	At metav1.Time `json:"at"`
}

// PreviousKey — прежний ключ, живущий до RevokeAt после ротации.
type PreviousKey struct {
	// KeyID — id прежнего ключа в kaname.
	KeyID string `json:"keyId"`
	// RevokeAt — когда прежний ключ отзывается.
	RevokeAt metav1.Time `json:"revokeAt"`
}

// KeyStatus — наблюдаемое состояние ключа.
type KeyStatus struct {
	// Name — имя ключа из spec.keys[].name.
	Name string `json:"name"`
	// KeyID — id действующего ключа в kaname.
	// +optional
	KeyID string `json:"keyId,omitempty"`
	// ExpiresAt — срок действующего ключа.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
	// VaultPath — путь записи Vault (mount/path), вычисленный оператором.
	// +optional
	VaultPath string `json:"vaultPath,omitempty"`
	// VaultVersion — версия записи Vault KV v2 с действующим ключом.
	// +optional
	VaultVersion int64 `json:"vaultVersion,omitempty"`
	// Issuing — незавершённый выпуск.
	// +optional
	Issuing *KeyIssuing `json:"issuing,omitempty"`
	// Previous — прежний ключ в окне перекрытия.
	// +optional
	Previous *PreviousKey `json:"previous,omitempty"`
}

// ServiceAccountStatus — наблюдаемое состояние учётки.
type ServiceAccountStatus struct {
	// ObservedGeneration — поколение spec, по которому выставлены условия.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// ID — id учётки в kaname (sva…).
	// +optional
	ID string `json:"id,omitempty"`
	// AccountID — аккаунт kaname, в котором учётка заведена.
	// +optional
	AccountID string `json:"accountId,omitempty"`
	// PendingOperation — незавершённая операция kaname.
	// +optional
	PendingOperation *PendingOperation `json:"pendingOperation,omitempty"`
	// ResyncNonce — значение аннотации resync-drift, по которому восстановление
	// уже выполнено.
	// +optional
	ResyncNonce string `json:"resyncNonce,omitempty"`
	// Keys — состояние ключей.
	// +listType=map
	// +listMapKey=name
	// +optional
	Keys []KeyStatus `json:"keys,omitempty"`
	// Conditions — Ready, Synced, KeysReady, Drifted, Conflict.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ServiceAccount — учётка kaname IAM с ключами, доставляемыми в Vault.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ksa,categories=kaname-iam
// +kubebuilder:printcolumn:name="KanameName",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="ID",type=string,JSONPath=`.status.id`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type ServiceAccount struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ServiceAccountSpec   `json:"spec"`
	Status ServiceAccountStatus `json:"status,omitempty"`
}

// ServiceAccountList — список ServiceAccount.
// +kubebuilder:object:root=true
type ServiceAccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceAccount `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ServiceAccount{}, &ServiceAccountList{})
}

// IsEnabled — включена ли учётка по spec (умолчание — да).
func (s *ServiceAccountSpec) IsEnabled() bool {
	return s.Enabled == nil || *s.Enabled
}

// EffectiveDeletionPolicy — политика удаления с умолчанием Delete.
func (s *ServiceAccountSpec) EffectiveDeletionPolicy() DeletionPolicy {
	if s.DeletionPolicy == "" {
		return DeletionPolicyDelete
	}
	return s.DeletionPolicy
}

// KeyStatusByName — указатель на состояние ключа по имени либо nil.
func (s *ServiceAccountStatus) KeyStatusByName(name string) *KeyStatus {
	for i := range s.Keys {
		if s.Keys[i].Name == name {
			return &s.Keys[i]
		}
	}
	return nil
}
