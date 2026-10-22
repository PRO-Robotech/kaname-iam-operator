// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

// WitnessKeyBytes — длина ключа печати свидетельства, байт (HMAC-SHA256).
const WitnessKeyBytes = 32

// WitnessKeyField — поле Secret, где лежит ключ печати.
const WitnessKeyField = "key"

// sealDomain — разделитель области: печать свидетельства не совпадает ни с
// какой другой подписью на том же ключе.
const sealDomain = "kaname-iam-operator/admission-witness/v1"

// WitnessSeal — печать свидетельства допуска: HMAC-SHA256 на ключе, который
// держит только оператор (Secret в его namespace), по uid объекта и всему
// содержимому свидетельства. Свидетельство лежит в status, а status пишет не
// только оператор: пока политика status не исполняется (её окно вступления в
// силу после переустановки, снятие, правка, допустившая других писателей),
// туда пишет любой, кому RBAC даёт accessbindings/status. Печать этого
// писателя от оператора отличает: без ключа её не подделать, а uid объекта в
// ней не даёт перенести запись оператора с другого объекта.
type WitnessSeal struct {
	key []byte
}

// NewWitnessSeal — печать на ключе key (не короче WitnessKeyBytes).
func NewWitnessSeal(key []byte) (*WitnessSeal, error) {
	if len(key) < WitnessKeyBytes {
		return nil, fmt.Errorf("witness key holds %d bytes, want at least %d", len(key), WitnessKeyBytes)
	}
	return &WitnessSeal{key: slices.Clone(key)}, nil
}

// sign — печать свидетельства w объекта uid.
func (s *WitnessSeal) sign(uid types.UID, w *iamv1alpha1.AdmissionWitness) string {
	return base64.StdEncoding.EncodeToString(s.mac(uid, w))
}

// verify — несёт ли w печать оператора для объекта uid.
func (s *WitnessSeal) verify(uid types.UID, w *iamv1alpha1.AdmissionWitness) bool {
	got, err := base64.StdEncoding.DecodeString(w.Seal)
	return err == nil && hmac.Equal(got, s.mac(uid, w))
}

// mac — HMAC канонической записи: каждое значение с длиной впереди, записи
// политик по имени, время — как его хранит k8s (RFC 3339, секунды), поэтому
// печать переживает запись в status и чтение обратно.
func (s *WitnessSeal) mac(uid types.UID, w *iamv1alpha1.AdmissionWitness) []byte {
	m := hmac.New(sha256.New, s.key)
	put := func(v string) { writeField(m, v) }
	num := func(v int64) { put(strconv.FormatInt(v, 10)) }
	put(sealDomain)
	put(string(uid))
	recs := slices.Clone(w.Policies)
	slices.SortFunc(recs, func(a, b iamv1alpha1.AdmissionPolicyUIDs) int { return strings.Compare(a.Name, b.Name) })
	num(int64(len(recs)))
	for _, r := range recs {
		put(r.Name)
		put(string(r.PolicyUID))
		num(r.PolicyGeneration)
		put(string(r.BindingUID))
		num(r.BindingGeneration)
		num(r.Generation)
		if r.PendingSince == nil {
			put("")
		} else {
			put(r.PendingSince.UTC().Format(time.RFC3339))
		}
	}
	put(w.RewitnessNonce)
	num(w.ConfirmedGeneration)
	put(w.ConfirmedCreatedBy)
	return m.Sum(nil)
}

// writeField пишет значение v с его длиной впереди («длина:значение,»):
// границы значений не сдвигаются содержимым.
func writeField(h hash.Hash, v string) {
	h.Write([]byte(strconv.Itoa(len(v)) + ":" + v + ","))
}

// SecretStore — то из клиента Secret одного namespace, чем пользуется
// LoadWitnessKey.
type SecretStore interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	Create(ctx context.Context, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
}

// LoadWitnessKey читает ключ печати из Secret name, а нет его — заводит
// (неизменяемым, со случайным ключом). Реплики оператора стартуют вместе:
// заведённый соседом Secret читается заново. Ключ короче WitnessKeyBytes —
// отказ: оператор без ключа не стартует, и свидетельству без печати не
// доверяет никто.
func LoadWitnessKey(ctx context.Context, secrets SecretStore, name string) ([]byte, error) {
	for range 2 {
		s, err := secrets.Get(ctx, name, metav1.GetOptions{})
		switch {
		case err == nil:
			key := s.Data[WitnessKeyField]
			if len(key) < WitnessKeyBytes {
				return nil, fmt.Errorf("witness key secret %s: field %q holds %d bytes, want at least %d", name, WitnessKeyField, len(key), WitnessKeyBytes)
			}
			return key, nil
		case !apierrors.IsNotFound(err):
			return nil, fmt.Errorf("witness key secret %s: %w", name, err)
		}
		key := make([]byte, WitnessKeyBytes)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("witness key: %w", err)
		}
		immutable := true
		_, err = secrets.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"app.kubernetes.io/managed-by": "kaname-iam-operator"}},
			Type:       corev1.SecretTypeOpaque,
			Immutable:  &immutable,
			Data:       map[string][]byte{WitnessKeyField: key},
		}, metav1.CreateOptions{})
		switch {
		case err == nil:
			return key, nil
		case !apierrors.IsAlreadyExists(err):
			return nil, fmt.Errorf("witness key secret %s: %w", name, err)
		}
	}
	return nil, fmt.Errorf("witness key secret %s is created and deleted concurrently", name)
}
