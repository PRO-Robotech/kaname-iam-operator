// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

// testSeal — печать проб: свидетельство, записанное оператором проб.
var testSeal = func() *WitnessSeal {
	s, err := NewWitnessSeal(bytes.Repeat([]byte{7}, WitnessKeyBytes))
	if err != nil {
		panic(err)
	}
	return s
}()

// Печать держит каждое поле свидетельства и uid объекта и переживает запись
// в status и чтение обратно. Законный близнец — свидетельство, прочитанное
// обратно; каждое отрицание меняет один факт.
func TestWitnessSealCoversEveryFieldAndTheObject(t *testing.T) {
	since := metav1.NewTime(t0.Add(1500 * time.Millisecond))
	w := &iamv1alpha1.AdmissionWitness{Policies: []iamv1alpha1.AdmissionPolicyUIDs{entry("kio-writers", 2), pending(entry("kio-bindings", 0), since.Time)},
		RewitnessNonce: "n1", ConfirmedGeneration: 2, ConfirmedCreatedBy: "platform"}
	w.Seal = testSeal.sign("ab-1", w)
	if back := stored(t, w); !testSeal.verify("ab-1", back) {
		t.Fatalf("seal of %+v lost on the way through status", back)
	}
	other, err := NewWitnessSeal(bytes.Repeat([]byte{8}, WitnessKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		uid    string
		seal   *WitnessSeal
		mutate func(*iamv1alpha1.AdmissionWitness)
	}{
		{"another object", "ab-2", testSeal, nil},
		{"another key", "ab-1", other, nil},
		{"no seal", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.Seal = "" }},
		{"seal not in base64", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.Seal = "%%" }},
		{"record generation", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.Policies[0].Generation = 0 }},
		{"record policy uid", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.Policies[0].PolicyUID += "x" }},
		{"record policy generation", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.Policies[0].PolicyGeneration++ }},
		{"record binding uid", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.Policies[0].BindingUID += "x" }},
		{"record binding generation", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.Policies[0].BindingGeneration++ }},
		{"record name", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.Policies[0].Name = "kio-other" }},
		{"pendingSince removed", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.Policies[1].PendingSince = nil }},
		{"pendingSince moved", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) {
			moved := metav1.NewTime(since.Add(-time.Hour))
			w.Policies[1].PendingSince = &moved
		}},
		{"record removed", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.Policies = w.Policies[:1] }},
		{"rewitness nonce", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.RewitnessNonce = "" }},
		{"confirmed generation", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.ConfirmedGeneration = 3 }},
		{"confirmed created-by", "ab-1", testSeal, func(w *iamv1alpha1.AdmissionWitness) { w.ConfirmedCreatedBy = "other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stored(t, w)
			if tc.mutate != nil {
				tc.mutate(got)
			}
			if tc.seal.verify(types.UID(tc.uid), got) {
				t.Fatalf("seal holds for %+v", got)
			}
		})
	}
	// Порядок записей политик печати не меняет: список — карта по имени.
	reordered := stored(t, w)
	reordered.Policies[0], reordered.Policies[1] = reordered.Policies[1], reordered.Policies[0]
	if !testSeal.verify("ab-1", reordered) {
		t.Fatal("seal depends on the order of the records")
	}
}

func TestWitnessSealRefusesAShortKey(t *testing.T) {
	if _, err := NewWitnessSeal(make([]byte, WitnessKeyBytes-1)); err == nil {
		t.Fatal("a key shorter than WitnessKeyBytes accepted")
	}
}

// Ключ печати: Secret есть — читается, нет — заводится неизменяемым со
// случайным ключом, заведён соседней репликой между чтением и созданием —
// читается заново; ключ короче WitnessKeyBytes — отказ.
func TestLoadWitnessKey(t *testing.T) {
	ctx := context.Background()
	const ns, name = "kio-system", "kio-witness-key"
	t.Run("absent: created immutable with a random key, and read back on the next start", func(t *testing.T) {
		cs := fake.NewClientset()
		key, err := LoadWitnessKey(ctx, cs.CoreV1().Secrets(ns), name)
		if err != nil || len(key) != WitnessKeyBytes || bytes.Equal(key, make([]byte, WitnessKeyBytes)) {
			t.Fatalf("key %x, err %v", key, err)
		}
		s, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil || s.Immutable == nil || !*s.Immutable || !bytes.Equal(s.Data[WitnessKeyField], key) {
			t.Fatalf("secret %+v, err %v", s, err)
		}
		again, err := LoadWitnessKey(ctx, cs.CoreV1().Secrets(ns), name)
		if err != nil || !bytes.Equal(again, key) {
			t.Fatalf("next start read %x (%v), want %x", again, err, key)
		}
	})
	t.Run("created by another replica in between", func(t *testing.T) {
		cs := fake.NewClientset()
		theirs := bytes.Repeat([]byte{9}, WitnessKeyBytes)
		cs.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
			if err := cs.Tracker().Add(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
				Data: map[string][]byte{WitnessKeyField: theirs}}); err != nil {
				return true, nil, err
			}
			return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, name)
		})
		key, err := LoadWitnessKey(ctx, cs.CoreV1().Secrets(ns), name)
		if err != nil || !bytes.Equal(key, theirs) {
			t.Fatalf("key %x (%v), want the other replica's %x", key, err, theirs)
		}
	})
	t.Run("a short key is refused", func(t *testing.T) {
		cs := fake.NewClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Data: map[string][]byte{WitnessKeyField: make([]byte, WitnessKeyBytes-1)}})
		if _, err := LoadWitnessKey(ctx, cs.CoreV1().Secrets(ns), name); err == nil || !strings.Contains(err.Error(), "holds 31 bytes") {
			t.Fatalf("short key: %v", err)
		}
	})
	t.Run("a read failure is not a missing key", func(t *testing.T) {
		cs := fake.NewClientset()
		cs.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, name, errors.New("no get"))
		})
		if _, err := LoadWitnessKey(ctx, cs.CoreV1().Secrets(ns), name); err == nil || !apierrors.IsForbidden(err) {
			t.Fatalf("forbidden read: %v", err)
		}
		if n := len(cs.Actions()); n != 1 {
			t.Fatalf("%d calls after a refused read, want 1: no key is created over a secret it cannot read", n)
		}
	})
}
