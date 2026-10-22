// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"
	"time"

	"k8s.io/utils/ptr"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

// Окно замены и перекрытие, не заданные в spec, выводятся из срока ключа:
// постоянное умолчание (10 суток) противоречило бы ключу на сутки.
func TestRotationWindowsDeriveFromTheKeyTTL(t *testing.T) {
	cases := []struct {
		name             string
		ttl              int64
		rot              iamv1alpha1.KeyRotation
		renew, overlapTo time.Duration
	}{
		{"default ttl", 0, iamv1alpha1.KeyRotation{}, 240 * time.Hour, 24 * time.Hour},
		{"one day key", 86400, iamv1alpha1.KeyRotation{}, 8 * time.Hour, 8 * time.Hour},
		{"explicit", 86400, iamv1alpha1.KeyRotation{RenewBeforeSeconds: ptr.To[int64](3600), OverlapSeconds: ptr.To[int64](600)}, time.Hour, 10 * time.Minute},
		{"explicit zero overlap", 86400, iamv1alpha1.KeyRotation{OverlapSeconds: ptr.To[int64](0)}, 8 * time.Hour, 0},
		{"renew only", 86400, iamv1alpha1.KeyRotation{RenewBeforeSeconds: ptr.To[int64](1800)}, 30 * time.Minute, 30 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := iamv1alpha1.KeySpec{TTLSeconds: tc.ttl, Rotation: tc.rot}
			if got := renewBefore(k); got != tc.renew {
				t.Errorf("renewBefore = %s, want %s", got, tc.renew)
			}
			if got := overlap(k); got != tc.overlapTo {
				t.Errorf("overlap = %s, want %s", got, tc.overlapTo)
			}
			if renewBefore(k) >= time.Duration(keyTTL(k))*time.Second {
				t.Errorf("renewBefore %s is not below the ttl", renewBefore(k))
			}
		})
	}
}
