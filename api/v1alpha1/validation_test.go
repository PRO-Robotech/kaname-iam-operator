// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package v1alpha1_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

// Проба схемы CRD: каждое отрицание схемы (CEL и OpenAPI) — с законным
// близнецом, отличающимся одним фактом. Судит настоящий kube-apiserver.
var k8s client.Client

const ns = "validation"

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		fmt.Fprintln(os.Stderr, "CRD validation suite: KUBEBUILDER_ASSETS is not set — run through `make test`; the suite is NOT executed")
		return 3
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest:", err)
		return 1
	}
	defer func() { _ = env.Stop() }()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = iamv1alpha1.AddToScheme(scheme)
	k8s, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		return 1
	}
	if err := k8s.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		fmt.Fprintln(os.Stderr, "namespace:", err)
		return 1
	}
	return m.Run()
}

var seq int

func name(prefix string) string {
	seq++
	return fmt.Sprintf("%s-%d", prefix, seq)
}

func validSA() *iamv1alpha1.ServiceAccount {
	return &iamv1alpha1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name("sa"), Namespace: ns},
		Spec: iamv1alpha1.ServiceAccountSpec{
			Name:   "zot-ci",
			Labels: map[string]string{"registry": "abc123"},
			Keys: []iamv1alpha1.KeySpec{{
				Name:     "push",
				Delivery: iamv1alpha1.KeyDelivery{Vault: iamv1alpha1.VaultDelivery{App: "docker-registry", Instance: "abc123"}},
			}},
		},
	}
}

func validAB() *iamv1alpha1.AccessBinding {
	return &iamv1alpha1.AccessBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name("ab"), Namespace: ns},
		Spec: iamv1alpha1.AccessBindingSpec{
			Subjects: []iamv1alpha1.Subject{{ServiceAccountRef: &iamv1alpha1.LocalServiceAccountRef{Name: "zot-ci"}}},
			RoleRef:  iamv1alpha1.RoleRef{Name: "registry.pusher"},
			Target:   iamv1alpha1.Target{Resources: []iamv1alpha1.ResourceRef{{Type: "registry.registries", ID: "abc123"}}},
		},
	}
}

func refused(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want refusal naming %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal %q does not name %q", err, want)
	}
}

func TestServiceAccountDefaultsAreApplied(t *testing.T) {
	sa := validSA()
	if err := k8s.Create(context.Background(), sa); err != nil {
		t.Fatalf("lawful SA refused: %v", err)
	}
	k := sa.Spec.Keys[0]
	if k.Kind != iamv1alpha1.KeyKindSecret || k.TTLSeconds != 2592000 || k.Rotation.RenewBeforeSeconds != 864000 || k.Rotation.OverlapSeconds != 86400 {
		t.Fatalf("key defaults = %+v", k)
	}
	if sa.Spec.Enabled == nil || !*sa.Spec.Enabled || sa.Spec.DeletionPolicy != iamv1alpha1.DeletionPolicyDelete {
		t.Fatalf("spec defaults: enabled %v policy %q", sa.Spec.Enabled, sa.Spec.DeletionPolicy)
	}
}

func TestServiceAccountCreateRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*iamv1alpha1.ServiceAccount)
		want   string
	}{
		{"secret ttl above 90 days", func(s *iamv1alpha1.ServiceAccount) { s.Spec.Keys[0].TTLSeconds = 7776001 }, "90 days"},
		{"secret with audience", func(s *iamv1alpha1.ServiceAccount) { s.Spec.Keys[0].Audience = []string{"registry"} }, "audience is not meaningful"},
		{"renewBefore not below ttl", func(s *iamv1alpha1.ServiceAccount) {
			s.Spec.Keys[0].TTLSeconds = 3600
			s.Spec.Keys[0].Rotation = iamv1alpha1.KeyRotation{RenewBeforeSeconds: 3600, OverlapSeconds: 60}
		}, "renewBeforeSeconds must be less than ttlSeconds"},
		{"overlap above renewBefore", func(s *iamv1alpha1.ServiceAccount) {
			s.Spec.Keys[0].Rotation = iamv1alpha1.KeyRotation{RenewBeforeSeconds: 600, OverlapSeconds: 601}
		}, "overlapSeconds must not exceed"},
		{"reserved label prefix", func(s *iamv1alpha1.ServiceAccount) {
			s.Spec.Labels = map[string]string{"k8s.in-cloud.io/uid": "x"}
		}, "reserved for the operator"},
		{"label key form", func(s *iamv1alpha1.ServiceAccount) { s.Spec.Labels = map[string]string{"Team": "a"} }, "label keys must match"},
		{"name not a dns label", func(s *iamv1alpha1.ServiceAccount) { s.Spec.Name = "Zot_CI" }, "spec.name"},
		{"vault instance with a slash", func(s *iamv1alpha1.ServiceAccount) { s.Spec.Keys[0].Delivery.Vault.Instance = "a/b" }, "instance"},
		{"unknown key kind", func(s *iamv1alpha1.ServiceAccount) { s.Spec.Keys[0].Kind = "Federated" }, "kind"},
		{"duplicate key names", func(s *iamv1alpha1.ServiceAccount) { s.Spec.Keys = append(s.Spec.Keys, s.Spec.Keys[0]) }, "Duplicate value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sa := validSA()
			tc.mutate(sa)
			refused(t, k8s.Create(context.Background(), sa), tc.want)
		})
	}
}

func TestServiceAccountLawfulTwins(t *testing.T) {
	twins := []func(*iamv1alpha1.ServiceAccount){
		func(s *iamv1alpha1.ServiceAccount) { s.Spec.Keys[0].TTLSeconds = 7776000 },
		func(s *iamv1alpha1.ServiceAccount) {
			s.Spec.Keys[0].Kind = iamv1alpha1.KeyKindKeypair
			s.Spec.Keys[0].TTLSeconds = 31536000
			s.Spec.Keys[0].Audience = []string{"registry"}
		},
		func(s *iamv1alpha1.ServiceAccount) {
			s.Spec.Keys[0].TTLSeconds = 3600
			s.Spec.Keys[0].Rotation = iamv1alpha1.KeyRotation{RenewBeforeSeconds: 3599, OverlapSeconds: 3599}
		},
		func(s *iamv1alpha1.ServiceAccount) { s.Spec.Labels = map[string]string{"in-cloud.io/team": "a"} },
	}
	for i, mutate := range twins {
		sa := validSA()
		mutate(sa)
		if err := k8s.Create(context.Background(), sa); err != nil {
			t.Errorf("twin %d refused: %v", i, err)
		}
	}
}

func TestServiceAccountImmutableFields(t *testing.T) {
	ctx := context.Background()
	sa := validSA()
	if err := k8s.Create(ctx, sa); err != nil {
		t.Fatal(err)
	}
	upd := func(mutate func(*iamv1alpha1.ServiceAccount)) error {
		cur := &iamv1alpha1.ServiceAccount{}
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(sa), cur); err != nil {
			t.Fatal(err)
		}
		mutate(cur)
		return k8s.Update(ctx, cur)
	}
	refused(t, upd(func(s *iamv1alpha1.ServiceAccount) { s.Spec.Name = "zot-other" }), "spec.name is immutable")
	refused(t, upd(func(s *iamv1alpha1.ServiceAccount) { s.Spec.Keys[0].Kind = iamv1alpha1.KeyKindKeypair }), "kind is immutable")
	refused(t, upd(func(s *iamv1alpha1.ServiceAccount) { s.Spec.Keys[0].Delivery.Vault.Instance = "def456" }), "delivery is immutable")
	// Законные близнецы: правка описания, срока ключа и выключение.
	if err := upd(func(s *iamv1alpha1.ServiceAccount) {
		s.Spec.Description = "v2"
		s.Spec.Keys[0].TTLSeconds = 86400
		s.Spec.Enabled = ptr.To(false)
	}); err != nil {
		t.Fatalf("mutable fields refused: %v", err)
	}
	// Новый ключ с иным путём — законно (другое имя ключа).
	if err := upd(func(s *iamv1alpha1.ServiceAccount) {
		s.Spec.Keys = append(s.Spec.Keys, iamv1alpha1.KeySpec{
			Name:     "pull",
			Delivery: iamv1alpha1.KeyDelivery{Vault: iamv1alpha1.VaultDelivery{App: "docker-registry", Instance: "def456"}},
		})
	}); err != nil {
		t.Fatalf("adding a key refused: %v", err)
	}
}

func TestAccessBindingCreateRefusalsAndTwins(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*iamv1alpha1.AccessBinding)
		want   string
	}{
		{"two fields in one subject", func(a *iamv1alpha1.AccessBinding) {
			a.Spec.Subjects[0].User = &iamv1alpha1.PrincipalRef{ID: "usr1"}
		}, "exactly one of"},
		{"no field in a subject", func(a *iamv1alpha1.AccessBinding) {
			a.Spec.Subjects = []iamv1alpha1.Subject{{}}
		}, "exactly one of"},
		{"no subjects", func(a *iamv1alpha1.AccessBinding) { a.Spec.Subjects = nil }, "subjects"},
		{"no target", func(a *iamv1alpha1.AccessBinding) { a.Spec.Target.Resources = nil }, "resources"},
		{"unknown system class", func(a *iamv1alpha1.AccessBinding) {
			a.Spec.Subjects = []iamv1alpha1.Subject{{SystemClass: &iamv1alpha1.SystemClassRef{Name: "everyone"}}}
		}, "name"},
		{"unknown scope type", func(a *iamv1alpha1.AccessBinding) { a.Spec.Scope.Type = "iam.cluster" }, "scope.type"},
		{"reserved label prefix", func(a *iamv1alpha1.AccessBinding) {
			a.Spec.Labels = map[string]string{"k8s.in-cloud.io/uid": "x"}
		}, "reserved for the operator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ab := validAB()
			tc.mutate(ab)
			refused(t, k8s.Create(context.Background(), ab), tc.want)
		})
	}
	twins := []func(*iamv1alpha1.AccessBinding){
		func(a *iamv1alpha1.AccessBinding) {},
		func(a *iamv1alpha1.AccessBinding) {
			a.Spec.Subjects = []iamv1alpha1.Subject{{SystemClass: &iamv1alpha1.SystemClassRef{Name: "anonymous"}}}
		},
		func(a *iamv1alpha1.AccessBinding) { a.Spec.Scope.Type = iamv1alpha1.ScopeAccount },
	}
	for i, mutate := range twins {
		ab := validAB()
		mutate(ab)
		if err := k8s.Create(context.Background(), ab); err != nil {
			t.Errorf("twin %d refused: %v", i, err)
		}
	}
}

func TestAccessBindingImmutableFieldsAndMutableTarget(t *testing.T) {
	ctx := context.Background()
	ab := validAB()
	if err := k8s.Create(ctx, ab); err != nil {
		t.Fatal(err)
	}
	if ab.Spec.Scope.Type != iamv1alpha1.ScopeProject || ab.Spec.DeletionPolicy != iamv1alpha1.DeletionPolicyDelete {
		t.Fatalf("defaults: scope %q policy %q", ab.Spec.Scope.Type, ab.Spec.DeletionPolicy)
	}
	upd := func(mutate func(*iamv1alpha1.AccessBinding)) error {
		cur := &iamv1alpha1.AccessBinding{}
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(ab), cur); err != nil {
			t.Fatal(err)
		}
		mutate(cur)
		return k8s.Update(ctx, cur)
	}
	refused(t, upd(func(a *iamv1alpha1.AccessBinding) { a.Spec.RoleRef.Name = "registry.admin" }), "roleRef is immutable")
	refused(t, upd(func(a *iamv1alpha1.AccessBinding) {
		a.Spec.Subjects[0].ServiceAccountRef.Name = "other"
	}), "subjects are immutable")
	refused(t, upd(func(a *iamv1alpha1.AccessBinding) { a.Spec.Scope.Type = iamv1alpha1.ScopeAccount }), "scope is immutable")
	// Законный близнец: цель меняется — оператор заводит новую выдачу.
	if err := upd(func(a *iamv1alpha1.AccessBinding) { a.Spec.Target.Resources[0].ID = "def456" }); err != nil {
		t.Fatalf("target change refused: %v", err)
	}
}
