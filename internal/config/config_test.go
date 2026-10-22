// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validYAML — законный близнец всех отрицательных случаев ниже: каждый из них
// меняет ровно один факт этого текста.
const validYAML = `
clusterName: system-1
kaname:
  apiURL: https://kaname.kaname.svc:9098
  audience: https://kaname.local
vault:
  address: https://vault.vault.svc:8200
  authMount: kubernetes
  role: kaname-iam-operator
  tokenPath: /var/run/secrets/vault/token
policy:
  allowedRoles: [registry.puller, registry.pusher, registry.public.read]
  systemClassRoles: [registry.public.read]
  platformPrincipals: ["system:serviceaccount:platform-system:onboarding"]
  targetResolvers:
    registry.registries:
      group: registry.in-cloud.io
      version: v1alpha1
      resource: registryidreservations
      match:
      - path: spec.registryRef.namespace
        equals: $namespace
      - path: status.phase
        equals: Active
delivery:
  vault:
    docker-registry:
      mount: secret
      pathTemplate: clusters/{cluster}/namespaces/{namespace}/apps/docker-registry/{instance}/robots/{name}/{key}
`

func TestParseValidConfigAppliesDefaults(t *testing.T) {
	c, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	if c == nil {
		t.Fatal("valid config: nil result")
	}
	if got := c.Kaname.CallTimeout.Duration; got != 10*time.Second {
		t.Errorf("kaname.callTimeout default = %s, want 10s", got)
	}
	if got := c.Vault.CallTimeout.Duration; got != 5*time.Second {
		t.Errorf("vault.callTimeout default = %s, want 5s", got)
	}
	if got := c.Kaname.AssertionTTL.Duration; got != 10*time.Minute {
		t.Errorf("kaname.assertionTTL default = %s, want 10m", got)
	}
	if got := c.Keys.OrphanGrace.Duration; got != 10*time.Minute {
		t.Errorf("keys.orphanGrace default = %s, want 10m", got)
	}
	if got := c.Kaname.CreateGrace.Duration; got != 10*time.Minute {
		t.Errorf("kaname.createGrace default = %s, want 10m", got)
	}
	if got := c.Kaname.TokenURL; got != "https://kaname.kaname.svc:9098/iam/v1/token" {
		t.Errorf("kaname.tokenURL default = %q", got)
	}
	if c.Kaname.QPS != 10 || c.Kaname.Burst != 20 {
		t.Errorf("kaname rate default = %v/%d, want 10/20", c.Kaname.QPS, c.Kaname.Burst)
	}
}

func TestParseRefusesEachBrokenFact(t *testing.T) {
	cases := []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{"cluster name missing", "clusterName: system-1", "clusterName: \"\"", "clusterName"},
		{"cluster name not a dns label", "clusterName: system-1", "clusterName: System_1", "clusterName"},
		{"kaname api over plaintext", "apiURL: https://kaname.kaname.svc:9098", "apiURL: http://kaname.kaname.svc:9098", "kaname.apiURL"},
		{"kaname api with a path", "apiURL: https://kaname.kaname.svc:9098", "apiURL: https://kaname.kaname.svc:9098/iam/v1", "kaname.apiURL"},
		{"kaname audience missing", "audience: https://kaname.local", "audience: \"\"", "kaname.audience"},
		{"vault over plaintext", "address: https://vault.vault.svc:8200", "address: http://vault.vault.svc:8200", "vault.address"},
		{"vault role missing", "role: kaname-iam-operator", "role: \"\"", "vault.role"},
		{"vault token path relative", "tokenPath: /var/run/secrets/vault/token", "tokenPath: token", "vault.tokenPath"},
		{"no allowed roles", "allowedRoles: [registry.puller, registry.pusher, registry.public.read]", "allowedRoles: []", "policy.allowedRoles"},
		{"system class role outside allowed", "systemClassRoles: [registry.public.read]", "systemClassRoles: [registry.admin]", "policy.systemClassRoles"},
		{"template without key", "robots/{name}/{key}", "robots/{name}", "{key}"},
		{"template without namespace", "namespaces/{namespace}/apps", "namespaces/x/apps", "{namespace}"},
		// Без кластера два кластера с общим Vault пишут в один путь.
		{"template without cluster", "clusters/{cluster}/namespaces", "clusters/x/namespaces", "{cluster}"},
		// Две подстановки в одном сегменте: (name=a, key=b-c) и (name=a-b, key=c)
		// дают один путь.
		{"two placeholders in one segment", "robots/{name}/{key}", "robots/{name}-{key}", "{name}-{key}"},
		{"placeholder glued to a literal", "robots/{name}/{key}", "robots/r{name}/{key}", "r{name}"},
		{"template unknown placeholder", "apps/docker-registry/{instance}", "apps/docker-registry/{tenant}", "{tenant}"},
		{"template parent segment", "clusters/{cluster}/", "clusters/../{cluster}/", ".."},
		{"template absolute", "pathTemplate: clusters/", "pathTemplate: /clusters/", "pathTemplate"},
		{"mount with slash", "mount: secret", "mount: secret/sub", "mount"},
		{"resolver without match", "      match:\n      - path: spec.registryRef.namespace\n        equals: $namespace\n      - path: status.phase\n        equals: Active\n", "      match: []\n", "match"},
		{"resolver bad path", "path: status.phase", "path: status..phase", "path"},
		{"resolver without namespace binding", "equals: $namespace", "equals: tenant", "$namespace"},
		{"unknown field", "clusterName: system-1", "clusterName: system-1\nclusterNmae: x", "clusterNmae"},
		{"call timeout too long", "audience: https://kaname.local", "audience: https://kaname.local\n  callTimeout: 5m", "kaname.callTimeout"},
		{"assertion ttl below apiserver floor", "audience: https://kaname.local", "audience: https://kaname.local\n  assertionTTL: 5m", "kaname.assertionTTL"},
		{"assertion ttl above kaname ceiling", "audience: https://kaname.local", "audience: https://kaname.local\n  assertionTTL: 2h", "kaname.assertionTTL"},
		// Окно короче фонового исполнения kaname — пустой поиск снова читался
		// бы доказательством отсутствия.
		{"create grace below the floor", "audience: https://kaname.local", "audience: https://kaname.local\n  createGrace: 30s", "kaname.createGrace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(validYAML, tc.old) {
				t.Fatalf("fixture drift: %q is not in the twin", tc.old)
			}
			broken := strings.Replace(validYAML, tc.old, tc.new, 1)
			_, err := Parse([]byte(broken))
			if err == nil {
				t.Fatalf("broken config accepted (%s)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not name %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadReadsTheFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c == nil || c.ClusterName != "system-1" {
		t.Fatalf("Load returned %+v", c)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("Load of an absent file succeeded")
	}
}

func TestVaultPathRendersAndRefusesForeignSegments(t *testing.T) {
	c, err := Parse([]byte(validYAML))
	if err != nil || c == nil {
		t.Fatalf("Parse: %v", err)
	}
	mount, path, err := c.VaultPath("docker-registry", PathParams{
		Namespace: "cust01", Instance: "abc123", Name: "zot-abc123-ci", Key: "push",
	})
	if err != nil {
		t.Fatalf("VaultPath: %v", err)
	}
	if mount != "secret" {
		t.Errorf("mount = %q", mount)
	}
	want := "clusters/system-1/namespaces/cust01/apps/docker-registry/abc123/robots/zot-abc123-ci/push"
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if _, _, err := c.VaultPath("unknown-app", PathParams{Namespace: "a", Instance: "b", Name: "c", Key: "d"}); err == nil {
		t.Error("unknown app accepted")
	}
	for _, bad := range []PathParams{
		{Namespace: "a/b", Instance: "b", Name: "c", Key: "d"},
		{Namespace: "a", Instance: "..", Name: "c", Key: "d"},
		{Namespace: "a", Instance: "b", Name: "", Key: "d"},
		{Namespace: "a", Instance: "b", Name: "c", Key: "D"},
	} {
		if _, _, err := c.VaultPath("docker-registry", bad); err == nil {
			t.Errorf("segment %+v accepted", bad)
		}
	}
}
