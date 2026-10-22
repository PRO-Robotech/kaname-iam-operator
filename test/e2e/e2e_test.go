//go:build e2e

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package e2e_test — установка чарта в kind: образ собирается и загружается,
// чарт ставится, Deployment доходит до rollout ready (страж конфигурации не
// отказал), Lease держит ровно один лидер, политики допуска проходят проверку
// типов kube-controller-manager и действуют, у оператора хватает прав
// довести CR до записанного status. kaname и Vault в этой пробе недостижимы
// намеренно: проба судит посадку, а не обмен с ними (его судит integration).
package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	ns      = "kaname-iam-system"
	release = "kio"
	tenant  = "e2e-tenant"
	writer  = "system:serviceaccount:registry-system:registry-operator"
)

var (
	img     = os.Getenv("IMG")
	cluster = os.Getenv("KIND_CLUSTER")
	kind    = envOr("KIND", "kind")
	root    = filepath.Join("..", "..")
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = root
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s%s", name, strings.Join(args, " "), err, out.String(), errb.String())
	}
	return out.String()
}

func try(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func kubectl(t *testing.T, args ...string) string {
	t.Helper()
	return run(t, "kubectl", append([]string{"--context", "kind-" + cluster}, args...)...)
}

func kubectlTry(args ...string) (string, error) {
	return try("kubectl", append([]string{"--context", "kind-" + cluster}, args...)...)
}

func eventually(t *testing.T, d time.Duration, check func() error) {
	t.Helper()
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		if last = check(); last == nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("not reached within %s: %v", d, last)
}

func TestInstallAndOperate(t *testing.T) {
	if img == "" || cluster == "" {
		t.Fatal("IMG and KIND_CLUSTER must be set (make test-e2e)")
	}
	run(t, "make", "docker-build", "IMG="+img)
	run(t, kind, "load", "docker-image", img, "--name", cluster)
	repo, tag, _ := strings.Cut(img, ":")
	run(t, "helm", "upgrade", "--install", release, "charts/kaname-iam-operator",
		"--kube-context", "kind-"+cluster, "--namespace", ns, "--create-namespace",
		"-f", "test/e2e/testdata/values.yaml",
		"--set", "image.repository="+repo, "--set", "image.tag="+tag, "--set", "image.pullPolicy=Never",
		"--wait", "--timeout", "5m")

	t.Run("rollout ready", func(t *testing.T) {
		kubectl(t, "-n", ns, "rollout", "status", "deploy/kaname-iam-operator", "--timeout=180s")
	})

	// Виды группы адресуются kubectl без группы и ни с чем не совпадают:
	// короткие имена разрешаются, перепись группы — ровно два ресурса с
	// префиксом IAM, а serviceaccount по-прежнему — core v1.
	t.Run("kinds resolve without the group", func(t *testing.T) {
		got := strings.Fields(kubectl(t, "api-resources", "--api-group=iam.kaname.in-cloud.io", "-o", "name"))
		slices.Sort(got)
		want := []string{"iamaccessbindings.iam.kaname.in-cloud.io", "iamserviceaccounts.iam.kaname.in-cloud.io"}
		if !slices.Equal(got, want) {
			t.Fatalf("api-resources of the group = %v, want %v", got, want)
		}
		for _, short := range []string{"iamsa", "iamab", "iamserviceaccount", "iamaccessbinding"} {
			kubectl(t, "get", short, "-A")
		}
		if v := kubectl(t, "-n", ns, "get", "serviceaccount", "kaname-iam-operator", "-o", "jsonpath={.apiVersion}"); strings.TrimSpace(v) != "v1" {
			t.Fatalf("kubectl get serviceaccount resolves to %q, want core v1", v)
		}
	})

	t.Run("exactly one leader", func(t *testing.T) {
		eventually(t, 2*time.Minute, func() error {
			out, err := kubectlTry("-n", ns, "get", "lease", "kaname-iam-operator.iam.kaname.in-cloud.io", "-o", "jsonpath={.spec.holderIdentity}")
			if err != nil || strings.TrimSpace(out) == "" {
				return fmt.Errorf("lease holder %q: %w", out, err)
			}
			return nil
		})
	})

	t.Run("admission policies type-check cleanly", func(t *testing.T) {
		eventually(t, 2*time.Minute, func() error {
			out, err := kubectlTry("get", "validatingadmissionpolicies", "-o", "json")
			if err != nil {
				return err
			}
			var list struct {
				Items []struct {
					Metadata struct{ Name string }
					Status   struct {
						TypeChecking *struct {
							ExpressionWarnings []struct{ FieldRef, Warning string } `json:"expressionWarnings"`
						} `json:"typeChecking"`
					}
				}
			}
			if err := json.Unmarshal([]byte(out), &list); err != nil {
				return err
			}
			checked := 0
			for _, p := range list.Items {
				if !strings.HasPrefix(p.Metadata.Name, "kaname-iam-operator-") {
					continue
				}
				if p.Status.TypeChecking == nil {
					return fmt.Errorf("policy %s not type-checked yet", p.Metadata.Name)
				}
				for _, w := range p.Status.TypeChecking.ExpressionWarnings {
					t.Errorf("policy %s: %s: %s", p.Metadata.Name, w.FieldRef, w.Warning)
				}
				checked++
			}
			if checked != 3 {
				return fmt.Errorf("type-checked %d of 3 policies", checked)
			}
			return nil
		})
	})

	t.Run("writers and strangers", func(t *testing.T) {
		kubectl(t, "create", "namespace", tenant)
		kubectl(t, "annotate", "namespace", tenant, "iam.kaname.in-cloud.io/account-id=acc-e2e", "iam.kaname.in-cloud.io/project-id=prj-e2e")
		manifest := `apiVersion: iam.kaname.in-cloud.io/v1alpha1
kind: IAMServiceAccount
metadata: {name: e2e, namespace: ` + tenant + `}
spec: {name: e2e-robot, deletionPolicy: Orphan}
`
		path := filepath.Join(t.TempDir(), "sa.yaml")
		if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := kubectlTry("--as", "system:serviceaccount:"+tenant+":default", "--as-group", "system:masters", "apply", "-f", path)
		if err == nil || !strings.Contains(out, "may not CREATE") {
			t.Fatalf("stranger create: %v %s", err, out)
		}
		kubectl(t, "--as", writer, "--as-group", "system:masters", "apply", "-f", path)
		// Оператор доводит CR до записанного status: финализатор и условия
		// (kaname недостижим — Synced/Ready False с причиной повтора).
		eventually(t, 3*time.Minute, func() error {
			out, err := kubectlTry("-n", tenant, "get", "iamserviceaccounts.iam.kaname.in-cloud.io", "e2e",
				"-o", `jsonpath={.metadata.finalizers}{"|"}{.status.conditions[?(@.type=="Ready")].reason}`)
			if err != nil {
				return err
			}
			if !strings.Contains(out, "iam.kaname.in-cloud.io/finalizer") || strings.HasSuffix(out, "|") {
				return fmt.Errorf("finalizer|ready reason = %q", out)
			}
			return nil
		})
		kubectl(t, "--as", writer, "--as-group", "system:masters", "-n", tenant, "delete", "iamserviceaccounts.iam.kaname.in-cloud.io", "e2e", "--timeout=120s")
	})
}
