//go:build integration

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
)

// platformUser — принципал платформы прогона: только он ставит субъектов
// user/group и цель «вся область».
const platformUser = "system:serviceaccount:platform-system:onboarding"

// guardNames — политики допуска чарта, которые оператор сверяет как гарантию
// подлинности created-by (policy.admissionGuard отрендеренной конфигурации).
var guardNames []string

// envtestAdmin — пользователь администратора envtest: писатель чарта, но не
// принципал платформы.
var envtestAdmin string

// installAdmission ставит в envtest ValidatingAdmissionPolicy ЧАРТА — те же,
// что уезжают в кластер, — с писателями прогона: администратор envtest (им
// пишут пробы и менеджер оператора) и принципал платформы. Выдачу на всю
// область и субъекта user пропускает только допуск чарта, и оператор
// принимает их только при этой гарантии.
func installAdmission(ctx context.Context) int {
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return notExecuted("clientset: %v", err)
	}
	review, err := cs.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil || review.Status.UserInfo.Username == "" {
		return notExecuted("envtest admin user name: %v", err)
	}
	adminUser := review.Status.UserInfo.Username
	envtestAdmin = adminUser
	list := func(v ...string) string {
		b, _ := json.Marshal(v)
		return string(b)
	}
	out, err := exec.CommandContext(ctx, "helm", "template", "kio", filepath.Join("..", "..", "charts", "kaname-iam-operator"),
		"--namespace", itNS, "-f", filepath.Join("..", "admission", "testdata", "values.yaml"),
		"--set-json", "admission.writers="+list(adminUser, platformUser),
		"--set-json", "admission.statusWriters="+list(adminUser),
		"--set-json", "config.policy.platformPrincipals="+list(platformUser),
		"--set-json", "config.policy.allowedRoles="+list(env["KIO_IT_ROLE"], pusherRole),
		"--set-json", "config.policy.systemClassRoles=[]",
	).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return notExecuted("helm template: %v: %s", err, ee.Stderr)
		}
		return notExecuted("helm template: %v", err)
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(out), 4096)
	installed := 0
	for {
		u := &unstructured.Unstructured{}
		if err := dec.Decode(&u.Object); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return notExecuted("decode chart: %v", err)
		}
		switch {
		case strings.HasPrefix(u.GetKind(), "ValidatingAdmissionPolicy"):
			if err := k8s.Create(ctx, u); err != nil {
				return notExecuted("apply %s %s: %v", u.GetKind(), u.GetName(), err)
			}
			obj := u.DeepCopy()
			cleanups = append(cleanups, func() { _ = k8s.Delete(context.Background(), obj) })
			installed++
		case u.GetKind() == "ConfigMap" && strings.HasSuffix(u.GetName(), "-config"):
			raw, _, _ := unstructured.NestedString(u.Object, "data", "config.yaml")
			c, err := config.Parse([]byte(raw))
			if err != nil {
				return notExecuted("rendered config: %v", err)
			}
			guardNames = c.Policy.AdmissionGuard
		}
	}
	if installed != 6 || len(guardNames) == 0 {
		return notExecuted("chart rendered %d admission objects (want 6) and admissionGuard %v", installed, guardNames)
	}
	fmt.Printf("integration: admission policies of the chart installed (%d objects), guard %v, writers %s, platform %s\n",
		installed, guardNames, list(adminUser, platformUser), platformUser)
	return 0
}

// as — клиент envtest от имени user. Группа system:masters даёт право RBAC, но
// не снимает допуска: политики судят имя пользователя.
func as(user string) (client.Client, error) {
	cfg := rest.CopyConfig(restCfg)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: []string{"system:masters", "system:authenticated"}}
	return client.New(cfg, client.Options{Scheme: scheme})
}
