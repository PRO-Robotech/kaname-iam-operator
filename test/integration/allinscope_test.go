//go:build integration

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

// pusherRole — роль модуля registry из доставленного стенду манифеста.
const pusherRole = "registry.pusher"

// materialize — бюджет материализации выдачи и регистрации в kaname: решение
// считается фоном, и выдача аккаунта обходит весь аккаунт.
const materialize = 180 * time.Second

// registrar — внутренний слушатель kaname под личностью модуля registry
// (лист kacho-registry от УЦ стенда, hack/it-stand.sh).
func registrar(t *testing.T) iamv1.InternalIAMServiceClient {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(tlsDir("registry.crt"), tlsDir("registry.key"))
	if err != nil {
		t.Fatalf("registry module leaf: %v", err)
	}
	pool, err := serverPool()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(env["KIO_IT_KANAME_INTERNAL_ADDR"], grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: env["KIO_IT_KANAME_INTERNAL_SERVER_NAME"], MinVersion: tls.VersionTLS12,
	})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return iamv1.NewInternalIAMServiceClient(conn)
}

// registration — объект модуля в kaname: кортеж с родителем и цепь предков,
// той формы, что пишет регистратор svc-registry.
type registration struct {
	object, relation, subject, project string
	chain                              []string
}

func registryOf(id, project string) registration {
	return registration{object: "registry_registry:" + id, relation: "project", subject: "project:" + project,
		project: project, chain: []string{"project:" + project}}
}

func repositoryOf(registryID, repo, project string) registration {
	return registration{object: "registry_repository:" + registryID + "/" + repo, relation: "parent",
		subject: "registry_registry:" + registryID, project: project,
		chain: []string{"registry_registry:" + registryID, "project:" + project}}
}

// register регистрирует объекты и снимает их в конце пробы. Отказ повторяется
// в пределах бюджета: членство личности модуля в группе пишущих кортежи
// материализуется фоном после старта службы.
func register(t *testing.T, rc iamv1.InternalIAMServiceClient, regs ...registration) {
	t.Helper()
	for _, r := range regs {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if _, err := rc.UnregisterResource(ctx, &iamv1.UnregisterResourceRequest{
				SubjectId: r.subject, Relation: r.relation, Object: r.object, ParentProjectId: r.project,
				TraceId: "kio-it-" + run, SourceVersion: timestamppb.Now(),
			}); err != nil {
				t.Logf("unregister %s: %v", r.object, err)
			}
		})
		deadline := time.Now().Add(materialize)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			_, err := rc.RegisterResource(ctx, &iamv1.RegisterResourceRequest{
				SubjectId: r.subject, Relation: r.relation, Object: r.object, ParentProjectId: r.project,
				ParentChain: r.chain, TraceId: "kio-it-" + run, SourceVersion: timestamppb.Now(),
			})
			cancel()
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("register %s within %s: %v", r.object, materialize, err)
			}
			time.Sleep(2 * time.Second)
		}
	}
}

func allowed(t *testing.T, rc iamv1.InternalIAMServiceClient, subject, relation, object string) (bool, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := rc.Check(ctx, &iamv1.CheckRequest{SubjectId: subject, Relation: relation, Object: object, TraceId: "kio-it-" + run})
	if err != nil {
		t.Fatalf("check %s %s %s: %v", subject, relation, object, err)
	}
	return resp.GetAllowed(), resp.GetReason()
}

// eventuallyAllowed ждёт разрешения в пределах бюджета материализации.
func eventuallyAllowed(t *testing.T, rc iamv1.InternalIAMServiceClient, want bool, subject, relation, object string) {
	t.Helper()
	deadline := time.Now().Add(materialize)
	for {
		got, reason := allowed(t, rc, subject, relation, object)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("check %s %s %s = %v within %s, want %v (reason %q)", subject, relation, object, got, materialize, want, reason)
		}
		time.Sleep(2 * time.Second)
	}
}

// human — человек, заведённый полосой входа стенда, и его личный аккаунт с
// проектом: это ДРУГОЙ аккаунт, чем аккаунт выдачи.
func human(ctx context.Context, t *testing.T) (userID, foreignAccount, foreignProject string) {
	t.Helper()
	var users iamv1.ListUsersResponse
	filter := url.QueryEscape(fmt.Sprintf("email=%q", env["KIO_IT_HUMAN_EMAIL"]))
	if err := admin.do(ctx, http.MethodGet, "/iam/v1/users?filter="+filter, nil, &users); err != nil || len(users.GetUsers()) != 1 {
		t.Fatalf("human of the login lane: %v (%d users)", err, len(users.GetUsers()))
	}
	userID = users.GetUsers()[0].GetId()
	var accounts iamv1.ListAccountsResponse
	if err := admin.do(ctx, http.MethodGet, "/iam/v1/accounts?page_size=1000", nil, &accounts); err != nil {
		t.Fatal(err)
	}
	for _, a := range accounts.GetAccounts() {
		if a.GetOwnerUserId() == userID {
			foreignAccount = a.GetId()
		}
	}
	if foreignAccount == "" || foreignAccount == account {
		t.Fatalf("personal account of the human %s: %q (grant account %s)", userID, foreignAccount, account)
	}
	var prj iamv1.Project
	if err := admin.mutate(ctx, http.MethodPost, "/iam/v1/projects",
		&iamv1.CreateProjectRequest{AccountId: foreignAccount, Name: "kio-it-" + run + "-foreign"}, &prj); err != nil {
		t.Fatalf("project in the foreign account: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.mutate(context.Background(), http.MethodDelete, "/iam/v1/projects/"+prj.GetId(), nil, nil)
	})
	return userID, foreignAccount, prj.GetId()
}

// TestAllInScopeAccountGrantReachesEveryRegistryOfTheAccount — выдача на всю
// область аккаунта от принципала платформы: человек с registry.pusher на
// аккаунт получает v_update на репозитории двух реестров аккаунта, в том числе
// реестра, зарегистрированного ПОСЛЕ выдачи; на репозиторий реестра другого
// аккаунта — отказ. Та же выдача от писателя, не являющегося платформой,
// отвергается допуском. Удаление CR отзывает выдачу, и право уходит.
func TestAllInScopeAccountGrantReachesEveryRegistryOfTheAccount(t *testing.T) {
	ctx := context.Background()
	rc := registrar(t)
	userID, foreignAccount, foreignProject := human(ctx, t)
	subject := "user:" + userID

	regA, regB, regC := "kioa"+run, "kiob"+run, "kioc"+run
	repoA, repoB, repoC := "registry_repository:"+regA+"/app", "registry_repository:"+regB+"/app", "registry_repository:"+regC+"/app"
	register(t, rc, registryOf(regA, project), repositoryOf(regA, "app", project),
		registryOf(regC, foreignProject), repositoryOf(regC, "app", foreignProject))
	if got, _ := allowed(t, rc, subject, "v_update", repoA); got {
		t.Fatalf("%s already allowed v_update on %s before any grant: the probe has nothing to measure", subject, repoA)
	}

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "whole-" + run, Annotations: map[string]string{
		iamv1alpha1.AnnotationAccountID: account, iamv1alpha1.AnnotationProjectID: project,
	}}}
	if err := k8s.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8s.Delete(context.Background(), ns) })
	whole := func(name, creator string) *iamv1alpha1.AccessBinding {
		return &iamv1alpha1.AccessBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns.Name,
				Annotations: map[string]string{iamv1alpha1.AnnotationCreatedBy: creator}},
			Spec: iamv1alpha1.AccessBindingSpec{
				Subjects: []iamv1alpha1.Subject{{User: &iamv1alpha1.PrincipalRef{ID: userID}}},
				RoleRef:  iamv1alpha1.RoleRef{Name: pusherRole},
				Scope:    iamv1alpha1.Scope{Type: iamv1alpha1.ScopeAccount},
				Target:   iamv1alpha1.Target{AllInScope: &iamv1alpha1.AllInScope{}},
			},
		}
	}

	// Писатель, не являющийся платформой (администратор envtest — писатель
	// чарта), выдачи на всю область не ставит: отказ допуска.
	err := k8s.Create(ctx, whole("whole-writer", envtestAdmin))
	if err == nil || !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "allInScope") {
		t.Fatalf("allInScope from a non-platform writer: %v, want an admission denial naming allInScope", err)
	}

	platform, err := as(platformUser)
	if err != nil {
		t.Fatal(err)
	}
	ab := whole("whole-pusher", platformUser)
	if err := platform.Create(ctx, ab); err != nil {
		t.Fatalf("allInScope from the platform principal: %v", err)
	}
	t.Cleanup(func() { _ = k8s.Delete(context.Background(), ab) })
	cur := &iamv1alpha1.AccessBinding{}
	eventually(t, func() error {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(ab), cur); err != nil {
			return err
		}
		return ready(cur.Status.Conditions)
	})
	b := binding(t, cur.Status.ID)
	if b.GetStatus() != iamv1.AccessBinding_ACTIVE || b.GetTarget().GetAllInScope() == nil || len(b.GetTarget().GetResources().GetResources()) != 0 ||
		b.GetScopeType() != string(iamv1alpha1.ScopeAccount) || b.GetScopeId() != account {
		t.Fatalf("kaname binding = %v, want an active allInScope binding on account %s", b, account)
	}
	if l := b.GetLabels(); l[iamv1alpha1.LabelOwnerUID] != string(cur.UID) || l[iamv1alpha1.LabelCluster] != cluster {
		t.Fatalf("kaname binding labels = %v", l)
	}

	eventuallyAllowed(t, rc, true, subject, "v_update", repoA)
	// Реестр, зарегистрированный ПОСЛЕ выдачи, покрыт той же выдачей.
	register(t, rc, registryOf(regB, project), repositoryOf(regB, "app", project))
	eventuallyAllowed(t, rc, true, subject, "v_update", repoB)
	// Реестр другого аккаунта выдачей не покрыт: право материализовано на
	// реестрах аккаунта выдачи — значит, и на этом его уже нет.
	if got, reason := allowed(t, rc, subject, "v_update", repoC); got {
		t.Fatalf("%s allowed v_update on %s of account %s: the grant on account %s leaked (reason %q)", subject, repoC, foreignAccount, account, reason)
	}

	// Удаление CR отзывает выдачу, и право уходит.
	if err := platform.Delete(ctx, ab); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() error {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(ab), &iamv1alpha1.AccessBinding{}); !apierrors.IsNotFound(err) {
			return fmt.Errorf("CR still present: %v", err)
		}
		return nil
	})
	if got := binding(t, cur.Status.ID); got.GetStatus() != iamv1.AccessBinding_REVOKED {
		t.Fatalf("binding after deletion = %s", got.GetStatus())
	}
	eventuallyAllowed(t, rc, false, subject, "v_update", repoA)
	eventuallyAllowed(t, rc, false, subject, "v_update", repoB)
}
