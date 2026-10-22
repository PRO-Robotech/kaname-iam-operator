// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/fakes/kanamefake"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/fakes/vaultfake"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/vault"
)

// Пробы протокола ключа (⛔1) прямыми проходами реконсиляции: без менеджера
// в фоне, поэтому состояние «падения между шагами» собирается точно и ни один
// проход не идёт мимо пробы.

type protoHarness struct {
	r        *ServiceAccountReconciler
	c        client.Client
	k        *kanamefake.Server
	v        *vaultfake.Server
	clk      *clocktesting.FakePassiveClock
	key      types.NamespacedName
	account  string
	failNext atomic.Int32
}

const protoNS = "cust01"

func newProtoHarness(t *testing.T) *protoHarness {
	t.Helper()
	h := &protoHarness{clk: clocktesting.NewFakePassiveClock(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)), account: "acc1"}
	h.k = kanamefake.New()
	h.k.SetNow(h.clk.Now)
	h.k.AddAccount(h.account)
	kSrv := httptest.NewTLSServer(h.k.Handler())
	t.Cleanup(kSrv.Close)
	h.v = vaultfake.New("kubernetes", "kaname-iam-operator", func(mount, path string) bool { return mount == vaultMount })
	vSrv := httptest.NewTLSServer(h.v)
	t.Cleanup(vSrv.Close)

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
clusterName: %s
kaname: {apiURL: %s, audience: https://kaname.local}
vault: {address: %s, authMount: kubernetes, role: kaname-iam-operator, tokenPath: /t}
policy: {allowedRoles: [registry.pusher]}
delivery:
  vault:
    docker-registry:
      mount: %s
      pathTemplate: clusters/{cluster}/namespaces/{namespace}/apps/docker-registry/{instance}/robots/{name}/{key}
`, clusterName, kSrv.URL, vSrv.URL, vaultMount)))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	tokens := kaname.NewFederatedTokenSource(kaname.FederatedTokenSourceOptions{
		TokenURL: cfg.Kaname.TokenURL, HTTPClient: kSrv.Client(), CallTimeout: 2 * time.Second, Now: h.clk.Now,
		Assertions: assertionFunc(func() string { n++; return fmt.Sprintf("a-%d", n) }),
	})
	kc, err := kaname.New(kaname.Options{BaseURL: cfg.Kaname.APIURL, HTTPClient: kSrv.Client(), Tokens: tokens, CallTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	vc, err := vault.New(vault.Options{
		Address: cfg.Vault.Address, HTTPClient: vSrv.Client(), AuthMount: "kubernetes", Role: "kaname-iam-operator",
		JWT: func() (string, error) { return "jwt", nil }, CallTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = iamv1alpha1.AddToScheme(scheme)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: protoNS, Annotations: map[string]string{
		iamv1alpha1.AnnotationAccountID: h.account, iamv1alpha1.AnnotationProjectID: "prj1",
	}}}
	sa := newSA(tenant{ns: protoNS}, "zot-ci", pushKey())
	sa.UID = "uid-zot-ci"
	sa.Generation = 1
	sa.Spec.Keys[0].Kind = iamv1alpha1.KeyKindSecret
	sa.Spec.Keys[0].TTLSeconds = 7200
	sa.Spec.Keys[0].Rotation = iamv1alpha1.KeyRotation{RenewBeforeSeconds: ptr.To[int64](1800), OverlapSeconds: ptr.To[int64](600)}
	h.key = client.ObjectKeyFromObject(sa)
	h.c = fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, sa).
		WithStatusSubresource(&iamv1alpha1.ServiceAccount{}).
		WithIndex(&iamv1alpha1.AccessBinding{}, indexBindingSA, func(o client.Object) []string {
			return referencedServiceAccounts(o.(*iamv1alpha1.AccessBinding))
		}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				if h.failNext.Load() > 0 {
					h.failNext.Add(-1)
					return apierrors.NewConflict(schema.GroupResource{Group: "iam.kaname.in-cloud.io", Resource: "serviceaccounts"}, obj.GetName(), fmt.Errorf("injected"))
				}
				return c.SubResource(sub).Update(ctx, obj, opts...)
			},
		}).Build()
	h.r = &ServiceAccountReconciler{Client: h.c, Deps: &Deps{
		Kaname: kc, Vault: vc, Config: cfg, Recorder: &events.FakeRecorder{}, Clock: h.clk, DriftInterval: time.Minute,
	}}
	return h
}

// settle гонит проходы, пока реконсиляция просит следующий сразу.
func (h *protoHarness) settle(t *testing.T) ctrl.Result {
	t.Helper()
	var res ctrl.Result
	for i := 0; i < 40; i++ {
		var err error
		res, err = h.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: h.key})
		if err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		if res.RequeueAfter != requeueNow {
			return res
		}
	}
	t.Fatal("reconcile did not settle within 40 passes")
	return res
}

func (h *protoHarness) sa(t *testing.T) *iamv1alpha1.ServiceAccount {
	t.Helper()
	out := &iamv1alpha1.ServiceAccount{}
	if err := h.c.Get(context.Background(), h.key, out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (h *protoHarness) setStatus(t *testing.T, mutate func(*iamv1alpha1.ServiceAccountStatus)) {
	t.Helper()
	cur := h.sa(t)
	mutate(&cur.Status)
	if err := h.c.Status().Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
}

func (h *protoHarness) issueCalls() int {
	n := 0
	for _, c := range h.k.Calls() {
		if strings.HasPrefix(c, "POST ") && strings.HasSuffix(c, "/keys") {
			n++
		}
	}
	return n
}

func (h *protoHarness) path() string {
	return fmt.Sprintf("clusters/%s/namespaces/%s/apps/docker-registry/abc123/robots/zot-ci/push", clusterName, protoNS)
}

func (h *protoHarness) ready(t *testing.T) *iamv1alpha1.ServiceAccount {
	t.Helper()
	h.settle(t)
	sa := h.sa(t)
	if err := wantCondition(sa.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, ""); err != nil {
		t.Fatal(err)
	}
	return sa
}

func (h *protoHarness) ownKeyLabels(nonce string) map[string]string {
	return map[string]string{
		iamv1alpha1.LabelOwnerUID: "uid-zot-ci", iamv1alpha1.LabelCluster: clusterName,
		iamv1alpha1.LabelKeyName: "push", iamv1alpha1.LabelKeyNonce: nonce,
	}
}

// Падение между записью Vault и записью status: запись Vault с нашим nonce —
// выпуск совершён, status дочитывается, нового выпуска нет.
func TestKeyProtocolFinishesFromVaultAfterACrashBeforeStatus(t *testing.T) {
	h := newProtoHarness(t)
	sa := h.ready(t)
	old := sa.Status.KeyStatusByName("push")
	expires := h.clk.Now().Add(2 * time.Hour)
	k := h.k.PutKey(&iamv1.ServiceAccountOAuthClient{SvaId: sa.Status.ID, Labels: h.ownKeyLabels("n-crash"),
		CredentialKind: iamv1.CredentialKind_CREDENTIAL_KIND_SECRET, ExpiresAt: tsOf(expires)})
	_, ver := h.v.Get(vaultMount, h.path())
	h.v.Put(vaultMount, h.path(), map[string]string{
		vaultUsername: k, vaultKeyID: k, vaultPassword: "kacho_x", vaultSAID: sa.Status.ID, vaultNonce: "n-crash",
	})
	h.setStatus(t, func(st *iamv1alpha1.ServiceAccountStatus) {
		st.Keys[0].Issuing = &iamv1alpha1.KeyIssuing{Nonce: "n-crash", At: metav1.NewTime(h.clk.Now())}
	})
	issues := h.issueCalls()
	h.settle(t)
	ks := h.sa(t).Status.KeyStatusByName("push")
	if ks.KeyID != k || ks.Issuing != nil || ks.VaultVersion != int64(ver+1) {
		t.Fatalf("key status = %+v (want key %s at version %d)", ks, k, ver+1)
	}
	if ks.Previous == nil || ks.Previous.KeyID != old.KeyID {
		t.Fatalf("previous = %+v, want %s", ks.Previous, old.KeyID)
	}
	if h.issueCalls() != issues {
		t.Fatal("a new key was issued although the crashed issuance had completed")
	}
}

// Падение между выпуском и записью Vault: секрет потерян. В окне уборки
// выпуска нет; после окна — новый nonce, новый ключ, потерянный отозван.
func TestKeyProtocolLostSecretWaitsTheGraceThenReissues(t *testing.T) {
	h := newProtoHarness(t)
	sa := h.ready(t)
	old := sa.Status.KeyStatusByName("push").KeyID
	lost := h.k.PutKey(&iamv1.ServiceAccountOAuthClient{SvaId: sa.Status.ID, Labels: h.ownKeyLabels("n-lost"),
		CredentialKind: iamv1.CredentialKind_CREDENTIAL_KIND_SECRET, ExpiresAt: tsOf(h.clk.Now().Add(2 * time.Hour))})
	h.setStatus(t, func(st *iamv1alpha1.ServiceAccountStatus) {
		st.Keys[0].Issuing = &iamv1alpha1.KeyIssuing{Nonce: "n-lost", At: metav1.NewTime(h.clk.Now())}
	})
	issues := h.issueCalls()
	res := h.settle(t)
	if h.issueCalls() != issues {
		t.Fatal("reissued inside the grace window")
	}
	if res.RequeueAfter <= 0 || res.RequeueAfter > grace {
		t.Fatalf("requeue after %s, want the rest of the grace window", res.RequeueAfter)
	}
	if err := wantCondition(h.sa(t).Status.Conditions, iamv1alpha1.ConditionKeysReady, metav1.ConditionFalse, iamv1alpha1.ReasonKeysIssuing); err != nil {
		t.Fatal(err)
	}
	h.clk.SetTime(h.clk.Now().Add(grace + time.Second))
	h.settle(t)
	ks := h.sa(t).Status.KeyStatusByName("push")
	if ks.KeyID == "" || ks.KeyID == lost || ks.KeyID == old || ks.Issuing != nil {
		t.Fatalf("key status = %+v", ks)
	}
	data, _ := h.v.Get(vaultMount, h.path())
	if data[vaultKeyID] != ks.KeyID || data[vaultNonce] == "n-lost" {
		t.Fatalf("vault record = keyId %q nonce %q", data[vaultKeyID], data[vaultNonce])
	}
	for _, k := range h.k.Keys(sa.Status.ID) {
		if k.GetId() == lost {
			t.Fatal("the lost key was not revoked")
		}
	}
}

// Намерение не записано (конфликт версии) — выпуска нет.
func TestKeyProtocolIntentPrecedesTheIssue(t *testing.T) {
	h := newProtoHarness(t)
	h.settle(t) // учётка заведена, ключ выпущен
	sa := h.sa(t)
	issues := h.issueCalls()
	h.clk.SetTime(h.clk.Now().Add(91 * time.Minute)) // окно замены: 2 ч − 30 мин
	h.failNext.Store(1)
	if _, err := h.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: h.key}); err != nil {
		t.Fatal(err)
	}
	if h.issueCalls() != issues {
		t.Fatal("key issued although the intent was not recorded")
	}
	// Законный близнец: та же замена без конфликта выпускает ключ.
	h.settle(t)
	if h.issueCalls() != issues+1 {
		t.Fatalf("issues = %d, want %d", h.issueCalls(), issues+1)
	}
	if ks := h.sa(t).Status.KeyStatusByName("push"); ks.Previous == nil || ks.Previous.KeyID != sa.Status.KeyStatusByName("push").KeyID {
		t.Fatalf("rotation did not keep the previous key: %+v", ks)
	}
}

// Выпуск с записанным nonce: ключ kaname несёт тот nonce, что в status.
func TestKeyProtocolIssuesWithTheRecordedNonce(t *testing.T) {
	h := newProtoHarness(t)
	id := h.k.PutServiceAccount(&iamv1.ServiceAccount{AccountId: h.account, Name: "zot-ci", Enabled: true, Description: "CI robot",
		Labels: map[string]string{iamv1alpha1.LabelOwnerUID: "uid-zot-ci", iamv1alpha1.LabelCluster: clusterName,
			iamv1alpha1.LabelRef: protoNS + ".zot-ci", "registry": "abc123"}})
	h.setStatus(t, func(st *iamv1alpha1.ServiceAccountStatus) {
		st.ID, st.AccountID = id, h.account
		st.Keys = []iamv1alpha1.KeyStatus{{Name: "push", Issuing: &iamv1alpha1.KeyIssuing{Nonce: "n-recorded", At: metav1.NewTime(h.clk.Now())}}}
	})
	h.settle(t)
	keys := h.k.Keys(id)
	if len(keys) != 1 || keys[0].GetLabels()[iamv1alpha1.LabelKeyNonce] != "n-recorded" {
		t.Fatalf("keys = %v", keys)
	}
	if data, _ := h.v.Get(vaultMount, h.path()); data[vaultNonce] != "n-recorded" {
		t.Fatalf("vault nonce = %q", data[vaultNonce])
	}
}

// Уборка: свой ключ вне status старше окна — отозван; моложе — оставлен до
// конца окна; чужой ключ — не тронут никогда.
func TestKeyProtocolSweepTouchesOnlyOwnStrays(t *testing.T) {
	h := newProtoHarness(t)
	sa := h.ready(t)
	foreign := h.k.PutKey(&iamv1.ServiceAccountOAuthClient{SvaId: sa.Status.ID, Labels: map[string]string{"team": "a"},
		CreatedAt: tsOf(h.clk.Now().Add(-24 * time.Hour))})
	oldStray := h.k.PutKey(&iamv1.ServiceAccountOAuthClient{SvaId: sa.Status.ID, Labels: h.ownKeyLabels("n-old"),
		CreatedAt: tsOf(h.clk.Now().Add(-grace - time.Minute))})
	youngStray := h.k.PutKey(&iamv1.ServiceAccountOAuthClient{SvaId: sa.Status.ID, Labels: h.ownKeyLabels("n-young"),
		CreatedAt: tsOf(h.clk.Now())})
	h.settle(t)
	has := func(id string) bool {
		for _, k := range h.k.Keys(sa.Status.ID) {
			if k.GetId() == id {
				return true
			}
		}
		return false
	}
	if has(oldStray) {
		t.Error("own stray older than the grace window survived")
	}
	if !has(youngStray) {
		t.Error("own stray inside the grace window was revoked")
	}
	if !has(foreign) {
		t.Error("foreign key was revoked")
	}
	h.clk.SetTime(h.clk.Now().Add(grace + time.Second))
	h.settle(t)
	if has(youngStray) {
		t.Error("own stray survived its grace window")
	}
	if !has(foreign) {
		t.Error("foreign key was revoked after the grace window")
	}
}

// Vault недоступен до выпуска — выпуска нет: секрет не рождается, если его
// некуда положить.
func TestKeyProtocolDoesNotIssueWhileVaultIsDown(t *testing.T) {
	h := newProtoHarness(t)
	// Учётка заведена, Vault падает до первого ключа.
	id := h.k.PutServiceAccount(&iamv1.ServiceAccount{AccountId: h.account, Name: "zot-ci", Enabled: true, Description: "CI robot",
		Labels: map[string]string{iamv1alpha1.LabelOwnerUID: "uid-zot-ci", iamv1alpha1.LabelCluster: clusterName,
			iamv1alpha1.LabelRef: protoNS + ".zot-ci", "registry": "abc123"}})
	h.setStatus(t, func(st *iamv1alpha1.ServiceAccountStatus) { st.ID, st.AccountID = id, h.account })
	h.v.FailNext(100)
	for range 3 {
		_, _ = h.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: h.key})
	}
	if h.issueCalls() != 0 {
		t.Fatal("key issued while Vault was unavailable")
	}
	if err := wantCondition(h.sa(t).Status.Conditions, iamv1alpha1.ConditionKeysReady, metav1.ConditionFalse, iamv1alpha1.ReasonVaultUnavailable); err != nil {
		t.Fatal(err)
	}
	// Законный близнец: Vault ожил — ключ выпущен и доставлен.
	h.v.FailNext(0)
	h.settle(t)
	if h.issueCalls() != 1 {
		t.Fatalf("issues = %d", h.issueCalls())
	}
}

// Запись Vault отказала после выпуска: секрет потерян, выпуск повторяется
// после окна уборки, потерянный ключ отзывается — без второго действующего.
func TestKeyProtocolVaultFailureAfterIssueConverges(t *testing.T) {
	h := newProtoHarness(t)
	h.k.OnIssue(func(string) { h.v.FailNext(10) })
	for range 5 {
		_, _ = h.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: h.key})
	}
	h.k.OnIssue(nil)
	h.v.FailNext(0)
	sa := h.sa(t)
	if sa.Status.ID == "" {
		t.Fatal("account not created")
	}
	lost := h.k.Keys(sa.Status.ID)
	if len(lost) != 1 {
		t.Fatalf("keys after the failed delivery = %v", lost)
	}
	h.clk.SetTime(h.clk.Now().Add(grace + time.Second))
	h.settle(t)
	keys := h.k.Keys(sa.Status.ID)
	ks := h.sa(t).Status.KeyStatusByName("push")
	if len(keys) != 1 || keys[0].GetId() == lost[0].GetId() || keys[0].GetId() != ks.KeyID {
		t.Fatalf("keys = %v, status key %q", keys, ks.KeyID)
	}
	if data, _ := h.v.Get(vaultMount, h.path()); data[vaultKeyID] != ks.KeyID {
		t.Fatalf("vault holds %q", data[vaultKeyID])
	}
}

func tsOf(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }
