// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/fakes/kanamefake"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/fakes/vaultfake"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/policy"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/vault"
)

// Общий стенд пакета: envtest, двойники kaname и Vault, менеджер с обоими
// контроллерами. Каждая проба работает в своих namespace и аккаунте.
var (
	k8s      client.Client
	fakeK    *kanamefake.Server
	fakeV    *vaultfake.Server
	clk      *clocktesting.FakePassiveClock
	testCfg  *config.Config
	restCfg  *rest.Config
	testRole = map[string]string{}
	// recorded — события оператора пакета: пробы судят по ним то, что
	// оператор сообщает наружу.
	recorded = &eventLog{}
	// testSeal — печать свидетельства допуска оператора пакета.
	testSeal = func() *policy.WitnessSeal {
		s, err := policy.NewWitnessSeal(bytes.Repeat([]byte{7}, policy.WitnessKeyBytes))
		if err != nil {
			panic(err)
		}
		return s
	}()

	scheme       = runtime.NewScheme()
	kanameCli    *kaname.Client
	vaultCli     *vault.Client
	stopOperator = func() {}
)

const (
	clusterName = "c1"
	vaultMount  = "secret"
	grace       = 10 * time.Minute
)

func TestMain(m *testing.M) {
	os.Exit(runSuite(m))
}

func runSuite(m *testing.M) int {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		fmt.Fprintln(os.Stderr, "controller suite: KUBEBUILDER_ASSETS is not set — run through `make test`; the suite is NOT executed")
		return 3
	}
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(os.Stderr), zap.Level(zapLevel())))
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases"), filepath.Join("testdata", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest start:", err)
		return 1
	}
	defer func() { _ = env.Stop() }()
	restCfg = cfg

	_ = clientgoscheme.AddToScheme(scheme)
	_ = iamv1alpha1.AddToScheme(scheme)

	clk = clocktesting.NewFakePassiveClock(time.Now().UTC().Truncate(time.Second))
	fakeK = kanamefake.New()
	fakeK.SetNow(clk.Now)
	for _, r := range []string{"registry.pusher", "registry.puller", "registry.public.read", "registry.admin"} {
		testRole[r] = fakeK.AddRole(r, true)
	}
	kSrv := httptest.NewTLSServer(fakeK.Handler())
	defer kSrv.Close()

	fakeV = vaultfake.New("kubernetes", "kaname-iam-operator", func(mount, path string) bool {
		return mount == vaultMount && strings.HasPrefix(path, "clusters/"+clusterName+"/")
	})
	vSrv := httptest.NewTLSServer(fakeV)
	defer vSrv.Close()

	testCfg, err = config.Parse([]byte(fmt.Sprintf(`
clusterName: %s
kaname:
  apiURL: %s
  audience: https://kaname.local
vault:
  address: %s
  authMount: kubernetes
  role: kaname-iam-operator
  tokenPath: /var/run/secrets/vault/token
policy:
  allowedRoles: [registry.puller, registry.pusher, registry.public.read]
  systemClassRoles: [registry.public.read]
  platformPrincipals: ["system:serviceaccount:platform-system:onboarding"]
  admissionGuard: [kio-test-writers, kio-test-bindings]
  # Срок вступления политики в силу — наименьший допустимый: часы оператора
  # пробы ненастоящие, и срок переводят пробы (inForce), а старшинство
  # политики над объектом судится по отметкам kube-apiserver (predate).
  admissionEnforcementDelay: 1s
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
      mount: %s
      pathTemplate: clusters/{cluster}/namespaces/{namespace}/apps/docker-registry/{instance}/robots/{name}/{key}
`, clusterName, kSrv.URL, vSrv.URL, vaultMount)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}

	n := 0
	tokens := kaname.NewFederatedTokenSource(kaname.FederatedTokenSourceOptions{
		TokenURL: testCfg.Kaname.TokenURL, HTTPClient: kSrv.Client(),
		Assertions:  assertionFunc(func() string { n++; return fmt.Sprintf("assertion-%d", n) }),
		CallTimeout: 2 * time.Second, Now: clk.Now,
	})
	kc, err := kaname.New(kaname.Options{BaseURL: testCfg.Kaname.APIURL, HTTPClient: kSrv.Client(), Tokens: tokens, CallTimeout: 2 * time.Second})
	if err != nil {
		fmt.Fprintln(os.Stderr, "kaname client:", err)
		return 1
	}
	vc, err := vault.New(vault.Options{
		Address: testCfg.Vault.Address, HTTPClient: vSrv.Client(), AuthMount: "kubernetes", Role: "kaname-iam-operator",
		JWT: func() (string, error) { return "projected", nil }, CallTimeout: 2 * time.Second,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "vault client:", err)
		return 1
	}

	kanameCli, vaultCli = kc, vc
	stop, err := startOperator(testCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	stopOperator = stop
	defer func() { stopOperator() }()
	k8s, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		return 1
	}
	return m.Run()
}

// startOperator запускает менеджер с обоими контроллерами по конфигурации
// cfg; stop останавливает его и ждёт, пока проходы допишут.
func startOperator(cfg *config.Config) (stop func(), err error) {
	// Имена контроллеров у перезапущенного менеджера те же, что у прежнего.
	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		Controller: crconfig.Controller{SkipNameValidation: ptr.To(true)}})
	if err != nil {
		return nil, fmt.Errorf("manager: %w", err)
	}
	deps := &Deps{
		Kaname: kanameCli, Vault: vaultCli, Config: cfg, Recorder: recorded,
		Clock: clk, DriftInterval: 500 * time.Millisecond, Seal: testSeal,
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := SetupIndexes(ctx, mgr); err != nil {
		cancel()
		return nil, fmt.Errorf("indexes: %w", err)
	}
	if err := SetupIAMServiceAccountReconciler(mgr, deps); err != nil {
		cancel()
		return nil, fmt.Errorf("SA reconciler: %w", err)
	}
	if err := SetupIAMAccessBindingReconciler(mgr, deps); err != nil {
		cancel()
		return nil, fmt.Errorf("AB reconciler: %w", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := mgr.Start(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "manager stopped:", err)
		}
	}()
	return func() { cancel(); <-done }, nil
}

// restartOperator останавливает оператор и поднимает его по cfg — так
// развёрнутый оператор видит смену своей конфигурации: контрольная сумма
// конфигурации в шаблоне пода перезапускает под.
func restartOperator(t *testing.T, cfg *config.Config) {
	t.Helper()
	stopOperator()
	stop, err := startOperator(cfg)
	if err != nil {
		stopOperator = func() {}
		t.Fatalf("restart operator: %v", err)
	}
	stopOperator = stop
}

// withPolicy перезапускает оператор с политикой пакета, правленной mutate
// (mutate присваивает новые срезы, а не правит общие), и в конце пробы
// возвращает политику пакета.
func withPolicy(t *testing.T, mutate func(*config.Policy)) {
	t.Helper()
	cfg := *testCfg
	mutate(&cfg.Policy)
	restartOperator(t, &cfg)
	t.Cleanup(func() { restartOperator(t, testCfg) })
}

func zapLevel() zapcore.Level {
	if os.Getenv("KIO_TEST_DEBUG") != "" {
		return zapcore.DebugLevel
	}
	return zapcore.ErrorLevel
}

// eventLog — EventRecorder пробы: хранит события с объектом, типом и
// причиной.
type eventLog struct {
	mu    sync.Mutex
	items []recordedEvent
}

type recordedEvent struct {
	object, eventtype, reason, note string
}

var _ events.EventRecorder = (*eventLog)(nil)

func (l *eventLog) Eventf(regarding, _ runtime.Object, eventtype, reason, _, note string, args ...any) {
	name := ""
	if o, ok := regarding.(client.Object); ok {
		name = o.GetNamespace() + "/" + o.GetName()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.items = append(l.items, recordedEvent{object: name, eventtype: eventtype, reason: reason, note: fmt.Sprintf(note, args...)})
}

// of — события объекта obj с причиной reason.
func (l *eventLog) of(obj client.Object, reason string) []recordedEvent {
	name := obj.GetNamespace() + "/" + obj.GetName()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []recordedEvent
	for _, e := range l.items {
		if e.object == name && e.reason == reason {
			out = append(out, e)
		}
	}
	return out
}

type assertionFunc func() string

func (f assertionFunc) Assertion(context.Context) (string, error) { return f(), nil }

func randSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// tenant — namespace арендатора с аккаунтом и проектом в двойнике kaname.
type tenant struct {
	ns, account, project string
}

// newTenant заводит namespace; annotate=false — без аннотаций аккаунта.
func newTenant(t *testing.T, annotate bool) tenant {
	t.Helper()
	tn := tenant{ns: "t-" + randSuffix(), account: "acc" + randSuffix(), project: "prj" + randSuffix()}
	fakeK.AddAccount(tn.account)
	fakeK.AddProject(tn.project, tn.account)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tn.ns}}
	if annotate {
		ns.Annotations = map[string]string{
			iamv1alpha1.AnnotationAccountID: tn.account,
			iamv1alpha1.AnnotationProjectID: tn.project,
		}
	}
	if err := k8s.Create(context.Background(), ns); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	t.Cleanup(func() { _ = k8s.Delete(context.Background(), ns) })
	return tn
}

func annotateTenant(t *testing.T, tn tenant) {
	t.Helper()
	patchObj(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tn.ns}}, func(o client.Object) {
		a := o.GetAnnotations()
		if a == nil {
			a = map[string]string{}
		}
		a[iamv1alpha1.AnnotationAccountID] = tn.account
		a[iamv1alpha1.AnnotationProjectID] = tn.project
		o.SetAnnotations(a)
	})
}

// patchObj читает объект и применяет правку с повтором на конфликт.
func patchObj(t *testing.T, obj client.Object, mutate func(client.Object)) {
	t.Helper()
	ctx := context.Background()
	for range 10 {
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			t.Fatalf("get %s: %v", obj.GetName(), err)
		}
		mutate(obj)
		err := k8s.Update(ctx, obj)
		if err == nil {
			return
		}
		if !apierrors.IsConflict(err) {
			t.Fatalf("update %s: %v", obj.GetName(), err)
		}
	}
	t.Fatalf("update %s: conflicts did not settle", obj.GetName())
}

// eventually повторяет проверку до успеха либо таймаута; на таймауте печатает
// последний отказ проверки.
func eventually(t *testing.T, timeout time.Duration, check func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if last = check(); last == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("condition not reached within %s: %v", timeout, last)
}

// consistently держит проверку всё окно.
func consistently(t *testing.T, window time.Duration, check func() error) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if err := check(); err != nil {
			t.Fatalf("condition broke within %s: %v", window, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func condition(conds []metav1.Condition, typ string) *metav1.Condition {
	return meta.FindStatusCondition(conds, typ)
}

func wantCondition(conds []metav1.Condition, typ string, status metav1.ConditionStatus, reason string) error {
	c := condition(conds, typ)
	if c == nil {
		return fmt.Errorf("condition %s absent (have %v)", typ, conds)
	}
	if c.Status != status || (reason != "" && c.Reason != reason) {
		return fmt.Errorf("condition %s = %s/%s (%s), want %s/%s", typ, c.Status, c.Reason, c.Message, status, reason)
	}
	return nil
}

// touch будит реконсиляцию правкой аннотации.
func touch(t *testing.T, obj client.Object) {
	t.Helper()
	patchObj(t, obj, func(o client.Object) {
		a := o.GetAnnotations()
		if a == nil {
			a = map[string]string{}
		}
		a["test.kaname.in-cloud.io/touch"] = randSuffix()
		o.SetAnnotations(a)
	})
}

func countCalls(prefix string) int {
	n := 0
	for _, c := range fakeK.Calls() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}
