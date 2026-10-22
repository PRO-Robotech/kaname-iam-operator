//go:build integration

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package integration_test — проба оператора против НАСТОЯЩИХ kaname и Vault.
//
// kaname — стенд kaname @93ad1b88 (доступ — переадресация портов, которую
// поднимает hack/it-stand.sh); Vault — контейнер testcontainers; k8s —
// envtest. Вход оператора в kaname — FEDERATED: утверждение TokenRequest
// envtest обменивается на токен kaname, издатель envtest заведён в kaname
// доверенным на время прогона. Всё заведённое прогон снимает сам, в том числе
// на падении, и в конце сверяет перепись остатков.
package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/controller"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/vault"
)

// Окружение стенда. Адресов и учётных данных в дереве нет: их ставит
// hack/it-stand.sh из своего контекста кластера.
var standEnv = []string{
	"KIO_IT_KANAME_REST_URL",         // origin REST-фронта kaname
	"KIO_IT_KANAME_TOKEN_URL",        // токен-эндпоинт kaname
	"KIO_IT_KANAME_INTERNAL_ADDR",    // host:port внутреннего gRPC (чеканка бутстрапа)
	"KIO_IT_KANAME_TLS_DIR",          // boot-tls.crt, boot-tls.key, server-ca.crt
	"KIO_IT_KANAME_REST_SERVER_NAME", // имя сертификата REST-фронта и токен-эндпоинта
	"KIO_IT_KANAME_INTERNAL_SERVER_NAME",
	"KIO_IT_ASSERTION_AUDIENCE", // идентификатор издателя kaname (aud утверждения)
	"KIO_IT_TOKEN_AUDIENCE",     // адресат REST-фронта (audience обмена)
	"KIO_IT_ROLE",               // роль, чьи правила покрывают тип цели
	"KIO_IT_TARGET_TYPE",        // тип цели выдачи
}

const (
	itNS        = "kio-it"
	operatorSA  = "kaname-iam-operator"
	vaultRole   = "kaname-iam-operator"
	vaultMount  = "secret"
	vaultImage  = "hashicorp/vault:1.20.1"
	tenantNSKey = "tenant"
)

var (
	env      map[string]string
	run      string
	cluster  string
	issuer   string
	restCfg  *rest.Config
	k8s      client.Client
	opClient *kaname.Client
	admin    *adminClient
	account  string
	project  string
	opSAID   string
	vaultCli *vault.Client
	vaultAPI *vaultAdmin
	scheme   = runtime.NewScheme()
	cleanups []func()
)

func TestMain(m *testing.M) {
	code := runSuite(m)
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
	os.Exit(code)
}

func notExecuted(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "integration: NOT EXECUTED (not a verdict): "+format+"\n", a...)
	return 3
}

func runSuite(m *testing.M) int {
	env = map[string]string{}
	var missing []string
	for _, k := range standEnv {
		if v := os.Getenv(k); v != "" {
			env[k] = v
		} else {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return notExecuted("stand environment is not set (%v) — run hack/it-stand.sh", missing)
	}
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		return notExecuted("KUBEBUILDER_ASSETS is not set")
	}
	ctrl.SetLogger(zap.New(zap.WriteTo(os.Stderr), zap.Level(zapcore.InfoLevel)))
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	run = hex.EncodeToString(b)
	cluster = "it" + run
	issuer = "https://kio-it-" + run + ".example.invalid"
	ctx := context.Background()

	// k8s: envtest с издателем, который kaname признаёт внешним.
	e := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			filepath.Join("..", "..", "internal", "controller", "testdata", "crds"),
		},
		ErrorIfCRDPathMissing: true,
	}
	e.ControlPlane.GetAPIServer().Configure().Set("service-account-issuer", issuer)
	var err error
	restCfg, err = e.Start()
	if err != nil {
		return notExecuted("envtest: %v", err)
	}
	cleanups = append(cleanups, func() { _ = e.Stop() })
	_ = clientgoscheme.AddToScheme(scheme)
	_ = iamv1alpha1.AddToScheme(scheme)
	k8s, _ = client.New(restCfg, client.Options{Scheme: scheme})
	if err := k8s.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: itNS}}); err != nil {
		return notExecuted("namespace: %v", err)
	}
	if err := k8s.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: operatorSA, Namespace: itNS}}); err != nil {
		return notExecuted("service account: %v", err)
	}
	signingPEM, signingAlg, err := saSigningKeyPEM(ctx)
	if err != nil {
		return notExecuted("envtest signing key: %v", err)
	}

	// Vault — контейнер, вход — тот же projected-токен SA, что и в кластере.
	if code := startVault(ctx, signingPEM); code != 0 {
		return code
	}

	// kaname: бутстрап-учётка стенда заводит учётку оператора, её
	// FEDERATED-ключ на издателя envtest и выдачу admin на аккаунт.
	admin, err = newAdmin(ctx)
	if err != nil {
		return notExecuted("kaname bootstrap: %v", err)
	}
	if code := setupOperatorIdentity(ctx, signingPEM, signingAlg); code != 0 {
		return code
	}

	if code := startManager(ctx); code != 0 {
		return code
	}
	code := m.Run()
	if code == 0 {
		if err := census(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "integration: residue census:", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "integration: residue census: 0 objects of run", run)
	}
	return code
}

// saSigningKeyPEM — открытый ключ подписи токенов SA envtest (из JWKS) и его
// алгоритм JOSE.
func saSigningKeyPEM(ctx context.Context) (string, string, error) {
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return "", "", err
	}
	raw, err := cs.CoreV1().RESTClient().Get().AbsPath("/openid/v1/jwks").DoRaw(ctx)
	if err != nil {
		return "", "", err
	}
	var set struct {
		Keys []struct {
			Kty, Crv, N, E, X, Y, Alg string
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) == 0 {
		return "", "", fmt.Errorf("jwks: %v (%d keys)", err, len(set.Keys))
	}
	k := set.Keys[0]
	b64 := func(s string) *big.Int {
		b, _ := base64.RawURLEncoding.DecodeString(s)
		return new(big.Int).SetBytes(b)
	}
	var pub any
	alg := k.Alg
	switch {
	case k.Kty == "RSA":
		pub = &rsa.PublicKey{N: b64(k.N), E: int(b64(k.E).Int64())}
		if alg == "" {
			alg = "RS256"
		}
	case k.Kty == "EC" && k.Crv == "P-256":
		pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: b64(k.X), Y: b64(k.Y)}
		if alg == "" {
			alg = "ES256"
		}
	default:
		return "", "", fmt.Errorf("unexpected jwk %s %s", k.Kty, k.Crv)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), alg, nil
}

func tokenRequest(ctx context.Context, audience string) (string, error) {
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return "", err
	}
	a := &kaname.TokenRequestAssertions{Client: cs, Namespace: itNS, ServiceAccount: operatorSA,
		Audience: audience, TTL: 10 * time.Minute, CallTimeout: 10 * time.Second}
	return a.Assertion(ctx)
}

// ── kaname: бутстрап и учётка оператора ─────────────────────────────────

type adminClient struct {
	http  *http.Client
	base  string
	token string
}

func tlsDir(name string) string { return filepath.Join(env["KIO_IT_KANAME_TLS_DIR"], name) }

func serverPool() (*x509.CertPool, error) {
	ca, err := os.ReadFile(tlsDir("server-ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("server-ca.crt holds no certificate")
	}
	return pool, nil
}

func kanameHTTP() (*http.Client, error) {
	pool, err := serverPool()
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, ServerName: env["KIO_IT_KANAME_REST_SERVER_NAME"], MinVersion: tls.VersionTLS12,
	}}}, nil
}

func newAdmin(ctx context.Context) (*adminClient, error) {
	cert, err := tls.LoadX509KeyPair(tlsDir("boot-tls.crt"), tlsDir("boot-tls.key"))
	if err != nil {
		return nil, err
	}
	pool, err := serverPool()
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(env["KIO_IT_KANAME_INTERNAL_ADDR"], grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: env["KIO_IT_KANAME_INTERNAL_SERVER_NAME"], MinVersion: tls.VersionTLS12,
	})))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := iamv1.NewInternalBootstrapTokenServiceClient(conn).MintBootstrapToken(cctx, &iamv1.MintBootstrapTokenRequest{})
	if err != nil {
		return nil, err
	}
	hc, err := kanameHTTP()
	if err != nil {
		return nil, err
	}
	return &adminClient{http: hc, base: env["KIO_IT_KANAME_REST_URL"], token: resp.GetAccessToken()}, nil
}

// do — вызов REST-фронта бутстрап-учёткой; тело и ответ — сообщения kaname.
func (a *adminClient) do(ctx context.Context, method, path string, in proto.Message, out proto.Message) error {
	var body io.Reader
	if in != nil {
		b, err := protojson.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, out)
	}
	return nil
}

// await дожидается операции и разбирает ответ в out.
func (a *adminClient) await(ctx context.Context, op *operationpb.Operation, out proto.Message) error {
	deadline := time.Now().Add(60 * time.Second)
	for {
		err := kaname.OperationResult(op, out)
		if !errors.Is(err, kaname.ErrOperationNotDone) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("operation %s not done in 60s", op.GetId())
		}
		time.Sleep(500 * time.Millisecond)
		next := &operationpb.Operation{}
		if err := a.do(ctx, http.MethodGet, "/operations/"+op.GetId(), nil, next); err != nil {
			return err
		}
		op = next
	}
}

func (a *adminClient) mutate(ctx context.Context, method, path string, in, out proto.Message) error {
	op := &operationpb.Operation{}
	if err := a.do(ctx, method, path, in, op); err != nil {
		return err
	}
	return a.await(ctx, op, out)
}

func setupOperatorIdentity(ctx context.Context, signingPEM, signingAlg string) int {
	var accounts iamv1.ListAccountsResponse
	if err := admin.do(ctx, http.MethodGet, "/iam/v1/accounts?page_size=100", nil, &accounts); err != nil {
		return notExecuted("list accounts: %v", err)
	}
	for _, a := range accounts.GetAccounts() {
		if a.GetName() == "system" {
			account = a.GetId()
		}
	}
	if account == "" {
		return notExecuted("the stand has no system account")
	}
	var prj iamv1.Project
	if err := admin.mutate(ctx, http.MethodPost, "/iam/v1/projects",
		&iamv1.CreateProjectRequest{AccountId: account, Name: "kio-it-" + run}, &prj); err != nil {
		return notExecuted("create project: %v", err)
	}
	project = prj.GetId()
	cleanups = append(cleanups, func() {
		_ = admin.mutate(context.Background(), http.MethodDelete, "/iam/v1/projects/"+project, nil, nil)
	})
	var sa iamv1.ServiceAccount
	if err := admin.mutate(ctx, http.MethodPost, "/iam/v1/serviceAccounts",
		&iamv1.CreateServiceAccountRequest{AccountId: account, Name: "kio-it-" + run + "-operator", Description: "kaname-iam-operator integration run"},
		&sa); err != nil {
		return notExecuted("create operator account: %v", err)
	}
	opSAID = sa.GetId()
	cleanups = append(cleanups, func() {
		// kaname не удаляет учётку с действующими ключами: сначала FEDERATED-ключ.
		ctx := context.Background()
		var keys iamv1.ListSAKeysResponse
		if err := admin.do(ctx, http.MethodGet, "/iam/v1/serviceAccounts/"+opSAID+"/keys", nil, &keys); err == nil {
			for _, k := range keys.GetKeys() {
				_ = admin.mutate(ctx, http.MethodDelete, "/iam/v1/serviceAccounts/"+opSAID+"/keys/"+k.GetId(), nil, nil)
			}
		}
		if err := admin.mutate(ctx, http.MethodDelete, "/iam/v1/serviceAccounts/"+opSAID, nil, nil); err != nil {
			fmt.Fprintln(os.Stderr, "integration: cleanup of the operator account:", err)
		}
	})
	subject := "system:serviceaccount:" + itNS + ":" + operatorSA
	if err := admin.mutate(ctx, http.MethodPost, "/iam/v1/serviceAccounts/"+opSAID+"/keys", &iamv1.IssueSAKeyRequest{
		ServiceAccountId: opSAID, CredentialKind: iamv1.CredentialKind_CREDENTIAL_KIND_FEDERATED,
		TrustedSubjects: []*iamv1.TrustedSubject{{Issuer: issuer, SubjectPattern: "^" + subject + "$", PublicKeyPem: signingPEM, KeyAlgorithm: signingAlg}},
	}, nil); err != nil {
		return notExecuted("issue FEDERATED key: %v", err)
	}
	var roles iamv1.ListRolesResponse
	if err := admin.do(ctx, http.MethodGet, "/iam/v1/roles?filter="+url.QueryEscape(`name = "admin"`), nil, &roles); err != nil || len(roles.GetRoles()) != 1 {
		return notExecuted("find role admin: %v (%d)", err, len(roles.GetRoles()))
	}
	var grant iamv1.AccessBinding
	if err := admin.mutate(ctx, http.MethodPost, "/iam/v1/accessBindings", &iamv1.CreateAccessBindingRequest{
		Subjects: []*iamv1.Subject{{Type: iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, Id: opSAID}},
		RoleId:   roles.GetRoles()[0].GetId(), ScopeType: "iam.account", ScopeId: account,
		Target: &iamv1.AccessTarget{Target: &iamv1.AccessTarget_AllInScope{AllInScope: &iamv1.AccessTargetAllInScope{}}},
	}, &grant); err != nil {
		return notExecuted("grant the operator: %v", err)
	}
	cleanups = append(cleanups, func() {
		_ = admin.mutate(context.Background(), http.MethodPost, "/iam/v1/accessBindings/"+grant.GetId()+":revoke",
			&iamv1.RevokeAccessBindingRequest{AccessBindingId: grant.GetId()}, nil)
	})

	hc, err := kanameHTTP()
	if err != nil {
		return notExecuted("tls: %v", err)
	}
	tokens := kaname.NewFederatedTokenSource(kaname.FederatedTokenSourceOptions{
		TokenURL: env["KIO_IT_KANAME_TOKEN_URL"], RequestedAudience: env["KIO_IT_TOKEN_AUDIENCE"], HTTPClient: hc,
		Assertions:  assertionFunc(func(ctx context.Context) (string, error) { return tokenRequest(ctx, env["KIO_IT_ASSERTION_AUDIENCE"]) }),
		CallTimeout: 20 * time.Second,
	})
	opClient, err = kaname.New(kaname.Options{BaseURL: env["KIO_IT_KANAME_REST_URL"], HTTPClient: hc, Tokens: tokens, CallTimeout: 20 * time.Second})
	if err != nil {
		return notExecuted("operator client: %v", err)
	}
	// Выдача материализуется асинхронно: ждём, пока учётка оператора увидит себя.
	deadline := time.Now().Add(90 * time.Second)
	for {
		_, err := opClient.GetServiceAccount(ctx, opSAID)
		if err == nil {
			return 0
		}
		if time.Now().After(deadline) {
			return notExecuted("the operator identity did not gain access within 90s: %v", err)
		}
		time.Sleep(time.Second)
	}
}

type assertionFunc func(ctx context.Context) (string, error)

func (f assertionFunc) Assertion(ctx context.Context) (string, error) { return f(ctx) }

func startManager(ctx context.Context) int {
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
clusterName: %s
kaname: {apiURL: %s, audience: %s}
vault: {address: %s, authMount: kubernetes, role: %s, tokenPath: /var/run/secrets/vault/token}
policy:
  allowedRoles: [%s]
  targetResolvers:
    %s:
      group: registry.in-cloud.io
      version: v1alpha1
      resource: registryidreservations
      match:
      - {path: spec.registryRef.namespace, equals: $namespace}
      - {path: status.phase, equals: Active}
delivery:
  vault:
    docker-registry:
      mount: %s
      pathTemplate: clusters/{cluster}/namespaces/{namespace}/apps/docker-registry/{instance}/robots/{name}/{key}
`, cluster, env["KIO_IT_KANAME_REST_URL"], env["KIO_IT_ASSERTION_AUDIENCE"], vaultAPI.addr, vaultRole,
		env["KIO_IT_ROLE"], env["KIO_IT_TARGET_TYPE"], vaultMount)))
	if err != nil {
		return notExecuted("config: %v", err)
	}
	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}})
	if err != nil {
		return notExecuted("manager: %v", err)
	}
	deps := &controller.Deps{
		Kaname: opClient, Vault: vaultCli, Config: cfg, Recorder: &events.FakeRecorder{},
		Clock: clock.RealClock{}, DriftInterval: 2 * time.Second, MaxConcurrentReconciles: 2,
	}
	mctx, cancel := context.WithCancel(ctx)
	cleanups = append(cleanups, cancel)
	if err := controller.SetupIndexes(mctx, mgr); err != nil {
		return notExecuted("indexes: %v", err)
	}
	if err := controller.SetupServiceAccountReconciler(mgr, deps); err != nil {
		return notExecuted("sa: %v", err)
	}
	if err := controller.SetupAccessBindingReconciler(mgr, deps); err != nil {
		return notExecuted("ab: %v", err)
	}
	go func() { _ = mgr.Start(mctx) }()
	return 0
}

// census — перепись остатков прогона в kaname и Vault: учёток с префиксом
// прогона и действующих выдач с меткой кластера прогона быть не должно.
func census(ctx context.Context) error {
	var list iamv1.ListServiceAccountsResponse
	if err := admin.do(ctx, http.MethodGet, "/iam/v1/serviceAccounts?page_size=1000&account_id="+account, nil, &list); err != nil {
		return err
	}
	var left []string
	for _, sa := range list.GetServiceAccounts() {
		if strings.HasPrefix(sa.GetName(), "kio-it-"+run) && sa.GetId() != opSAID {
			left = append(left, sa.GetName())
		}
	}
	var abs iamv1.ListAccessBindingsResponse
	if err := admin.do(ctx, http.MethodGet, "/iam/v1/accounts/"+account+"/accessBindings?page_size=1000", nil, &abs); err != nil {
		return err
	}
	for _, b := range abs.GetAccessBindings() {
		if b.GetLabels()[iamv1alpha1.LabelCluster] == cluster && b.GetStatus() != iamv1.AccessBinding_REVOKED {
			left = append(left, "binding "+b.GetId())
		}
	}
	paths, err := vaultAPI.list(ctx, "clusters/"+cluster)
	if err != nil {
		return err
	}
	left = append(left, paths...)
	if len(left) > 0 {
		return fmt.Errorf("%d objects left: %v", len(left), left)
	}
	return nil
}
