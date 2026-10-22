// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Command manager — kaname-iam-operator: CR IAMServiceAccount и IAMAccessBinding
// группы iam.kaname.in-cloud.io отражаются в учётки и выдачи kaname IAM.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/controller"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/metrics"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/policy"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/vault"
)

// Переменные окружения, которые ставит Deployment (downward API).
const (
	envPodNamespace   = "POD_NAMESPACE"
	envServiceAccount = "SERVICE_ACCOUNT_NAME"
	leaderElectionID  = "kaname-iam-operator.iam.kaname.in-cloud.io"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kaname-iam-operator:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath    string
		metricsAddr   string
		probeAddr     string
		secureMetrics bool
		leaderElect   bool
		driftInterval time.Duration
		concurrency   int
		witnessKey    string
	)
	flag.StringVar(&configPath, "config", "/etc/kaname-iam-operator/config.yaml", "Operator configuration file.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8443", "Metrics endpoint address; 0 disables it.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe endpoint address.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true, "Serve metrics over HTTPS with authentication and authorization.")
	flag.BoolVar(&leaderElect, "leader-elect", true, "Run only while holding the Lease; two active replicas must not issue keys.")
	flag.DurationVar(&driftInterval, "drift-interval", 10*time.Minute, "How often a ready object is compared with kaname.")
	flag.IntVar(&concurrency, "max-concurrent-reconciles", 4, "Parallel reconciles per kind.")
	flag.StringVar(&witnessKey, "witness-key-secret", "kaname-iam-operator-witness-key",
		"Secret in the operator namespace holding the admission witness seal key; created on first start.")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("setup")

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if driftInterval < 30*time.Second {
		return fmt.Errorf("--drift-interval %s is below 30s", driftInterval)
	}
	podNS, saName := os.Getenv(envPodNamespace), os.Getenv(envServiceAccount)
	if podNS == "" || saName == "" {
		return fmt.Errorf("%s and %s must be set: the FEDERATED entry asks a token for the operator's own service account", envPodNamespace, envServiceAccount)
	}
	if !leaderElect {
		log.Info("leader election is OFF: run a single replica only, two active replicas would race on key issuance")
	}
	kanameHTTP, err := httpClient(cfg.Kaname.CAFile, cfg.Kaname.CallTimeout.Duration)
	if err != nil {
		return fmt.Errorf("kaname TLS: %w", err)
	}
	vaultHTTP, err := httpClient(cfg.Vault.CAFile, cfg.Vault.CallTimeout.Duration)
	if err != nil {
		return fmt.Errorf("vault TLS: %w", err)
	}
	if _, err := os.Stat(cfg.Vault.TokenPath); err != nil {
		return fmt.Errorf("vault.tokenPath: %w", err)
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(iamv1alpha1.AddToScheme(scheme))

	restCfg := ctrl.GetConfigOrDie()
	metricsOpts := metricsserver.Options{BindAddress: metricsAddr, SecureServing: secureMetrics}
	if secureMetrics {
		metricsOpts.FilterProvider = filters.WithAuthenticationAndAuthorization
		metricsOpts.TLSOpts = []func(*tls.Config){func(c *tls.Config) { c.MinVersion = tls.VersionTLS12 }}
	}
	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsOpts,
		HealthProbeBindAddress:        probeAddr,
		LeaderElection:                leaderElect,
		LeaderElectionID:              leaderElectionID,
		LeaderElectionNamespace:       podNS,
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		return fmt.Errorf("manager: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("clientset: %w", err)
	}
	// Ключ печати свидетельства допуска — до старта контроллеров: без него
	// свидетельству в status, которое пишет не только оператор, не доверяется.
	seal, err := witnessSeal(clientset, podNS, witnessKey)
	if err != nil {
		return err
	}
	tokens := kaname.NewFederatedTokenSource(kaname.FederatedTokenSourceOptions{
		TokenURL:          cfg.Kaname.TokenURL,
		RequestedAudience: cfg.Kaname.RequestedAudience,
		HTTPClient:        kanameHTTP,
		Assertions: &kaname.TokenRequestAssertions{
			Client: clientset, Namespace: podNS, ServiceAccount: saName,
			Audience: cfg.Kaname.Audience, TTL: cfg.Kaname.AssertionTTL.Duration, CallTimeout: cfg.Kaname.CallTimeout.Duration,
		},
		CallTimeout: cfg.Kaname.CallTimeout.Duration,
		Observe:     metrics.ObserveExchange,
	})
	kc, err := kaname.New(kaname.Options{
		BaseURL: cfg.Kaname.APIURL, HTTPClient: kanameHTTP, Tokens: tokens, CallTimeout: cfg.Kaname.CallTimeout.Duration,
		Limiter: rate.NewLimiter(rate.Limit(cfg.Kaname.QPS), cfg.Kaname.Burst), Observe: metrics.ObserveKaname,
	})
	if err != nil {
		return err
	}
	tokenPath := cfg.Vault.TokenPath
	vc, err := vault.New(vault.Options{
		Address: cfg.Vault.Address, HTTPClient: vaultHTTP, AuthMount: cfg.Vault.AuthMount, Role: cfg.Vault.Role,
		JWT: func() (string, error) {
			b, err := os.ReadFile(tokenPath) //nolint:gosec // путь — из проверенной конфигурации.
			if err != nil {
				return "", err
			}
			tok := strings.TrimSpace(string(b))
			if tok == "" {
				return "", errors.New("projected token file is empty")
			}
			return tok, nil
		},
		CallTimeout: cfg.Vault.CallTimeout.Duration,
		Observe:     metrics.ObserveVault,
	})
	if err != nil {
		return err
	}
	deps := &controller.Deps{
		Kaname: kc, Vault: vc, Config: cfg,
		Recorder: mgr.GetEventRecorder("kaname-iam-operator"), Clock: clock.RealClock{}, Seal: seal,
		DriftInterval: driftInterval, MaxConcurrentReconciles: concurrency,
	}
	ctx := ctrl.SetupSignalHandler()
	if err := controller.SetupIndexes(ctx, mgr); err != nil {
		return err
	}
	if err := controller.SetupIAMServiceAccountReconciler(mgr, deps); err != nil {
		return err
	}
	if err := controller.SetupIAMAccessBindingReconciler(mgr, deps); err != nil {
		return err
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}
	log.Info("starting", "cluster", cfg.ClusterName, "leaderElection", leaderElect)
	return mgr.Start(ctx)
}

// witnessSeal читает (а нет его — заводит) ключ печати свидетельства из
// Secret name в namespace оператора.
func witnessSeal(cs kubernetes.Interface, namespace, name string) (*policy.WitnessSeal, error) {
	if name == "" {
		return nil, errors.New("--witness-key-secret is empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	key, err := policy.LoadWitnessKey(ctx, cs.CoreV1().Secrets(namespace), name)
	if err != nil {
		return nil, err
	}
	return policy.NewWitnessSeal(key)
}

// httpClient — клиент с собственным УЦ (либо системными корнями) и TLS ≥ 1.2.
// Timeout клиента — страховка поверх дедлайна каждого вызова.
func httpClient(caFile string, callTimeout time.Duration) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // путь — из проверенной конфигурации.
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no PEM certificate", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &http.Client{Transport: tr, Timeout: callTimeout + 5*time.Second}, nil
}
