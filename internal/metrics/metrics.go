// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package metrics — счётчики оператора. Регистрируются в реестре
// controller-runtime и отдаются его эндпоинтом метрик.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const ns = "kaname_iam_operator"

var (
	// KanameRequests — вызовы kaname по операции и коду.
	KanameRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "kaname_requests_total", Help: "kaname API calls by operation and result code.",
	}, []string{"op", "code"})
	// KanameLatency — длительность вызовов kaname.
	KanameLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns, Name: "kaname_request_duration_seconds", Help: "kaname API call latency.",
		Buckets: prometheus.ExponentialBuckets(0.005, 2, 12),
	}, []string{"op"})
	// TokenExchanges — обмены jwt-bearer по исходу.
	TokenExchanges = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "token_exchanges_total", Help: "FEDERATED jwt-bearer exchanges by outcome.",
	}, []string{"outcome"})
	// VaultRequests — вызовы Vault по операции и исходу.
	VaultRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "vault_requests_total", Help: "Vault calls by operation and outcome.",
	}, []string{"op", "outcome"})
	// VaultLatency — длительность вызовов Vault.
	VaultLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns, Name: "vault_request_duration_seconds", Help: "Vault call latency.",
		Buckets: prometheus.ExponentialBuckets(0.005, 2, 12),
	}, []string{"op"})
	// KeysIssued — выпущенные ключи по виду.
	KeysIssued = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "keys_issued_total", Help: "Service account keys issued by kind.",
	}, []string{"kind"})
	// KeysRevoked — отозванные ключи по причине.
	KeysRevoked = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "keys_revoked_total", Help: "Service account keys revoked by reason.",
	}, []string{"reason"})
	// Drift — замеченный дрейф по виду объекта и причине.
	Drift = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "drift_detected_total", Help: "Out-of-band changes in kaname detected by kind and reason.",
	}, []string{"kind", "reason"})
	// Refusals — отказы реконсиляции по виду объекта и причине условия.
	Refusals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "refusals_total", Help: "Reconcile refusals by kind and condition reason.",
	}, []string{"kind", "reason"})
)

func init() {
	crmetrics.Registry.MustRegister(KanameRequests, KanameLatency, TokenExchanges, VaultRequests, VaultLatency,
		KeysIssued, KeysRevoked, Drift, Refusals)
}

// ObserveKaname — наблюдатель клиента kaname.
func ObserveKaname(op, code string, d time.Duration) {
	KanameRequests.WithLabelValues(op, code).Inc()
	KanameLatency.WithLabelValues(op).Observe(d.Seconds())
}

// ObserveVault — наблюдатель клиента Vault.
func ObserveVault(op, outcome string, d time.Duration) {
	VaultRequests.WithLabelValues(op, outcome).Inc()
	VaultLatency.WithLabelValues(op).Observe(d.Seconds())
}

// ObserveExchange — наблюдатель обмена jwt-bearer.
func ObserveExchange(outcome string) {
	TokenExchanges.WithLabelValues(outcome).Inc()
}
