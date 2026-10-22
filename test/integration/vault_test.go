//go:build integration

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/PRO-Robotech/kaname-iam-operator/internal/vault"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/vault/vaulttest"
)

// vaultAdmin — корневой доступ к контейнеру Vault для подготовки и переписи.
type vaultAdmin struct {
	addr string
	http *http.Client
	root string
}

const vaultRoot = "kio-it-root"

// startVault поднимает Vault (dev, TLS), заводит метод JWT на пути
// kubernetes с ключом подписи SA envtest и роль с политикой ТОЛЬКО на пути
// доставки прогона — ту же форму, что роль kubernetes-auth на площадке.
func startVault(ctx context.Context, signingPEM string) int {
	req := testcontainers.ContainerRequest{
		Image:        vaultImage,
		ExposedPorts: []string{"8200/tcp"},
		Env:          map[string]string{"SKIP_SETCAP": "true"},
		Cmd: []string{"server", "-dev", "-dev-tls", "-dev-tls-cert-dir=/vault/file",
			"-dev-root-token-id=" + vaultRoot, "-dev-listen-address=0.0.0.0:8200"},
		WaitingFor: wait.ForLog("Development mode should NOT be used in production").WithStartupTimeout(60 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		return notExecuted("vault container: %v", err)
	}
	cleanups = append(cleanups, func() { _ = c.Terminate(context.Background()) })
	rc, err := c.CopyFileFromContainer(ctx, "/vault/file/vault-ca.pem")
	if err != nil {
		return notExecuted("vault CA: %v", err)
	}
	caPEM, _ := io.ReadAll(rc)
	_ = rc.Close()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return notExecuted("vault CA holds no certificate")
	}
	port, err := c.MappedPort(ctx, "8200/tcp")
	if err != nil {
		return notExecuted("vault port: %v", err)
	}
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	vaultAPI = &vaultAdmin{addr: fmt.Sprintf("https://localhost:%s", port.Port()), http: hc, root: vaultRoot}
	policy := fmt.Sprintf(`path "%[1]s/data/clusters/%[2]s/*" { capabilities = ["create", "read", "update", "delete"] }
path "%[1]s/metadata/clusters/%[2]s/*" { capabilities = ["read", "delete"] }`, vaultMount, cluster)
	steps := []struct {
		method, path string
		body         any
	}{
		{"POST", "/v1/sys/auth/kubernetes", map[string]any{"type": "jwt"}},
		{"POST", "/v1/auth/kubernetes/config", map[string]any{"jwt_validation_pubkeys": []string{signingPEM}, "bound_issuer": issuer}},
		{"PUT", "/v1/sys/policies/acl/kio", map[string]any{"policy": policy}},
		{"POST", "/v1/auth/kubernetes/role/" + vaultRole, map[string]any{
			"role_type": "jwt", "bound_audiences": []string{"vault"}, "user_claim": "sub",
			"bound_subject": "system:serviceaccount:" + itNS + ":" + operatorSA, "token_policies": []string{"kio"}, "token_ttl": "1h",
		}},
	}
	for _, s := range steps {
		if err := vaultAPI.call(ctx, s.method, s.path, s.body, nil); err != nil {
			return notExecuted("vault setup %s %s: %v", s.method, s.path, err)
		}
	}
	vaultCli, err = vault.New(vault.Options{
		Address: vaultAPI.addr, HTTPClient: hc, AuthMount: "kubernetes", Role: vaultRole, CallTimeout: 10 * time.Second,
		JWT: func() (string, error) { return tokenRequest(context.Background(), "vault") },
	})
	if err != nil {
		return notExecuted("vault client: %v", err)
	}
	return 0
}

func (v *vaultAdmin) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.addr+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.root)
	resp, err := v.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound && method == "LIST" {
		return nil
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%d %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// list — все записи KV v2 под prefix (рекурсивно).
func (v *vaultAdmin) list(ctx context.Context, prefix string) ([]string, error) {
	var out struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := v.call(ctx, "LIST", "/v1/"+vaultMount+"/metadata/"+prefix, nil, &out); err != nil {
		return nil, err
	}
	var all []string
	for _, k := range out.Data.Keys {
		if strings.HasSuffix(k, "/") {
			sub, err := v.list(ctx, prefix+"/"+strings.TrimSuffix(k, "/"))
			if err != nil {
				return nil, err
			}
			all = append(all, sub...)
			continue
		}
		all = append(all, prefix+"/"+k)
	}
	return all, nil
}

// TestVaultContractOnTheContainer — тот же контракт, что гоняется против
// двойника: двойник не снисходительнее настоящего Vault.
func TestVaultContractOnTheContainer(t *testing.T) {
	vaulttest.RunContract(t, vaultCli, vaultMount, "clusters/"+cluster, "clusters/other-"+run+"/x")
}
