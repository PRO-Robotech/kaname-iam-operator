// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package kaname

import (
	"context"
	"fmt"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// TokenRequestAssertions — утверждения из TokenRequest API на собственный SA
// оператора. Файл projected-токена не годится: kubelet меняет его раз в
// десятки минут, а kaname принимает каждое утверждение ровно один раз (jti).
type TokenRequestAssertions struct {
	// Client — клиент kube-apiserver.
	Client kubernetes.Interface
	// Namespace и ServiceAccount — собственный SA оператора.
	Namespace      string
	ServiceAccount string
	// Audience — адресат утверждения (идентификатор издателя kaname).
	Audience string
	// TTL — срок утверждения.
	TTL time.Duration
	// CallTimeout — дедлайн вызова kube-apiserver.
	CallTimeout time.Duration
}

// Assertion запрашивает новое утверждение.
func (a *TokenRequestAssertions) Assertion(ctx context.Context) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, a.CallTimeout)
	defer cancel()
	ttl := int64(a.TTL / time.Second)
	tr, err := a.Client.CoreV1().ServiceAccounts(a.Namespace).CreateToken(callCtx, a.ServiceAccount,
		&authv1.TokenRequest{Spec: authv1.TokenRequestSpec{
			Audiences:         []string{a.Audience},
			ExpirationSeconds: &ttl,
		}}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("token request for %s/%s: %w", a.Namespace, a.ServiceAccount, err)
	}
	if tr.Status.Token == "" {
		return "", fmt.Errorf("token request for %s/%s returned no token", a.Namespace, a.ServiceAccount)
	}
	return tr.Status.Token, nil
}
