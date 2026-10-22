// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package controller — реконсиляция ServiceAccount и AccessBinding.
//
// Каждый проход делает не больше одного изменяющего вызова kaname: запущенная
// операция записывается в status (PendingOperation) и дочитывается следующим
// проходом. Намерение выпуска ключа записывается в status ДО вызова, с
// проверкой resourceVersion — это сравнение-и-запись на стороне k8s.
package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/metrics"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/policy"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/vault"
)

// KanameAPI — то из клиента kaname, чем пользуются контроллеры.
type KanameAPI interface {
	GetServiceAccount(ctx context.Context, id string) (*iamv1.ServiceAccount, error)
	FindServiceAccountByName(ctx context.Context, accountID, name string) (*iamv1.ServiceAccount, error)
	CreateServiceAccount(ctx context.Context, req *iamv1.CreateServiceAccountRequest) (*operationpb.Operation, error)
	UpdateServiceAccount(ctx context.Context, req *iamv1.UpdateServiceAccountRequest) (*operationpb.Operation, error)
	DisableServiceAccount(ctx context.Context, id string) (*operationpb.Operation, error)
	EnableServiceAccount(ctx context.Context, id string) (*operationpb.Operation, error)
	DeleteServiceAccount(ctx context.Context, id string) (*operationpb.Operation, error)
	IssueKey(ctx context.Context, req *iamv1.IssueSAKeyRequest) (*operationpb.Operation, error)
	ListKeys(ctx context.Context, serviceAccountID string) ([]*iamv1.ServiceAccountOAuthClient, error)
	RevokeKey(ctx context.Context, serviceAccountID, keyID string) (*operationpb.Operation, error)
	GetOperation(ctx context.Context, id string) (*operationpb.Operation, error)
	CreateAccessBinding(ctx context.Context, req *iamv1.CreateAccessBindingRequest) (*operationpb.Operation, error)
	GetAccessBinding(ctx context.Context, id string) (*iamv1.AccessBinding, error)
	UpdateAccessBinding(ctx context.Context, req *iamv1.UpdateAccessBindingRequest) (*operationpb.Operation, error)
	RevokeAccessBinding(ctx context.Context, id string) (*operationpb.Operation, error)
	ListAccessBindingsByAccount(ctx context.Context, accountID string) ([]*iamv1.AccessBinding, error)
	FindSystemRole(ctx context.Context, name string) (*iamv1.Role, error)
}

// VaultAPI — то из клиента Vault, чем пользуется протокол ключей.
type VaultAPI interface {
	Read(ctx context.Context, mount, path string) (*vault.Record, error)
	WriteCAS(ctx context.Context, mount, path string, data map[string]string, cas int64) (int64, error)
	DeleteAll(ctx context.Context, mount, path string) error
}

var (
	_ KanameAPI = (*kaname.Client)(nil)
	_ VaultAPI  = (*vault.Client)(nil)
)

// Deps — общие зависимости контроллеров.
type Deps struct {
	Kaname   KanameAPI
	Vault    VaultAPI
	Config   *config.Config
	Recorder events.EventRecorder
	Clock    clock.PassiveClock
	// Seal — печать свидетельства допуска: свидетельство в status без неё
	// гарантии не даёт (policy.CheckAdmissionGuarantee).
	Seal *policy.WitnessSeal
	// DriftInterval — как часто готовый объект сверяется с kaname.
	DriftInterval time.Duration
	// MaxConcurrentReconciles — параллельные проходы на вид (один объект
	// очередь всё равно не отдаёт двум проходам сразу).
	MaxConcurrentReconciles int
}

func (d *Deps) controllerOptions() controller.Options {
	return controller.Options{
		MaxConcurrentReconciles: max(d.MaxConcurrentReconciles, 1),
		RateLimiter:             workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](pollInitial, forbiddenPause),
	}
}

func (d *Deps) now() time.Time { return d.Clock.Now() }

// Паузы повтора.
const (
	pollInitial     = 2 * time.Second
	pollMax         = 30 * time.Second
	invalidRecheck  = 10 * time.Minute
	forbiddenPause  = 5 * time.Minute
	conflictRecheck = 10 * time.Minute
)

// errRequeue — состояние записано, нужен немедленный следующий проход.
var errRequeue = errors.New("requeue")

// setCondition выставляет условие с поколением объекта.
func setCondition(conds *[]metav1.Condition, gen int64, typ string, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(conds, metav1.Condition{
		Type: typ, Status: status, Reason: reason, Message: truncate(msg, 1024), ObservedGeneration: gen,
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// pollDelay — пауза дочитывания операции по её возрасту: 2 с → 30 с.
func pollDelay(started, now time.Time) time.Duration {
	age := now.Sub(started)
	d := pollInitial
	for d < pollMax && age > 4*d {
		d *= 2
	}
	return min(d, pollMax)
}

// ownedBy — несёт ли объект kaname метки владения этого CR в этом кластере.
func ownedBy(labels map[string]string, uid, cluster string) bool {
	return labels[iamv1alpha1.LabelOwnerUID] == uid && labels[iamv1alpha1.LabelCluster] == cluster
}

// ownershipLabels — метки владения CR: uid, кластер и ссылка, если помещается.
func ownershipLabels(obj metav1.Object, cluster string) map[string]string {
	out := map[string]string{
		iamv1alpha1.LabelOwnerUID: string(obj.GetUID()),
		iamv1alpha1.LabelCluster:  cluster,
	}
	if ref := obj.GetNamespace() + "." + obj.GetName(); len(ref) <= 63 {
		out[iamv1alpha1.LabelRef] = ref
	}
	return out
}

// desiredLabels — метки spec плюс метки владения (последние сильнее).
func desiredLabels(spec map[string]string, obj metav1.Object, cluster string) map[string]string {
	out := make(map[string]string, len(spec)+3)
	for k, v := range spec {
		out[k] = v
	}
	for k, v := range ownershipLabels(obj, cluster) {
		out[k] = v
	}
	return out
}

func equalLabels(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// outcome — что делать по отказу kaname: условие, пауза либо ошибка для
// очереди с нарастающей паузой.
type outcome struct {
	reason  string
	message string
	after   time.Duration
	err     error
}

// classify переводит отказ kaname в условие и повтор по таблице класса.
func classify(kind string, err error) outcome {
	msg := err.Error()
	switch kaname.Classify(err) {
	case kaname.ClassInvalid:
		metrics.Refusals.WithLabelValues(kind, iamv1alpha1.ReasonInvalid).Inc()
		return outcome{reason: iamv1alpha1.ReasonInvalid, message: msg, after: invalidRecheck}
	case kaname.ClassForbidden:
		metrics.Refusals.WithLabelValues(kind, iamv1alpha1.ReasonForbidden).Inc()
		return outcome{reason: iamv1alpha1.ReasonForbidden, message: msg, after: forbiddenPause}
	default:
		// Retryable, Unknown, а также NotFound и AlreadyExists там, где шаг их
		// не ждал: повтор с нарастающей паузой очереди и с текстом отказа.
		metrics.Refusals.WithLabelValues(kind, iamv1alpha1.ReasonRetrying).Inc()
		return outcome{reason: iamv1alpha1.ReasonRetrying, message: msg, err: fmt.Errorf("%s: %w", kind, err)}
	}
}

func (o outcome) result() (ctrl.Result, error) {
	if o.err != nil {
		return ctrl.Result{}, o.err
	}
	return ctrl.Result{RequeueAfter: o.after}, nil
}

func isConflict(err error) bool { return apierrors.IsConflict(err) }

// deletionAccounts — аккаунты, где удаление ищет объект kaname, чей id не
// дошёл до status: записанный в status (намерение) и аккаунт namespace, если
// он другой. Namespace уже снят — остаётся только status.
func deletionAccounts(ctx context.Context, c client.Reader, namespace, recorded string) ([]string, error) {
	var out []string
	if recorded != "" {
		out = append(out, recorded)
	}
	ns := &corev1.Namespace{}
	err := c.Get(ctx, client.ObjectKey{Name: namespace}, ns)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	if acc := ns.Annotations[iamv1alpha1.AnnotationAccountID]; err == nil && acc != "" && acc != recorded {
		out = append(out, acc)
	}
	return out, nil
}

// newPending — запись операции, запущенной сейчас.
func newPending(op *operationpb.Operation, verb iamv1alpha1.OperationVerb, subject string, now time.Time) *iamv1alpha1.PendingOperation {
	return &iamv1alpha1.PendingOperation{ID: op.GetId(), Verb: verb, Subject: subject, StartedAt: metav1.NewTime(now)}
}
