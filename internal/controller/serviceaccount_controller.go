// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/metrics"
)

const (
	kindSA = "ServiceAccount"
	// requeueNow — следующий проход сразу после записанного шага.
	requeueNow = 100 * time.Millisecond
	// deletionBlockedRecheck — пауза ожидания снятия ссылающихся выдач.
	deletionBlockedRecheck = 5 * time.Second
)

// ServiceAccountReconciler отражает CR ServiceAccount в учётку kaname.
type ServiceAccountReconciler struct {
	client.Client
	*Deps
}

// +kubebuilder:rbac:groups=iam.kaname.in-cloud.io,resources=serviceaccounts,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=iam.kaname.in-cloud.io,resources=serviceaccounts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.kaname.in-cloud.io,resources=serviceaccounts/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// SetupServiceAccountReconciler регистрирует контроллер ServiceAccount.
func SetupServiceAccountReconciler(mgr ctrl.Manager, d *Deps) error {
	r := &ServiceAccountReconciler{Client: mgr.GetClient(), Deps: d}
	return ctrl.NewControllerManagedBy(mgr).
		For(&iamv1alpha1.ServiceAccount{}, builder.WithPredicates(specOrMetaChanged())).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.forNamespace),
			builder.WithPredicates(predicate.AnnotationChangedPredicate{})).
		Watches(&iamv1alpha1.AccessBinding{}, handler.EnqueueRequestsFromMapFunc(r.forBinding)).
		WithOptions(d.controllerOptions()).
		Named("serviceaccount").
		Complete(r)
}

// specOrMetaChanged — проход на смену spec, аннотаций, меток и начало
// удаления; собственные записи status прохода не будят.
func specOrMetaChanged() predicate.Predicate {
	return predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{},
		predicate.LabelChangedPredicate{}, predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				return e.ObjectNew.GetDeletionTimestamp() != nil
			},
		})
}

func (r *ServiceAccountReconciler) forNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	var list iamv1alpha1.ServiceAccountList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetName())); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(list.Items))
	for _, it := range list.Items {
		out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&it)})
	}
	return out
}

// forBinding будит учётки, на которые ссылается выдача: удаление учётки
// ждёт снятия ссылающихся выдач.
func (r *ServiceAccountReconciler) forBinding(_ context.Context, obj client.Object) []reconcile.Request {
	ab, ok := obj.(*iamv1alpha1.AccessBinding)
	if !ok {
		return nil
	}
	var out []reconcile.Request
	for _, name := range referencedServiceAccounts(ab) {
		out = append(out, reconcile.Request{NamespacedName: client.ObjectKey{Namespace: ab.Namespace, Name: name}})
	}
	return out
}

// Reconcile — один проход.
func (r *ServiceAccountReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	sa := &iamv1alpha1.ServiceAccount{}
	if err := r.Get(ctx, req.NamespacedName, sa); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	p := &saPass{r: r, sa: sa, saved: sa.Status.DeepCopy()}
	if !sa.DeletionTimestamp.IsZero() {
		res, err := p.finalize(ctx)
		return p.finish(ctx, res, err)
	}
	if !controllerutil.ContainsFinalizer(sa, iamv1alpha1.Finalizer) {
		controllerutil.AddFinalizer(sa, iamv1alpha1.Finalizer)
		if err := r.Update(ctx, sa); err != nil {
			return ctrl.Result{}, err
		}
		p.saved = sa.Status.DeepCopy()
	}
	res, err := p.reconcile(ctx)
	sa.Status.ObservedGeneration = sa.Generation
	return p.finish(ctx, res, err)
}

// saPass — состояние одного прохода.
type saPass struct {
	r     *ServiceAccountReconciler
	sa    *iamv1alpha1.ServiceAccount
	saved *iamv1alpha1.ServiceAccountStatus
	// resyncNow — аннотация resync-drift разрешает восстановление в этом проходе.
	resyncNow bool
	// keyDrift — имена ключей, отозванных в kaname мимо оператора.
	keyDrift []string
	// wake — ближайшее время, к которому нужен следующий проход.
	wake time.Time
}

func (p *saPass) now() time.Time { return p.r.now() }

func (p *saPass) cond(typ string, status metav1.ConditionStatus, reason, msg string) {
	setCondition(&p.sa.Status.Conditions, p.sa.Generation, typ, status, reason, msg)
}

// save пишет status с проверкой resourceVersion: это запись намерения либо
// результата шага, после которой шаг считается совершённым.
func (p *saPass) save(ctx context.Context) error {
	if equality.Semantic.DeepEqual(p.saved, &p.sa.Status) {
		return nil
	}
	if err := p.r.Status().Update(ctx, p.sa); err != nil {
		return err
	}
	p.saved = p.sa.Status.DeepCopy()
	return nil
}

func (p *saPass) finish(ctx context.Context, res ctrl.Result, err error) (ctrl.Result, error) {
	if serr := p.save(ctx); serr != nil {
		if apierrors.IsNotFound(serr) {
			return ctrl.Result{}, nil
		}
		if isConflict(serr) {
			return ctrl.Result{RequeueAfter: requeueNow}, nil
		}
		return ctrl.Result{}, serr
	}
	if errors.Is(err, errRequeue) {
		return ctrl.Result{RequeueAfter: requeueNow}, nil
	}
	if err != nil && isConflict(err) {
		return ctrl.Result{RequeueAfter: requeueNow}, nil
	}
	return res, err
}

func (p *saPass) wakeAt(t time.Time) {
	if p.wake.IsZero() || t.Before(p.wake) {
		p.wake = t
	}
}

// fail выставляет условия по отказу kaname и возвращает повтор его класса.
func (p *saPass) fail(err error) (ctrl.Result, error) {
	o := classify(kindSA, err)
	p.cond(iamv1alpha1.ConditionSynced, metav1.ConditionFalse, o.reason, o.message)
	p.cond(iamv1alpha1.ConditionReady, metav1.ConditionFalse, o.reason, o.message)
	if o.reason == iamv1alpha1.ReasonForbidden {
		p.r.Recorder.Eventf(p.sa, nil, corev1.EventTypeWarning, iamv1alpha1.ReasonForbidden, "Reconcile", "kaname refused the operator: %s", o.message)
	}
	return o.result()
}

func (p *saPass) notReady(reason, msg string) {
	p.cond(iamv1alpha1.ConditionReady, metav1.ConditionFalse, reason, msg)
}

func (p *saPass) conflict(reason, msg string) (ctrl.Result, error) {
	p.cond(iamv1alpha1.ConditionConflict, metav1.ConditionTrue, reason, msg)
	p.notReady(reason, msg)
	metrics.Refusals.WithLabelValues(kindSA, reason).Inc()
	p.r.Recorder.Eventf(p.sa, nil, corev1.EventTypeWarning, reason, "Reconcile", "%s", msg)
	return ctrl.Result{RequeueAfter: conflictRecheck}, nil
}

func (p *saPass) drift(reason, msg string) (ctrl.Result, error) {
	if c := findCondition(p.sa.Status.Conditions, iamv1alpha1.ConditionDrifted); c == nil || c.Status != metav1.ConditionTrue || c.Reason != reason {
		metrics.Drift.WithLabelValues(kindSA, reason).Inc()
		p.r.Recorder.Eventf(p.sa, nil, corev1.EventTypeWarning, reason, "Reconcile",
			"%s; the operator does not undo it — set annotation %s to restore", msg, iamv1alpha1.AnnotationResyncDrift)
	}
	p.cond(iamv1alpha1.ConditionDrifted, metav1.ConditionTrue, reason, msg)
	p.notReady(reason, msg)
	return ctrl.Result{RequeueAfter: p.r.DriftInterval}, nil
}

// observeResync отмечает аннотацию resync-drift прочитанной: она разрешает
// восстановить дрейф, существующий СЕЙЧАС, и только его.
func (p *saPass) observeResync() {
	ann := p.sa.Annotations[iamv1alpha1.AnnotationResyncDrift]
	if ann != "" && ann != p.sa.Status.ResyncNonce {
		p.resyncNow = true
		p.sa.Status.ResyncNonce = ann
	}
}

func findCondition(conds []metav1.Condition, typ string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == typ {
			return &conds[i]
		}
	}
	return nil
}

func (p *saPass) reconcile(ctx context.Context) (ctrl.Result, error) {
	sa, st := p.sa, &p.sa.Status
	cfg := p.r.Config
	ns := &corev1.Namespace{}
	if err := p.r.Get(ctx, client.ObjectKey{Name: sa.Namespace}, ns); err != nil {
		return ctrl.Result{}, err
	}
	accountID := ns.Annotations[iamv1alpha1.AnnotationAccountID]
	if accountID == "" {
		p.notReady(iamv1alpha1.ReasonAccountUnresolved,
			fmt.Sprintf("namespace %s has no annotation %s", sa.Namespace, iamv1alpha1.AnnotationAccountID))
		return ctrl.Result{}, nil
	}
	if st.ID != "" && st.AccountID != "" && st.AccountID != accountID {
		return p.conflict(iamv1alpha1.ReasonAccountMismatch,
			fmt.Sprintf("account %s of kaname account %s differs from namespace account %s", st.AccountID, st.ID, accountID))
	}
	st.AccountID = accountID

	if st.PendingOperation != nil {
		if res, err, proceed := p.resolvePending(ctx); !proceed {
			return res, err
		}
	}
	if st.ID == "" {
		return p.ensureIdentity(ctx, accountID)
	}

	remote, err := p.r.Kaname.GetServiceAccount(ctx, st.ID)
	if kaname.Classify(err) == kaname.ClassNotFound {
		p.observeResync()
		if !p.resyncNow {
			return p.drift(iamv1alpha1.ReasonDeletedExternally,
				fmt.Sprintf("kaname account %s was deleted outside the operator", st.ID))
		}
		p.r.Recorder.Eventf(sa, nil, corev1.EventTypeNormal, "Resync", "Reconcile", "recreating kaname account %s deleted outside the operator", st.ID)
		st.ID = ""
		st.Keys = nil
		return ctrl.Result{RequeueAfter: requeueNow}, nil
	}
	if err != nil {
		return p.fail(err)
	}
	if remote.GetAccountId() != accountID {
		return p.conflict(iamv1alpha1.ReasonAccountMismatch,
			fmt.Sprintf("kaname account %s belongs to account %s, namespace says %s", st.ID, remote.GetAccountId(), accountID))
	}
	if !ownedBy(remote.GetLabels(), string(sa.UID), cfg.ClusterName) {
		return p.conflict(iamv1alpha1.ReasonNotOwned,
			fmt.Sprintf("kaname account %s does not carry the ownership labels of this object", st.ID))
	}
	p.observeResync()

	wantEnabled := sa.Spec.IsEnabled()
	if res, err, proceed := p.reconcileEnabled(ctx, remote, wantEnabled); !proceed {
		return res, err
	}

	wantLabels := desiredLabels(sa.Spec.Labels, sa, cfg.ClusterName)
	var mask []string
	if remote.GetDescription() != sa.Spec.Description {
		mask = append(mask, "description")
	}
	if !equalLabels(remote.GetLabels(), wantLabels) {
		mask = append(mask, "labels")
	}
	if len(mask) > 0 {
		op, err := p.r.Kaname.UpdateServiceAccount(ctx, &iamv1.UpdateServiceAccountRequest{
			ServiceAccountId: st.ID, UpdateMask: &fieldmaskpb.FieldMask{Paths: mask},
			Description: sa.Spec.Description, Labels: wantLabels,
		})
		if err != nil {
			return p.fail(err)
		}
		return p.track(ctx, op, iamv1alpha1.VerbUpdate, "")
	}

	if wantEnabled {
		res, err, proceed := p.reconcileKeys(ctx)
		if !proceed {
			return res, err
		}
	} else {
		p.cond(iamv1alpha1.ConditionKeysReady, metav1.ConditionFalse, iamv1alpha1.ReasonDisabled, "the account is disabled by spec; keys are not issued")
	}

	p.cond(iamv1alpha1.ConditionSynced, metav1.ConditionTrue, iamv1alpha1.ReasonReconciled, "kaname matches spec")
	p.cond(iamv1alpha1.ConditionConflict, metav1.ConditionFalse, iamv1alpha1.ReasonNoConflict, "")
	if len(p.keyDrift) > 0 {
		msg := fmt.Sprintf("keys %v were revoked in kaname outside the operator", p.keyDrift)
		p.cond(iamv1alpha1.ConditionKeysReady, metav1.ConditionFalse, iamv1alpha1.ReasonKeyRevoked, msg)
		return p.drift(iamv1alpha1.ReasonKeyRevoked, msg)
	}
	p.cond(iamv1alpha1.ConditionDrifted, metav1.ConditionFalse, iamv1alpha1.ReasonNoDrift, "")
	if wantEnabled {
		p.cond(iamv1alpha1.ConditionKeysReady, metav1.ConditionTrue, iamv1alpha1.ReasonReconciled, "")
		p.cond(iamv1alpha1.ConditionReady, metav1.ConditionTrue, iamv1alpha1.ReasonReconciled, "")
	} else {
		p.cond(iamv1alpha1.ConditionReady, metav1.ConditionTrue, iamv1alpha1.ReasonDisabled, "disabled by spec")
	}
	after := p.r.DriftInterval
	if !p.wake.IsZero() {
		after = min(after, max(p.wake.Sub(p.now()), requeueNow))
	}
	return ctrl.Result{RequeueAfter: after}, nil
}

// reconcileEnabled сводит включённость учётки со spec. proceed — включённость
// сошлась, проход идёт дальше.
func (p *saPass) reconcileEnabled(ctx context.Context, remote *iamv1.ServiceAccount, wantEnabled bool) (ctrl.Result, error, bool) {
	sa, st := p.sa, &p.sa.Status
	switch {
	case wantEnabled && !remote.GetEnabled():
		// Отключение, записанное оператором по spec, снимается по spec;
		// отключение мимо оператора — дрейф до resync.
		switch {
		case st.DisabledBySpec:
			p.r.Recorder.Eventf(sa, nil, corev1.EventTypeNormal, "Enable", "Reconcile", "enabling kaname account %s by spec", st.ID)
		case p.resyncNow:
			p.r.Recorder.Eventf(sa, nil, corev1.EventTypeNormal, "Resync", "Reconcile", "re-enabling kaname account %s", st.ID)
		default:
			res, err := p.drift(iamv1alpha1.ReasonDisabledExternally,
				fmt.Sprintf("kaname account %s was disabled outside the operator", st.ID))
			return res, err, false
		}
		op, err := p.r.Kaname.EnableServiceAccount(ctx, st.ID)
		if err != nil {
			res, ferr := p.fail(err)
			return res, ferr, false
		}
		res, err := p.track(ctx, op, iamv1alpha1.VerbEnable, "")
		return res, err, false
	case !wantEnabled && remote.GetEnabled():
		// Намерение — до вызова: отключение, исполненное без записи признака,
		// при включении по spec читалось бы ручным.
		if !st.DisabledBySpec {
			st.DisabledBySpec = true
			if err := p.save(ctx); err != nil {
				return ctrl.Result{}, err, false
			}
		}
		op, err := p.r.Kaname.DisableServiceAccount(ctx, st.ID)
		if err != nil {
			res, ferr := p.fail(err)
			return res, ferr, false
		}
		res, err := p.track(ctx, op, iamv1alpha1.VerbDisable, "")
		return res, err, false
	case wantEnabled && remote.GetEnabled():
		// Учётка включена (оператором или мимо него): признак снят.
		st.DisabledBySpec = false
	}
	return ctrl.Result{}, nil, true
}

// ensureIdentity усыновляет учётку с тем же именем, если она своя, либо
// заводит новую. Чужая учётка с тем же именем — Conflict без вызовов.
func (p *saPass) ensureIdentity(ctx context.Context, accountID string) (ctrl.Result, error) {
	sa, cfg := p.sa, p.r.Config
	found, err := p.r.Kaname.FindServiceAccountByName(ctx, accountID, sa.Spec.Name)
	if err != nil {
		return p.fail(err)
	}
	if found != nil {
		if !ownedBy(found.GetLabels(), string(sa.UID), cfg.ClusterName) {
			return p.conflict(iamv1alpha1.ReasonNotOwned,
				fmt.Sprintf("kaname account %q (%s) exists in account %s and is not owned by this object", sa.Spec.Name, found.GetId(), accountID))
		}
		sa.Status.ID = found.GetId()
		p.r.Recorder.Eventf(sa, nil, corev1.EventTypeNormal, "Adopted", "Reconcile", "adopted kaname account %s", found.GetId())
		return ctrl.Result{RequeueAfter: requeueNow}, nil
	}
	// Намерение — до вызова: аккаунт в status (с проверкой resourceVersion).
	// Учётка, чей id не дошёл до status, находится по нему и при удалении CR.
	p.notReady(iamv1alpha1.ReasonInProgress, "creating the kaname account")
	if err := p.save(ctx); err != nil {
		return ctrl.Result{}, err
	}
	op, err := p.r.Kaname.CreateServiceAccount(ctx, &iamv1.CreateServiceAccountRequest{
		AccountId: accountID, Name: sa.Spec.Name, Description: sa.Spec.Description,
		Labels: desiredLabels(sa.Spec.Labels, sa, cfg.ClusterName),
	})
	if err != nil {
		if kaname.Classify(err) == kaname.ClassAlreadyExists {
			return ctrl.Result{RequeueAfter: requeueNow}, nil
		}
		return p.fail(err)
	}
	return p.track(ctx, op, iamv1alpha1.VerbCreate, "")
}

// track применяет завершённую операцию сразу либо записывает её в status.
func (p *saPass) track(ctx context.Context, op *operationpb.Operation, verb iamv1alpha1.OperationVerb, subject string) (ctrl.Result, error) {
	if op.GetDone() {
		return p.apply(ctx, verb, subject, op)
	}
	p.sa.Status.PendingOperation = newPending(op, verb, subject, p.now())
	p.notReady(iamv1alpha1.ReasonInProgress, fmt.Sprintf("kaname operation %s (%s) in progress", op.GetId(), verb))
	if err := p.save(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: pollInitial}, nil
}

// resolvePending дочитывает записанную операцию. proceed — проход идёт дальше.
func (p *saPass) resolvePending(ctx context.Context) (ctrl.Result, error, bool) {
	pend := p.sa.Status.PendingOperation
	op, err := p.r.Kaname.GetOperation(ctx, pend.ID)
	if kaname.Classify(err) == kaname.ClassNotFound {
		// Операции нет (истекла либо не наша): состояние перечитывается.
		p.sa.Status.PendingOperation = nil
		return ctrl.Result{}, nil, true
	}
	if err != nil {
		res, ferr := p.fail(err)
		return res, ferr, false
	}
	if !op.GetDone() {
		p.notReady(iamv1alpha1.ReasonInProgress, fmt.Sprintf("kaname operation %s (%s) in progress", op.GetId(), pend.Verb))
		return ctrl.Result{RequeueAfter: pollDelay(pend.StartedAt.Time, p.now())}, nil, false
	}
	p.sa.Status.PendingOperation = nil
	res, err := p.apply(ctx, pend.Verb, pend.Subject, op)
	return res, err, false
}

// apply применяет результат завершённой операции.
func (p *saPass) apply(ctx context.Context, verb iamv1alpha1.OperationVerb, subject string, op *operationpb.Operation) (ctrl.Result, error) {
	st := &p.sa.Status
	switch verb {
	case iamv1alpha1.VerbCreate:
		var out iamv1.ServiceAccount
		err := kaname.OperationResult(op, &out)
		switch {
		case err == nil:
			st.ID = out.GetId()
			p.r.Recorder.Eventf(p.sa, nil, corev1.EventTypeNormal, "Created", "Reconcile", "created kaname account %s", out.GetId())
		case kaname.Classify(err) == kaname.ClassAlreadyExists:
			// Учётка с этим именем появилась между поиском и созданием:
			// следующий проход её найдёт и решит, своя ли она.
		default:
			return p.fail(err)
		}
	case iamv1alpha1.VerbIssueKey:
		return p.applyIssue(ctx, subject, op)
	case iamv1alpha1.VerbRevokeKey:
		if err := kaname.OperationResult(op, nil); err != nil && kaname.Classify(err) != kaname.ClassNotFound {
			return p.fail(err)
		}
		p.keyRevoked(subject)
	case iamv1alpha1.VerbDelete:
		if err := kaname.OperationResult(op, nil); err != nil && kaname.Classify(err) != kaname.ClassNotFound {
			return p.fail(err)
		}
		st.ID = ""
	case iamv1alpha1.VerbEnable:
		if err := kaname.OperationResult(op, nil); err != nil {
			return p.fail(err)
		}
		st.DisabledBySpec = false
	default:
		if err := kaname.OperationResult(op, nil); err != nil {
			return p.fail(err)
		}
	}
	if err := p.save(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeueNow}, nil
}

// finalize — удаление CR: ждать снятия ссылающихся выдач, отключить учётку,
// отозвать ключи, удалить записи Vault, удалить учётку, снять финализатор.
func (p *saPass) finalize(ctx context.Context) (ctrl.Result, error) {
	sa, st := p.sa, &p.sa.Status
	if !controllerutil.ContainsFinalizer(sa, iamv1alpha1.Finalizer) {
		return ctrl.Result{}, nil
	}
	if sa.Spec.EffectiveDeletionPolicy() == iamv1alpha1.DeletionPolicyOrphan {
		return p.removeFinalizer(ctx)
	}
	if st.PendingOperation != nil {
		if res, err, proceed := p.resolvePending(ctx); !proceed {
			return res, err
		}
	}
	var refs iamv1alpha1.AccessBindingList
	if err := p.r.List(ctx, &refs, client.InNamespace(sa.Namespace), client.MatchingFields{indexBindingSA: sa.Name}); err != nil {
		return ctrl.Result{}, err
	}
	if len(refs.Items) > 0 {
		names := make([]string, 0, len(refs.Items))
		for _, it := range refs.Items {
			names = append(names, it.Name)
		}
		p.notReady(iamv1alpha1.ReasonDeletionBlocked, fmt.Sprintf("access bindings %v still refer to this account", names))
		return ctrl.Result{RequeueAfter: deletionBlockedRecheck}, nil
	}
	cfg := p.r.Config
	if st.ID == "" {
		// Учётка могла завестись, а id — не дойти до status: ищется своя по
		// имени в аккаунте status либо, если его нет, namespace.
		accounts, err := deletionAccounts(ctx, p.r.Client, sa.Namespace, st.AccountID)
		if err != nil {
			return ctrl.Result{}, err
		}
		for _, acc := range accounts {
			found, err := p.r.Kaname.FindServiceAccountByName(ctx, acc, sa.Spec.Name)
			if err != nil {
				return p.fail(err)
			}
			if found != nil && ownedBy(found.GetLabels(), string(sa.UID), cfg.ClusterName) {
				st.ID, st.AccountID = found.GetId(), acc
				return ctrl.Result{RequeueAfter: requeueNow}, nil
			}
		}
	}
	if st.ID != "" {
		remote, err := p.r.Kaname.GetServiceAccount(ctx, st.ID)
		switch {
		case kaname.Classify(err) == kaname.ClassNotFound:
			st.ID = ""
		case err != nil:
			return p.fail(err)
		case !ownedBy(remote.GetLabels(), string(sa.UID), cfg.ClusterName):
			// Чужую учётку оператор не трогает и при удалении.
			st.ID = ""
		default:
			return p.teardown(ctx, remote)
		}
	}
	if err := p.deleteVaultRecords(ctx); err != nil {
		return p.failVault(err)
	}
	return p.removeFinalizer(ctx)
}

// teardown — шаги снятия существующей своей учётки по одному за проход.
func (p *saPass) teardown(ctx context.Context, remote *iamv1.ServiceAccount) (ctrl.Result, error) {
	st := &p.sa.Status
	if remote.GetEnabled() {
		op, err := p.r.Kaname.DisableServiceAccount(ctx, st.ID)
		if err != nil {
			return p.fail(err)
		}
		return p.track(ctx, op, iamv1alpha1.VerbDisable, "")
	}
	keys, err := p.r.Kaname.ListKeys(ctx, st.ID)
	if err != nil && kaname.Classify(err) != kaname.ClassNotFound {
		return p.fail(err)
	}
	// Учётка своя и удаляется: отзываются ВСЕ её ключи, в том числе выпущенные
	// мимо оператора, — kaname не удаляет учётку с действующими ключами.
	for _, k := range keys {
		op, err := p.r.Kaname.RevokeKey(ctx, st.ID, k.GetId())
		if kaname.Classify(err) == kaname.ClassNotFound {
			continue
		}
		if err != nil {
			return p.fail(err)
		}
		metrics.KeysRevoked.WithLabelValues("deletion").Inc()
		return p.track(ctx, op, iamv1alpha1.VerbRevokeKey, k.GetLabels()[iamv1alpha1.LabelKeyName]+"/"+k.GetId())
	}
	if err := p.deleteVaultRecords(ctx); err != nil {
		return p.failVault(err)
	}
	op, err := p.r.Kaname.DeleteServiceAccount(ctx, st.ID)
	if kaname.Classify(err) == kaname.ClassNotFound {
		st.ID = ""
		return ctrl.Result{RequeueAfter: requeueNow}, nil
	}
	if err != nil {
		return p.fail(err)
	}
	return p.track(ctx, op, iamv1alpha1.VerbDelete, "")
}

func (p *saPass) removeFinalizer(ctx context.Context) (ctrl.Result, error) {
	if err := p.save(ctx); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	controllerutil.RemoveFinalizer(p.sa, iamv1alpha1.Finalizer)
	if err := p.r.Update(ctx, p.sa); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	p.saved = p.sa.Status.DeepCopy()
	return ctrl.Result{}, nil
}
