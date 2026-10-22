// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/metrics"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/policy"
)

const (
	kindAB = "AccessBinding"
	// pendingRecheck — пауза ожидания цели либо субъекта (и страховка к
	// событию, которое их принесёт).
	pendingRecheck = 30 * time.Second
)

// AccessBindingReconciler отражает CR AccessBinding в выдачу kaname.
type AccessBindingReconciler struct {
	client.Client
	*Deps
	Mapper meta.RESTMapper
	// Reader — чтение мимо кэша: объекты целей разных видов не держат
	// информеров и требуют только права get.
	Reader client.Reader
}

// +kubebuilder:rbac:groups=iam.kaname.in-cloud.io,resources=accessbindings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=iam.kaname.in-cloud.io,resources=accessbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.kaname.in-cloud.io,resources=accessbindings/finalizers,verbs=update
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingadmissionpolicies;validatingadmissionpolicybindings,verbs=get

// SetupAccessBindingReconciler регистрирует контроллер AccessBinding.
func SetupAccessBindingReconciler(mgr ctrl.Manager, d *Deps) error {
	r := &AccessBindingReconciler{Client: mgr.GetClient(), Deps: d, Mapper: mgr.GetRESTMapper(), Reader: mgr.GetAPIReader()}
	return ctrl.NewControllerManagedBy(mgr).
		For(&iamv1alpha1.AccessBinding{}, builder.WithPredicates(specOrMetaChanged())).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.forNamespace),
			builder.WithPredicates(predicate.AnnotationChangedPredicate{})).
		Watches(&iamv1alpha1.ServiceAccount{}, handler.EnqueueRequestsFromMapFunc(r.forServiceAccount)).
		WithOptions(d.controllerOptions()).
		Named("accessbinding").
		Complete(r)
}

func (r *AccessBindingReconciler) forNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	var list iamv1alpha1.AccessBindingList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetName())); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(list.Items))
	for _, it := range list.Items {
		out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&it)})
	}
	return out
}

// forServiceAccount будит выдачи, чей субъект — эта учётка.
func (r *AccessBindingReconciler) forServiceAccount(ctx context.Context, obj client.Object) []reconcile.Request {
	var list iamv1alpha1.AccessBindingList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace()), client.MatchingFields{indexBindingSA: obj.GetName()}); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(list.Items))
	for _, it := range list.Items {
		out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&it)})
	}
	return out
}

// Reconcile — один проход.
func (r *AccessBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ab := &iamv1alpha1.AccessBinding{}
	if err := r.Get(ctx, req.NamespacedName, ab); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	p := &abPass{r: r, ab: ab, saved: ab.Status.DeepCopy()}
	if !ab.DeletionTimestamp.IsZero() {
		res, err := p.finalize(ctx)
		return p.finish(ctx, res, err)
	}
	if !controllerutil.ContainsFinalizer(ab, iamv1alpha1.Finalizer) {
		controllerutil.AddFinalizer(ab, iamv1alpha1.Finalizer)
		if err := r.Update(ctx, ab); err != nil {
			return ctrl.Result{}, err
		}
		p.saved = ab.Status.DeepCopy()
	}
	res, err := p.reconcile(ctx)
	ab.Status.ObservedGeneration = ab.Generation
	return p.finish(ctx, res, err)
}

type abPass struct {
	r         *AccessBindingReconciler
	ab        *iamv1alpha1.AccessBinding
	saved     *iamv1alpha1.AccessBindingStatus
	resyncNow bool
}

func (p *abPass) now() time.Time { return p.r.now() }

func (p *abPass) cond(typ string, status metav1.ConditionStatus, reason, msg string) {
	setCondition(&p.ab.Status.Conditions, p.ab.Generation, typ, status, reason, msg)
}

func (p *abPass) save(ctx context.Context) error {
	if equality.Semantic.DeepEqual(p.saved, &p.ab.Status) {
		return nil
	}
	if err := p.r.Status().Update(ctx, p.ab); err != nil {
		return err
	}
	p.saved = p.ab.Status.DeepCopy()
	return nil
}

func (p *abPass) finish(ctx context.Context, res ctrl.Result, err error) (ctrl.Result, error) {
	if serr := p.save(ctx); serr != nil {
		if apierrors.IsNotFound(serr) {
			return ctrl.Result{}, nil
		}
		if isConflict(serr) {
			return ctrl.Result{RequeueAfter: requeueNow}, nil
		}
		return ctrl.Result{}, serr
	}
	if errors.Is(err, errRequeue) || (err != nil && isConflict(err)) {
		return ctrl.Result{RequeueAfter: requeueNow}, nil
	}
	return res, err
}

func (p *abPass) notReady(reason, msg string) {
	p.cond(iamv1alpha1.ConditionReady, metav1.ConditionFalse, reason, msg)
}

func (p *abPass) fail(err error) (ctrl.Result, error) {
	o := classify(kindAB, err)
	p.cond(iamv1alpha1.ConditionSynced, metav1.ConditionFalse, o.reason, o.message)
	p.notReady(o.reason, o.message)
	if o.reason == iamv1alpha1.ReasonForbidden {
		p.r.Recorder.Eventf(p.ab, nil, corev1.EventTypeWarning, iamv1alpha1.ReasonForbidden, "Reconcile", "kaname refused the operator: %s", o.message)
	}
	return o.result()
}

// refuse — выдача запрещена конфигурацией оператора: kaname не зовётся.
func (p *abPass) refuse(v *policy.Violation) (ctrl.Result, error) {
	p.cond(iamv1alpha1.ConditionSynced, metav1.ConditionFalse, v.Reason, v.Message)
	p.notReady(v.Reason, v.Message)
	if v.Reason == iamv1alpha1.ReasonForbidden {
		metrics.Refusals.WithLabelValues(kindAB, v.Reason).Inc()
		p.r.Recorder.Eventf(p.ab, nil, corev1.EventTypeWarning, v.Reason, "Reconcile", "%s", v.Message)
		return ctrl.Result{RequeueAfter: invalidRecheck}, nil
	}
	return ctrl.Result{RequeueAfter: pendingRecheck}, nil
}

// conflict — в kaname уже есть чужая выдача (без меток владения этого CR).
func (p *abPass) conflict(msg string) (ctrl.Result, error) {
	reason := iamv1alpha1.ReasonNotOwned
	p.cond(iamv1alpha1.ConditionConflict, metav1.ConditionTrue, reason, msg)
	p.notReady(reason, msg)
	metrics.Refusals.WithLabelValues(kindAB, reason).Inc()
	p.r.Recorder.Eventf(p.ab, nil, corev1.EventTypeWarning, reason, "Reconcile", "%s", msg)
	return ctrl.Result{RequeueAfter: conflictRecheck}, nil
}

// drift — выдача отозвана в kaname мимо оператора.
func (p *abPass) drift(msg string) (ctrl.Result, error) {
	reason := iamv1alpha1.ReasonRevokedExternally
	if c := findCondition(p.ab.Status.Conditions, iamv1alpha1.ConditionDrifted); c == nil || c.Status != metav1.ConditionTrue || c.Reason != reason {
		metrics.Drift.WithLabelValues(kindAB, reason).Inc()
		p.r.Recorder.Eventf(p.ab, nil, corev1.EventTypeWarning, reason, "Reconcile",
			"%s; the operator does not undo it — set annotation %s to restore", msg, iamv1alpha1.AnnotationResyncDrift)
	}
	p.cond(iamv1alpha1.ConditionDrifted, metav1.ConditionTrue, reason, msg)
	p.notReady(reason, msg)
	return ctrl.Result{RequeueAfter: p.r.DriftInterval}, nil
}

func (p *abPass) observeResync() {
	ann := p.ab.Annotations[iamv1alpha1.AnnotationResyncDrift]
	if ann != "" && ann != p.ab.Status.ResyncNonce {
		p.resyncNow = true
		p.ab.Status.ResyncNonce = ann
	}
}

func (p *abPass) owned(labels map[string]string) bool {
	return ownedBy(labels, string(p.ab.UID), p.r.Config.ClusterName)
}

// desired — выдача в терминах kaname: субъекты, роль, область.
type desired struct {
	resolved iamv1alpha1.ResolvedBinding
	subjects []*iamv1.Subject
	target   *iamv1.AccessTarget
	hash     string
}

func (p *abPass) reconcile(ctx context.Context) (ctrl.Result, error) {
	ab, st := p.ab, &p.ab.Status
	ns := &corev1.Namespace{}
	if err := p.r.Get(ctx, client.ObjectKey{Name: ab.Namespace}, ns); err != nil {
		return ctrl.Result{}, err
	}
	scopeType := ab.Spec.EffectiveScopeType()
	ann := iamv1alpha1.AnnotationProjectID
	if scopeType == iamv1alpha1.ScopeAccount {
		ann = iamv1alpha1.AnnotationAccountID
	}
	scopeID, accountID := ns.Annotations[ann], ns.Annotations[iamv1alpha1.AnnotationAccountID]
	if scopeID == "" || accountID == "" {
		p.notReady(iamv1alpha1.ReasonScopeUnresolved, fmt.Sprintf("namespace %s needs annotations %s and %s",
			ab.Namespace, iamv1alpha1.AnnotationAccountID, ann))
		return ctrl.Result{}, nil
	}
	if v := policy.Evaluate(p.r.Config.Policy, ab); v != nil {
		return p.refuse(v)
	}
	if policy.NeedsAdmissionGuarantee(ab) {
		v, err := policy.CheckAdmissionGuarantee(ctx, p.r.Reader, p.r.Config.Policy.AdmissionGuard, ab.CreationTimestamp.Time)
		if err != nil {
			return ctrl.Result{}, err
		}
		if v != nil {
			return p.refuse(v)
		}
	}
	v, err := policy.ResolveTargets(ctx, p.r.Reader, p.r.Mapper, p.r.Config.Policy, ab.Namespace, ab.Spec.Target.Resources)
	if err != nil {
		return ctrl.Result{}, err
	}
	if v != nil {
		return p.refuse(v)
	}
	if st.PendingOperation != nil {
		if res, err, proceed := p.resolvePending(ctx); !proceed {
			return res, err
		}
	}
	want, res, err, ok := p.resolve(ctx, accountID, string(scopeType), scopeID)
	if !ok {
		return res, err
	}
	if st.ID == "" {
		return p.ensureBinding(ctx, want)
	}
	remote, err := p.r.Kaname.GetAccessBinding(ctx, st.ID)
	gone := kaname.Classify(err) == kaname.ClassNotFound || (err == nil && remote.GetStatus() == iamv1.AccessBinding_REVOKED)
	if gone {
		p.observeResync()
		if !p.resyncNow {
			return p.drift(fmt.Sprintf("kaname binding %s was revoked outside the operator", st.ID))
		}
		p.r.Recorder.Eventf(ab, nil, corev1.EventTypeNormal, "Resync", "Reconcile", "regranting binding %s revoked outside the operator", st.ID)
		st.ID, st.BindingHash = "", ""
		return ctrl.Result{RequeueAfter: requeueNow}, nil
	}
	if err != nil {
		return p.fail(err)
	}
	if !p.owned(remote.GetLabels()) {
		return p.conflict(fmt.Sprintf("kaname binding %s does not carry the ownership labels of this object", st.ID))
	}
	p.observeResync()
	if st.BindingHash != want.hash {
		// Прежняя замена ещё не отозвана: сначала она, иначе её id затёрся бы
		// и выдача осталась бы действовать без хозяина.
		if st.Replaced != nil {
			return p.revoke(ctx, st.Replaced.ID)
		}
		// Цель (как и субъекты, роль, область, срок) в kaname неизменяема:
		// новая выдача заводится первой, прежняя отзывается после неё.
		st.Replaced = &iamv1alpha1.ReplacedBinding{ID: st.ID}
		st.ID, st.BindingHash = "", ""
		p.notReady(iamv1alpha1.ReasonInProgress, "replacing the binding: target, subjects or expiry changed")
		if err := p.save(ctx); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueNow}, nil
	}
	wantLabels := desiredLabels(ab.Spec.Labels, ab, p.r.Config.ClusterName)
	if !equalLabels(remote.GetLabels(), wantLabels) {
		op, err := p.r.Kaname.UpdateAccessBinding(ctx, &iamv1.UpdateAccessBindingRequest{
			AccessBindingId: st.ID, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}}, Labels: wantLabels,
		})
		if err != nil {
			return p.fail(err)
		}
		return p.track(ctx, op, iamv1alpha1.VerbUpdate, st.ID)
	}
	if st.Replaced != nil {
		return p.revoke(ctx, st.Replaced.ID)
	}
	p.cond(iamv1alpha1.ConditionSynced, metav1.ConditionTrue, iamv1alpha1.ReasonReconciled, "kaname matches spec")
	p.cond(iamv1alpha1.ConditionConflict, metav1.ConditionFalse, iamv1alpha1.ReasonNoConflict, "")
	p.cond(iamv1alpha1.ConditionDrifted, metav1.ConditionFalse, iamv1alpha1.ReasonNoDrift, "")
	p.cond(iamv1alpha1.ConditionReady, metav1.ConditionTrue, iamv1alpha1.ReasonReconciled, "")
	return ctrl.Result{RequeueAfter: p.r.DriftInterval}, nil
}

// resolve переводит субъектов, роль и область в термины kaname.
func (p *abPass) resolve(ctx context.Context, accountID, scopeType, scopeID string) (desired, ctrl.Result, error, bool) {
	ab := p.ab
	var subjects []*iamv1.Subject
	var resolved []iamv1alpha1.ResolvedSubject
	for _, s := range ab.Spec.Subjects {
		var sub *iamv1.Subject
		switch {
		case s.ServiceAccountRef != nil:
			sa := &iamv1alpha1.ServiceAccount{}
			err := p.r.Get(ctx, client.ObjectKey{Namespace: ab.Namespace, Name: s.ServiceAccountRef.Name}, sa)
			if err != nil && !apierrors.IsNotFound(err) {
				return desired{}, ctrl.Result{}, err, false
			}
			ready := findCondition(sa.Status.Conditions, iamv1alpha1.ConditionReady)
			if apierrors.IsNotFound(err) || sa.Status.ID == "" || ready == nil || ready.Status != metav1.ConditionTrue || !sa.DeletionTimestamp.IsZero() {
				msg := fmt.Sprintf("service account %s is not ready", s.ServiceAccountRef.Name)
				p.cond(iamv1alpha1.ConditionSubjectPending, metav1.ConditionTrue, iamv1alpha1.ReasonSubjectNotReady, msg)
				p.notReady(iamv1alpha1.ReasonSubjectNotReady, msg)
				return desired{}, ctrl.Result{RequeueAfter: pendingRecheck}, nil, false
			}
			sub = &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, Id: sa.Status.ID}
		case s.User != nil:
			sub = &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_USER, Id: s.User.ID}
		case s.Group != nil:
			sub = &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_GROUP, Id: s.Group.ID}
		case s.SystemClass != nil:
			sub = &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_SYSTEM_CLASS, Id: string(s.SystemClass.Name)}
		}
		subjects = append(subjects, sub)
		resolved = append(resolved, iamv1alpha1.ResolvedSubject{Type: sub.GetType().String(), ID: sub.GetId()})
	}
	p.cond(iamv1alpha1.ConditionSubjectPending, metav1.ConditionFalse, iamv1alpha1.ReasonSubjectsResolved, "")
	role, err := p.r.Kaname.FindSystemRole(ctx, ab.Spec.RoleRef.Name)
	if err != nil {
		res, ferr := p.fail(err)
		return desired{}, res, ferr, false
	}
	refs := make([]*iamv1.ResourceRef, 0, len(ab.Spec.Target.Resources))
	for _, t := range ab.Spec.Target.Resources {
		refs = append(refs, &iamv1.ResourceRef{Type: t.Type, Id: t.ID})
	}
	want := desired{
		resolved: iamv1alpha1.ResolvedBinding{Subjects: resolved, RoleID: role.GetId(), ScopeType: scopeType, ScopeID: scopeID, AccountID: accountID},
		subjects: subjects,
		target:   &iamv1.AccessTarget{Target: &iamv1.AccessTarget_Resources{Resources: &iamv1.AccessTargetResources{Resources: refs}}},
	}
	want.hash = bindingHash(subjects, role.GetId(), scopeType, scopeID, refs, ab.Spec.ExpiresAt)
	return want, ctrl.Result{}, nil, true
}

// bindingHash — отпечаток неизменяемой части выдачи kaname.
func bindingHash(subjects []*iamv1.Subject, roleID, scopeType, scopeID string, targets []*iamv1.ResourceRef, expires *metav1.Time) string {
	subs := make([]string, 0, len(subjects))
	for _, s := range subjects {
		subs = append(subs, s.GetType().String()+":"+s.GetId())
	}
	sort.Strings(subs)
	tgts := make([]string, 0, len(targets))
	for _, t := range targets {
		tgts = append(tgts, t.GetType()+":"+t.GetId())
	}
	sort.Strings(tgts)
	exp := ""
	if expires != nil {
		exp = expires.UTC().Format(time.RFC3339)
	}
	h := sha256.Sum256([]byte(strings.Join([]string{
		strings.Join(subs, ","), roleID, scopeType, scopeID, strings.Join(tgts, ","), exp,
	}, "\n")))
	return hex.EncodeToString(h[:16])
}

// sameBinding — совпадает ли выдача kaname с желаемой по неизменяемой части.
func sameBinding(b *iamv1.AccessBinding, want desired) bool {
	if b.GetStatus() == iamv1.AccessBinding_REVOKED || b.GetTarget().GetAllInScope() != nil {
		return false
	}
	return bindingHash(b.GetSubjects(), b.GetRoleId(), b.GetScopeType(), b.GetScopeId(),
		b.GetTarget().GetResources().GetResources(), expiresOf(b)) == want.hash
}

// expiresOf — срок выдачи kaname в той же форме, что и в spec.
func expiresOf(b *iamv1.AccessBinding) *metav1.Time {
	if b.GetExpiresAt() == nil {
		return nil
	}
	t := metav1.NewTime(b.GetExpiresAt().AsTime())
	return &t
}

// ensureBinding усыновляет свою выдачу с тем же ключом либо заводит новую.
// Чужая выдача с тем же ключом — Conflict без вызовов. Свои выдачи с другим
// ключом, кроме прежней (Replaced), — следы создания, чей id не дошёл до
// status: они отзываются раньше, чем заводится новая, по одной за проход.
func (p *abPass) ensureBinding(ctx context.Context, want desired) (ctrl.Result, error) {
	ab, st := p.ab, &p.ab.Status
	list, err := p.r.Kaname.ListAccessBindingsByAccount(ctx, want.resolved.AccountID)
	if err != nil {
		return p.fail(err)
	}
	var adopt *iamv1.AccessBinding
	for _, b := range list {
		if b.GetStatus() == iamv1.AccessBinding_REVOKED {
			continue
		}
		owned := p.owned(b.GetLabels())
		switch {
		case sameBinding(b, want) && !owned:
			return p.conflict(fmt.Sprintf("kaname binding %s with the same subjects, role, scope and target exists and is not owned by this object", b.GetId()))
		case sameBinding(b, want):
			adopt = b
		case owned && (st.Replaced == nil || b.GetId() != st.Replaced.ID):
			p.r.Recorder.Eventf(ab, nil, corev1.EventTypeNormal, "RevokingStray", "Reconcile",
				"revoking kaname binding %s: owned by this object but not the one it holds", b.GetId())
			return p.revoke(ctx, b.GetId())
		}
	}
	if adopt != nil {
		st.ID, st.BindingHash, st.PendingHash = adopt.GetId(), want.hash, ""
		resolved := want.resolved
		st.Resolved = &resolved
		// Возврат прежней цели: прежняя выдача снова действующая, отзывать её
		// как замену — значит разорвать доступ.
		if st.Replaced != nil && st.Replaced.ID == adopt.GetId() {
			st.Replaced = nil
		}
		p.r.Recorder.Eventf(ab, nil, corev1.EventTypeNormal, "Adopted", "Reconcile", "adopted kaname binding %s", adopt.GetId())
		return ctrl.Result{RequeueAfter: requeueNow}, nil
	}
	req := &iamv1.CreateAccessBindingRequest{
		Subjects: want.subjects, RoleId: want.resolved.RoleID, ScopeType: want.resolved.ScopeType, ScopeId: want.resolved.ScopeID,
		Target: want.target, Labels: desiredLabels(ab.Spec.Labels, ab, p.r.Config.ClusterName),
	}
	if ab.Spec.ExpiresAt != nil {
		req.ExpiresAt = timestamppb.New(ab.Spec.ExpiresAt.Time)
	}
	// Намерение — до вызова, с проверкой resourceVersion: аккаунт выдачи и её
	// отпечаток. Конфликт версии — выдачи нет; запись после вызова потеряна —
	// выдача находится по меткам владения и при следующем проходе, и при
	// удалении CR.
	resolved := want.resolved
	st.Resolved, st.PendingHash = &resolved, want.hash
	p.notReady(iamv1alpha1.ReasonInProgress, "creating the kaname binding")
	if err := p.save(ctx); err != nil {
		return ctrl.Result{}, err
	}
	op, err := p.r.Kaname.CreateAccessBinding(ctx, req)
	if err != nil {
		if kaname.Classify(err) == kaname.ClassAlreadyExists {
			return ctrl.Result{RequeueAfter: requeueNow}, nil
		}
		return p.fail(err)
	}
	return p.track(ctx, op, iamv1alpha1.VerbCreate, "")
}

func (p *abPass) revoke(ctx context.Context, id string) (ctrl.Result, error) {
	op, err := p.r.Kaname.RevokeAccessBinding(ctx, id)
	if kaname.Classify(err) == kaname.ClassNotFound {
		p.bindingGone(id)
		if err := p.save(ctx); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueNow}, nil
	}
	if err != nil {
		return p.fail(err)
	}
	return p.track(ctx, op, iamv1alpha1.VerbRevoke, id)
}

func (p *abPass) bindingGone(id string) {
	st := &p.ab.Status
	if st.Replaced != nil && st.Replaced.ID == id {
		st.Replaced = nil
	}
	if st.ID == id {
		st.ID, st.BindingHash = "", ""
	}
}

func (p *abPass) track(ctx context.Context, op *operationpb.Operation, verb iamv1alpha1.OperationVerb, subject string) (ctrl.Result, error) {
	if op.GetDone() {
		return p.apply(ctx, verb, subject, op)
	}
	p.ab.Status.PendingOperation = newPending(op, verb, subject, p.now())
	p.notReady(iamv1alpha1.ReasonInProgress, fmt.Sprintf("kaname operation %s (%s) in progress", op.GetId(), verb))
	if err := p.save(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: pollInitial}, nil
}

func (p *abPass) resolvePending(ctx context.Context) (ctrl.Result, error, bool) {
	pend := p.ab.Status.PendingOperation
	op, err := p.r.Kaname.GetOperation(ctx, pend.ID)
	if kaname.Classify(err) == kaname.ClassNotFound {
		p.ab.Status.PendingOperation = nil
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
	p.ab.Status.PendingOperation = nil
	res, err := p.apply(ctx, pend.Verb, pend.Subject, op)
	return res, err, false
}

func (p *abPass) apply(ctx context.Context, verb iamv1alpha1.OperationVerb, subject string, op *operationpb.Operation) (ctrl.Result, error) {
	st := &p.ab.Status
	switch verb {
	case iamv1alpha1.VerbCreate:
		var out iamv1.AccessBinding
		err := kaname.OperationResult(op, &out)
		switch {
		case err == nil:
			st.ID, st.BindingHash, st.PendingHash = out.GetId(), st.PendingHash, ""
			p.r.Recorder.Eventf(p.ab, nil, corev1.EventTypeNormal, "Created", "Reconcile", "created kaname binding %s", out.GetId())
		case kaname.Classify(err) == kaname.ClassAlreadyExists:
			// Выдача с тем же ключом появилась между поиском и созданием:
			// следующий проход найдёт её и решит, своя ли она.
			st.PendingHash = ""
		default:
			st.PendingHash = ""
			return p.fail(err)
		}
	case iamv1alpha1.VerbRevoke:
		if err := kaname.OperationResult(op, nil); err != nil && kaname.Classify(err) != kaname.ClassNotFound {
			return p.fail(err)
		}
		p.bindingGone(subject)
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

// finalize — удаление CR: отозвать прежнюю и действующую выдачи, снять
// финализатор. Orphan — только снять финализатор.
func (p *abPass) finalize(ctx context.Context) (ctrl.Result, error) {
	ab, st := p.ab, &p.ab.Status
	if !controllerutil.ContainsFinalizer(ab, iamv1alpha1.Finalizer) {
		return ctrl.Result{}, nil
	}
	if ab.Spec.EffectiveDeletionPolicy() == iamv1alpha1.DeletionPolicyOrphan {
		return p.removeFinalizer(ctx)
	}
	if st.PendingOperation != nil {
		if res, err, proceed := p.resolvePending(ctx); !proceed {
			return res, err
		}
	}
	if st.Replaced != nil {
		return p.revoke(ctx, st.Replaced.ID)
	}
	if st.ID != "" {
		return p.revoke(ctx, st.ID)
	}
	// Выдача могла завестись, но не дойти до status: ищется своя по меткам в
	// аккаунте намерения и в аккаунте namespace.
	recorded := ""
	if st.Resolved != nil {
		recorded = st.Resolved.AccountID
	}
	accounts, err := deletionAccounts(ctx, p.r.Client, ab.Namespace, recorded)
	if err != nil {
		return ctrl.Result{}, err
	}
	for _, acc := range accounts {
		list, err := p.r.Kaname.ListAccessBindingsByAccount(ctx, acc)
		if err != nil {
			return p.fail(err)
		}
		for _, b := range list {
			if b.GetStatus() != iamv1.AccessBinding_REVOKED && p.owned(b.GetLabels()) {
				return p.revoke(ctx, b.GetId())
			}
		}
	}
	return p.removeFinalizer(ctx)
}

func (p *abPass) removeFinalizer(ctx context.Context) (ctrl.Result, error) {
	if err := p.save(ctx); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	controllerutil.RemoveFinalizer(p.ab, iamv1alpha1.Finalizer)
	if err := p.r.Update(ctx, p.ab); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	p.saved = p.ab.Status.DeepCopy()
	return ctrl.Result{}, nil
}
