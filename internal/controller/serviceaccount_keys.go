// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/kaname"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/metrics"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/vault"
)

// Протокол ключа (⛔1 дизайна):
//
//  1. Нужен новый ключ — намерение (nonce, момент) пишется в status ДО выпуска,
//     с проверкой resourceVersion.
//  2. Выпуск в kaname несёт nonce в метках ключа.
//  3. Удостоверение пишется в Vault KV v2 с CAS; запись несёт тот же nonce.
//  4. status получает id ключа и версию записи, прежний ключ — окно перекрытия.
//
// Падение между любыми двумя шагами распознаётся по nonce: запись Vault с
// нашим nonce — выпуск совершён (дочитать status); ключ kaname с нашим nonce
// без записи Vault — секрет потерян (выждать окно уборки, выпустить заново
// с новым nonce, потерянный ключ отзовёт уборка). Источник правды о том,
// какой ключ действует, — запись Vault.

// Значения в записи Vault.
const (
	vaultUsername  = "username"
	vaultPassword  = "password"
	vaultKeyID     = "keyId"
	vaultKind      = "kind"
	vaultSAID      = "serviceAccountId"
	vaultAccountID = "accountId"
	vaultExpiresAt = "expiresAt"
	vaultNonce     = "nonce"
	vaultIssuedAt  = "issuedAt"
	vaultPrivKey   = "privateKeyPem"
	vaultAlgorithm = "algorithm"
	// vaultCASAttempts — повторы записи при конкурентной смене версии.
	vaultCASAttempts = 3
	defaultKeyTTL    = int64(2592000)
	defaultRenew     = int64(864000)
	defaultOverlap   = int64(86400)
)

func newNonce() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func keyKind(s iamv1alpha1.KeySpec) iamv1alpha1.KeyKind {
	if s.Kind == "" {
		return iamv1alpha1.KeyKindSecret
	}
	return s.Kind
}

func keyTTL(s iamv1alpha1.KeySpec) int64 {
	if s.TTLSeconds == 0 {
		return defaultKeyTTL
	}
	return s.TTLSeconds
}

// renewBefore — окно замены: заданное либо min(10 суток, срок/3).
func renewBefore(s iamv1alpha1.KeySpec) time.Duration {
	if v := s.Rotation.RenewBeforeSeconds; v != nil {
		return time.Duration(*v) * time.Second
	}
	return time.Duration(min(defaultRenew, keyTTL(s)/3)) * time.Second
}

// overlap — перекрытие: заданное (0 — сразу) либо min(1 сутки, окно замены).
func overlap(s iamv1alpha1.KeySpec) time.Duration {
	if v := s.Rotation.OverlapSeconds; v != nil {
		return time.Duration(*v) * time.Second
	}
	return min(time.Duration(defaultOverlap)*time.Second, renewBefore(s))
}

func (p *saPass) keyStatus(name string) *iamv1alpha1.KeyStatus {
	return p.sa.Status.KeyStatusByName(name)
}

func (p *saPass) ensureKeyStatus(name string) *iamv1alpha1.KeyStatus {
	if ks := p.keyStatus(name); ks != nil {
		return ks
	}
	p.sa.Status.Keys = append(p.sa.Status.Keys, iamv1alpha1.KeyStatus{Name: name})
	return &p.sa.Status.Keys[len(p.sa.Status.Keys)-1]
}

func (p *saPass) specKey(name string) *iamv1alpha1.KeySpec {
	for i := range p.sa.Spec.Keys {
		if p.sa.Spec.Keys[i].Name == name {
			return &p.sa.Spec.Keys[i]
		}
	}
	return nil
}

func (p *saPass) vaultPath(s iamv1alpha1.KeySpec) (string, string, error) {
	return p.r.Config.VaultPath(s.Delivery.Vault.App, config.PathParams{
		Namespace: p.sa.Namespace, Instance: s.Delivery.Vault.Instance, Name: p.sa.Name, Key: s.Name,
	})
}

func (p *saPass) owned(labels map[string]string) bool {
	return ownedBy(labels, string(p.sa.UID), p.r.Config.ClusterName)
}

func (p *saPass) failVault(err error) (ctrl.Result, error) {
	msg := err.Error()
	p.cond(iamv1alpha1.ConditionKeysReady, metav1.ConditionFalse, iamv1alpha1.ReasonVaultUnavailable, msg)
	p.cond(iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonVaultUnavailable, msg)
	metrics.Refusals.WithLabelValues(kindSA, iamv1alpha1.ReasonVaultUnavailable).Inc()
	if vault.IsForbidden(err) {
		p.r.Recorder.Eventf(p.sa, nil, corev1.EventTypeWarning, iamv1alpha1.ReasonForbidden, "Reconcile", "Vault refused the operator: %s", msg)
		return ctrl.Result{RequeueAfter: forbiddenPause}, nil
	}
	return ctrl.Result{}, fmt.Errorf("vault: %w", err)
}

func (p *saPass) issuing(reason, msg string) {
	p.cond(iamv1alpha1.ConditionKeysReady, metav1.ConditionFalse, reason, msg)
	p.notReady(reason, msg)
}

// reconcileKeys ведёт все ключи spec, снимает удалённые из spec и убирает
// потерянные выпуски. proceed — ключи в порядке, проход идёт дальше.
func (p *saPass) reconcileKeys(ctx context.Context) (ctrl.Result, error, bool) {
	st := &p.sa.Status
	live, err := p.r.Kaname.ListKeys(ctx, st.ID)
	if err != nil {
		res, ferr := p.fail(err)
		return res, ferr, false
	}
	byID := make(map[string]*iamv1.ServiceAccountOAuthClient, len(live))
	for _, k := range live {
		byID[k.GetId()] = k
	}
	for _, spec := range p.sa.Spec.Keys {
		res, err, proceed := p.reconcileKey(ctx, spec, byID)
		if !proceed {
			return res, err, false
		}
	}
	if res, err, proceed := p.dropRemovedKeys(ctx, live); !proceed {
		return res, err, false
	}
	if res, err, proceed := p.sweep(ctx, live); !proceed {
		return res, err, false
	}
	return ctrl.Result{}, nil, true
}

// reconcileKey ведёт один ключ на шаг вперёд.
func (p *saPass) reconcileKey(ctx context.Context, spec iamv1alpha1.KeySpec, live map[string]*iamv1.ServiceAccountOAuthClient) (ctrl.Result, error, bool) {
	mount, path, err := p.vaultPath(spec)
	if err != nil {
		msg := fmt.Sprintf("key %s: delivery: %v", spec.Name, err)
		p.cond(iamv1alpha1.ConditionKeysReady, metav1.ConditionFalse, iamv1alpha1.ReasonInvalid, msg)
		p.notReady(iamv1alpha1.ReasonInvalid, msg)
		return ctrl.Result{RequeueAfter: invalidRecheck}, nil, false
	}
	ks := p.ensureKeyStatus(spec.Name)
	ks.VaultPath = mount + "/" + path
	rec, err := p.r.Vault.Read(ctx, mount, path)
	if err != nil {
		res, ferr := p.failVault(err)
		return res, ferr, false
	}
	now := p.now()
	grace := p.r.Config.Keys.OrphanGrace.Duration

	// A. Незавершённый выпуск.
	if ks.Issuing != nil {
		nonce := ks.Issuing.Nonce
		if rec != nil && rec.Data[vaultNonce] == nonce {
			if k, ok := live[rec.Data[vaultKeyID]]; ok && p.owned(k.GetLabels()) {
				p.finalizeKey(spec, ks, rec.Data[vaultKeyID], k.GetExpiresAt().AsTime(), rec.Version)
				return p.saved3(ctx)
			}
			// Записанный ключ уже отозван: выпуск считается несостоявшимся.
			ks.Issuing = &iamv1alpha1.KeyIssuing{Nonce: newNonce(), At: metav1.NewTime(now)}
			return p.saved3(ctx)
		}
		if k := liveWithNonce(live, nonce, p.owned); k != nil {
			// Ключ выпущен, а запись Vault не сделана: секрет потерян. Окно
			// уборки ждёт, не дописывает ли его другой исполнитель.
			if age := now.Sub(k.GetCreatedAt().AsTime()); age < grace {
				p.issuing(iamv1alpha1.ReasonKeysIssuing, fmt.Sprintf("key %s: issuance %s awaits its Vault record", spec.Name, k.GetId()))
				return ctrl.Result{RequeueAfter: grace - age}, nil, false
			}
			p.r.Recorder.Eventf(p.sa, nil, corev1.EventTypeWarning, "SecretLost", "Reconcile",
				"key %s: issued key %s never reached Vault; reissuing, the lost key will be revoked", spec.Name, k.GetId())
			ks.Issuing = &iamv1alpha1.KeyIssuing{Nonce: newNonce(), At: metav1.NewTime(now)}
			return p.saved3(ctx)
		}
		return p.issue(ctx, spec, ks)
	}

	// B. Запись Vault есть, а status её не знает (status потерян) — усыновить.
	if ks.KeyID == "" && rec != nil && rec.Data[vaultSAID] == p.sa.Status.ID {
		if k, ok := live[rec.Data[vaultKeyID]]; ok && p.owned(k.GetLabels()) {
			ks.KeyID, ks.VaultVersion = k.GetId(), rec.Version
			exp := metav1.NewTime(k.GetExpiresAt().AsTime())
			ks.ExpiresAt = &exp
			return p.saved3(ctx)
		}
	}

	// C. Действующий ключ.
	need := ""
	switch {
	case ks.KeyID == "":
		need = "no key yet"
	case live[ks.KeyID] == nil:
		if !p.resyncNow {
			p.keyDrift = append(p.keyDrift, spec.Name)
			return ctrl.Result{}, nil, true
		}
		p.r.Recorder.Eventf(p.sa, nil, corev1.EventTypeNormal, "Resync", "Reconcile", "key %s: reissuing after a revocation in kaname", spec.Name)
		ks.KeyID, ks.ExpiresAt, ks.VaultVersion, ks.Previous = "", nil, 0, nil
		need = "resync after revocation"
	case rec == nil || rec.Data[vaultKeyID] != ks.KeyID:
		need = "vault record lost"
	case ks.ExpiresAt != nil && ks.ExpiresAt.Sub(now) < renewBefore(spec):
		need = "rotation"
	}
	if need != "" {
		ks.Issuing = &iamv1alpha1.KeyIssuing{Nonce: newNonce(), At: metav1.NewTime(now)}
		p.issuing(iamv1alpha1.ReasonKeysIssuing, fmt.Sprintf("key %s: issuing (%s)", spec.Name, need))
		// Намерение — до вызова kaname: конфликт версии — выпуска нет.
		if err := p.save(ctx); err != nil {
			return ctrl.Result{}, err, false
		}
		return p.issue(ctx, spec, ks)
	}
	if ks.ExpiresAt != nil {
		p.wakeAt(ks.ExpiresAt.Add(-renewBefore(spec)))
	}

	// D. Прежний ключ после окна перекрытия.
	if ks.Previous != nil {
		if now.Before(ks.Previous.RevokeAt.Time) {
			p.wakeAt(ks.Previous.RevokeAt.Time)
			return ctrl.Result{}, nil, true
		}
		op, err := p.r.Kaname.RevokeKey(ctx, p.sa.Status.ID, ks.Previous.KeyID)
		if kaname.Classify(err) == kaname.ClassNotFound {
			ks.Previous = nil
			return p.saved3(ctx)
		}
		if err != nil {
			res, ferr := p.fail(err)
			return res, ferr, false
		}
		metrics.KeysRevoked.WithLabelValues("rotation").Inc()
		res, err := p.track(ctx, op, iamv1alpha1.VerbRevokeKey, spec.Name+"/"+ks.Previous.KeyID)
		return res, err, false
	}
	return ctrl.Result{}, nil, true
}

// saved3 — записать status и разбудить следующий проход.
func (p *saPass) saved3(ctx context.Context) (ctrl.Result, error, bool) {
	if err := p.save(ctx); err != nil {
		return ctrl.Result{}, err, false
	}
	return ctrl.Result{RequeueAfter: requeueNow}, nil, false
}

func liveWithNonce(live map[string]*iamv1.ServiceAccountOAuthClient, nonce string, owned func(map[string]string) bool) *iamv1.ServiceAccountOAuthClient {
	for _, k := range live {
		if k.GetLabels()[iamv1alpha1.LabelKeyNonce] == nonce && owned(k.GetLabels()) {
			return k
		}
	}
	return nil
}

// keyName — имя ключа в kaname (DNS-метка): имя из spec и начало nonce.
func keyName(spec iamv1alpha1.KeySpec, nonce string) string {
	return spec.Name + "-" + nonce[:10]
}

func (p *saPass) issue(ctx context.Context, spec iamv1alpha1.KeySpec, ks *iamv1alpha1.KeyStatus) (ctrl.Result, error, bool) {
	nonce := ks.Issuing.Nonce
	labels := ownershipLabels(p.sa, p.r.Config.ClusterName)
	delete(labels, iamv1alpha1.LabelRef)
	labels[iamv1alpha1.LabelKeyName] = spec.Name
	labels[iamv1alpha1.LabelKeyNonce] = nonce
	req := &iamv1.IssueSAKeyRequest{
		ServiceAccountId: p.sa.Status.ID,
		Description:      truncate(fmt.Sprintf("k8s %s/%s key %s", p.sa.Namespace, p.sa.Name, spec.Name), 256),
		TtlSeconds:       keyTTL(spec),
		Name:             keyName(spec, nonce),
		Labels:           labels,
		CredentialKind:   iamv1.CredentialKind_CREDENTIAL_KIND_SECRET,
	}
	if keyKind(spec) == iamv1alpha1.KeyKindKeypair {
		req.CredentialKind = iamv1.CredentialKind_CREDENTIAL_KIND_KEYPAIR
		req.Audience = spec.Audience
	}
	op, err := p.r.Kaname.IssueKey(ctx, req)
	if err != nil {
		o := classify(kindSA, err)
		p.cond(iamv1alpha1.ConditionSynced, metav1.ConditionFalse, o.reason, o.message)
		p.issuing(o.reason, fmt.Sprintf("key %s: %s", spec.Name, o.message))
		res, rerr := o.result()
		return res, rerr, false
	}
	res, err := p.track(ctx, op, iamv1alpha1.VerbIssueKey, spec.Name)
	return res, err, false
}

// applyIssue кладёт выпущенный ключ в Vault и дочитывает status.
func (p *saPass) applyIssue(ctx context.Context, name string, op *operationpb.Operation) (ctrl.Result, error) {
	spec, ks := p.specKey(name), p.keyStatus(name)
	if spec == nil || ks == nil || ks.Issuing == nil {
		// Ключ снят из spec или выпуск уже дочитан: потерянный ключ уберёт уборка.
		return ctrl.Result{RequeueAfter: requeueNow}, nil
	}
	var resp iamv1.IssueSAKeyResponse
	if err := kaname.OperationResult(op, &resp); err != nil {
		o := classify(kindSA, err)
		p.cond(iamv1alpha1.ConditionSynced, metav1.ConditionFalse, o.reason, o.message)
		p.issuing(o.reason, fmt.Sprintf("key %s: %s", name, o.message))
		return o.result()
	}
	kind := keyKind(*spec)
	secret := resp.GetSecret()
	if kind == iamv1alpha1.KeyKindKeypair {
		secret = resp.GetPrivateKeyPem()
	}
	if secret == "" || resp.GetKeyId() == "" {
		// Ответ без удостоверения (окно показа истекло): ключ kaname с нашим
		// nonce дождётся окна уборки и будет заменён.
		p.issuing(iamv1alpha1.ReasonKeysIssuing, fmt.Sprintf("key %s: the issued credential was not delivered by kaname", name))
		return ctrl.Result{RequeueAfter: p.r.Config.Keys.OrphanGrace.Duration}, nil
	}
	mount, path, err := p.vaultPath(*spec)
	if err != nil {
		return ctrl.Result{RequeueAfter: invalidRecheck}, nil
	}
	expires := resp.GetKey().GetExpiresAt().AsTime()
	data := map[string]string{
		vaultUsername:  resp.GetKeyId(),
		vaultKeyID:     resp.GetKeyId(),
		vaultKind:      string(kind),
		vaultSAID:      p.sa.Status.ID,
		vaultAccountID: p.sa.Status.AccountID,
		vaultExpiresAt: expires.UTC().Format(time.RFC3339),
		vaultNonce:     ks.Issuing.Nonce,
		vaultIssuedAt:  p.now().UTC().Format(time.RFC3339),
	}
	if kind == iamv1alpha1.KeyKindKeypair {
		data[vaultPrivKey] = secret
		data[vaultAlgorithm] = resp.GetAlgorithm()
	} else {
		data[vaultPassword] = secret
	}
	version, err := p.writeVault(ctx, mount, path, data)
	if err != nil {
		// Секрет не записан и больше не будет доступен: ключ kaname с этим
		// nonce уйдёт уборкой, выпуск повторится.
		return p.failVault(err)
	}
	metrics.KeysIssued.WithLabelValues(string(kind)).Inc()
	p.finalizeKey(*spec, ks, resp.GetKeyId(), expires, version)
	p.r.Recorder.Eventf(p.sa, nil, corev1.EventTypeNormal, "KeyIssued", "Reconcile", "key %s: issued %s, delivered to Vault version %d", name, resp.GetKeyId(), version)
	if err := p.save(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeueNow}, nil
}

// writeVault пишет запись с CAS по последней прочитанной версии; запись уже
// несёт наш nonce — выпуск записан раньше.
func (p *saPass) writeVault(ctx context.Context, mount, path string, data map[string]string) (int64, error) {
	var lastErr error
	for range vaultCASAttempts {
		cur, err := p.r.Vault.Read(ctx, mount, path)
		if err != nil {
			return 0, err
		}
		cas := int64(0)
		if cur != nil {
			if cur.Data[vaultNonce] == data[vaultNonce] {
				return cur.Version, nil
			}
			cas = cur.Version
		}
		v, err := p.r.Vault.WriteCAS(ctx, mount, path, data, cas)
		if err == nil {
			return v, nil
		}
		if !errors.Is(err, vault.ErrCASMismatch) {
			return 0, err
		}
		lastErr = err
	}
	return 0, lastErr
}

// finalizeKey делает ключ keyID действующим; прежний уходит в перекрытие.
func (p *saPass) finalizeKey(spec iamv1alpha1.KeySpec, ks *iamv1alpha1.KeyStatus, keyID string, expires time.Time, version int64) {
	now := p.now()
	if ks.KeyID != "" && ks.KeyID != keyID {
		revokeAt := now.Add(overlap(spec))
		if ks.ExpiresAt != nil && ks.ExpiresAt.Before(&metav1.Time{Time: revokeAt}) {
			revokeAt = ks.ExpiresAt.Time
		}
		ks.Previous = &iamv1alpha1.PreviousKey{KeyID: ks.KeyID, RevokeAt: metav1.NewTime(revokeAt)}
	}
	exp := metav1.NewTime(expires)
	ks.KeyID, ks.ExpiresAt, ks.VaultVersion, ks.Issuing = keyID, &exp, version, nil
}

// keyRevoked снимает отозванный ключ из status (subject — "имя/id").
func (p *saPass) keyRevoked(subject string) {
	name, id, ok := strings.Cut(subject, "/")
	if !ok {
		return
	}
	if ks := p.keyStatus(name); ks != nil && ks.Previous != nil && ks.Previous.KeyID == id {
		ks.Previous = nil
	}
}

// dropRemovedKeys снимает ключи, убранные из spec: отзыв в kaname, удаление
// записи Vault, снятие из status.
func (p *saPass) dropRemovedKeys(ctx context.Context, live []*iamv1.ServiceAccountOAuthClient) (ctrl.Result, error, bool) {
	st := &p.sa.Status
	kept := st.Keys[:0:0]
	changed := false
	for _, ks := range st.Keys {
		if p.specKey(ks.Name) != nil {
			kept = append(kept, ks)
			continue
		}
		for _, k := range live {
			if p.owned(k.GetLabels()) && k.GetLabels()[iamv1alpha1.LabelKeyName] == ks.Name {
				op, err := p.r.Kaname.RevokeKey(ctx, st.ID, k.GetId())
				if kaname.Classify(err) == kaname.ClassNotFound {
					continue
				}
				if err != nil {
					res, ferr := p.fail(err)
					return res, ferr, false
				}
				metrics.KeysRevoked.WithLabelValues("removed").Inc()
				res, err := p.track(ctx, op, iamv1alpha1.VerbRevokeKey, ks.Name+"/"+k.GetId())
				return res, err, false
			}
		}
		if ks.VaultPath != "" {
			mount, path, _ := strings.Cut(ks.VaultPath, "/")
			if err := p.r.Vault.DeleteAll(ctx, mount, path); err != nil {
				res, ferr := p.failVault(err)
				return res, ferr, false
			}
		}
		changed = true
	}
	if changed {
		st.Keys = kept
		return p.saved3(ctx)
	}
	return ctrl.Result{}, nil, true
}

// sweep отзывает свои ключи kaname, которых нет ни в status (действующий,
// прежний), ни в незавершённом выпуске, и которые старше окна уборки.
// Чужие ключи (без меток владения) не трогаются.
func (p *saPass) sweep(ctx context.Context, live []*iamv1.ServiceAccountOAuthClient) (ctrl.Result, error, bool) {
	now := p.now()
	grace := p.r.Config.Keys.OrphanGrace.Duration
	sorted := append([]*iamv1.ServiceAccountOAuthClient(nil), live...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].GetCreatedAt().AsTime().Before(sorted[j].GetCreatedAt().AsTime())
	})
	for _, k := range sorted {
		if !p.owned(k.GetLabels()) {
			continue
		}
		name := k.GetLabels()[iamv1alpha1.LabelKeyName]
		if ks := p.keyStatus(name); ks != nil {
			if k.GetId() == ks.KeyID || (ks.Previous != nil && k.GetId() == ks.Previous.KeyID) {
				continue
			}
			if ks.Issuing != nil && k.GetLabels()[iamv1alpha1.LabelKeyNonce] == ks.Issuing.Nonce {
				continue
			}
		}
		if p.specKey(name) != nil {
			if until := k.GetCreatedAt().AsTime().Add(grace); now.Before(until) {
				p.wakeAt(until)
				continue
			}
		}
		op, err := p.r.Kaname.RevokeKey(ctx, p.sa.Status.ID, k.GetId())
		if kaname.Classify(err) == kaname.ClassNotFound {
			continue
		}
		if err != nil {
			res, ferr := p.fail(err)
			return res, ferr, false
		}
		metrics.KeysRevoked.WithLabelValues("orphan").Inc()
		p.r.Recorder.Eventf(p.sa, nil, corev1.EventTypeNormal, "KeyRevoked", "Reconcile", "revoking orphaned key %s (%s)", k.GetId(), name)
		res, err := p.track(ctx, op, iamv1alpha1.VerbRevokeKey, name+"/"+k.GetId())
		return res, err, false
	}
	return ctrl.Result{}, nil, true
}

// deleteVaultRecords удаляет записи Vault ключей учётки (при удалении CR).
func (p *saPass) deleteVaultRecords(ctx context.Context) error {
	paths := map[string]bool{}
	for _, ks := range p.sa.Status.Keys {
		if ks.VaultPath != "" {
			paths[ks.VaultPath] = true
		}
	}
	for _, s := range p.sa.Spec.Keys {
		if mount, path, err := p.vaultPath(s); err == nil {
			paths[mount+"/"+path] = true
		}
	}
	for full := range paths {
		mount, path, _ := strings.Cut(full, "/")
		if err := p.r.Vault.DeleteAll(ctx, mount, path); err != nil {
			return err
		}
	}
	return nil
}
