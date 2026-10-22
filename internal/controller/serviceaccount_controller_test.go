// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

const waitReady = 20 * time.Second

func newSA(tn tenant, name string, keys ...iamv1alpha1.KeySpec) *iamv1alpha1.ServiceAccount {
	return &iamv1alpha1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tn.ns},
		Spec: iamv1alpha1.ServiceAccountSpec{
			Name:        name,
			Description: "CI robot",
			Labels:      map[string]string{"registry": "abc123"},
			Keys:        keys,
		},
	}
}

func pushKey() iamv1alpha1.KeySpec {
	return iamv1alpha1.KeySpec{
		Name: "push",
		Delivery: iamv1alpha1.KeyDelivery{Vault: iamv1alpha1.VaultDelivery{
			App: "docker-registry", Instance: "abc123",
		}},
	}
}

func createSA(t *testing.T, sa *iamv1alpha1.ServiceAccount) {
	t.Helper()
	if err := k8s.Create(context.Background(), sa); err != nil {
		t.Fatalf("create SA: %v", err)
	}
	t.Cleanup(func() { forceDelete(t, sa) })
}

// forceDelete снимает CR в конце пробы; финализатор снимает сам оператор.
func forceDelete(t *testing.T, obj client.Object) {
	t.Helper()
	_ = k8s.Delete(context.Background(), obj)
}

func getSA(t *testing.T, sa *iamv1alpha1.ServiceAccount) *iamv1alpha1.ServiceAccount {
	t.Helper()
	out := &iamv1alpha1.ServiceAccount{}
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(sa), out); err != nil {
		t.Fatalf("get SA: %v", err)
	}
	return out
}

func waitSAReady(t *testing.T, sa *iamv1alpha1.ServiceAccount) *iamv1alpha1.ServiceAccount {
	t.Helper()
	var cur *iamv1alpha1.ServiceAccount
	eventually(t, waitReady, func() error {
		cur = getSA(t, sa)
		if cur.Status.ObservedGeneration != cur.Generation {
			return fmt.Errorf("observedGeneration %d of %d", cur.Status.ObservedGeneration, cur.Generation)
		}
		return wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	return cur
}

func vaultPath(tn tenant, name, key string) string {
	return fmt.Sprintf("clusters/%s/namespaces/%s/apps/docker-registry/abc123/robots/%s/%s", clusterName, tn.ns, name, key)
}

func remoteSA(t *testing.T, id string) *iamv1.ServiceAccount {
	t.Helper()
	for _, sa := range fakeK.ServiceAccounts() {
		if sa.GetId() == id {
			return sa
		}
	}
	return nil
}

func TestSAReachesReadyWithOwnershipLabelsAndKeyInVault(t *testing.T) {
	tn := newTenant(t, true)
	sa := newSA(tn, "zot-ci", pushKey())
	createSA(t, sa)
	cur := waitSAReady(t, sa)

	if cur.Status.ID == "" || cur.Status.AccountID != tn.account {
		t.Fatalf("status id %q account %q", cur.Status.ID, cur.Status.AccountID)
	}
	remote := remoteSA(t, cur.Status.ID)
	if remote == nil {
		t.Fatal("no kaname account")
	}
	l := remote.GetLabels()
	if remote.GetName() != "zot-ci" || remote.GetAccountId() != tn.account || remote.GetDescription() != "CI robot" ||
		l[iamv1alpha1.LabelOwnerUID] != string(cur.UID) || l[iamv1alpha1.LabelCluster] != clusterName ||
		l[iamv1alpha1.LabelRef] != tn.ns+".zot-ci" || l["registry"] != "abc123" {
		t.Fatalf("kaname account = %v", remote)
	}
	if err := wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionKeysReady, metav1.ConditionTrue, ""); err != nil {
		t.Fatal(err)
	}
	ks := cur.Status.KeyStatusByName("push")
	if ks == nil || ks.KeyID == "" || ks.Issuing != nil || ks.ExpiresAt == nil || ks.VaultVersion < 1 {
		t.Fatalf("key status = %+v", ks)
	}
	data, _ := fakeV.Get(vaultMount, vaultPath(tn, "zot-ci", "push"))
	if data == nil {
		t.Fatalf("no vault record at %s (have %v)", vaultPath(tn, "zot-ci", "push"), fakeV.Paths())
	}
	if data["username"] != ks.KeyID || data["password"] != fakeK.SecretOf(ks.KeyID) || data["serviceAccountId"] != cur.Status.ID {
		t.Fatalf("vault record does not carry the issued key (username %q)", data["username"])
	}
	keys := fakeK.Keys(cur.Status.ID)
	if len(keys) != 1 || keys[0].GetId() != ks.KeyID {
		t.Fatalf("kaname keys = %v", keys)
	}
	kl := keys[0].GetLabels()
	if kl[iamv1alpha1.LabelOwnerUID] != string(cur.UID) || kl[iamv1alpha1.LabelKeyName] != "push" || kl[iamv1alpha1.LabelKeyNonce] == "" ||
		kl[iamv1alpha1.LabelKeyNonce] != data["nonce"] {
		t.Fatalf("key labels = %v (vault nonce %q)", kl, data["nonce"])
	}
	if keys[0].GetCredentialKind() != iamv1.CredentialKind_CREDENTIAL_KIND_SECRET {
		t.Fatalf("key kind = %s", keys[0].GetCredentialKind())
	}
	// Секрет не попадает в status.
	if strings.Contains(fmt.Sprintf("%+v", cur.Status), fakeK.SecretOf(ks.KeyID)) {
		t.Fatal("secret leaked into status")
	}
}

func TestSAWaitsForTheAccountAnnotation(t *testing.T) {
	tn := newTenant(t, false)
	sa := newSA(tn, "zot-wait")
	createSA(t, sa)
	eventually(t, waitReady, func() error {
		return wantCondition(getSA(t, sa).Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonAccountUnresolved)
	})
	if n := countCalls("POST /iam/v1/serviceAccounts"); n > 0 {
		before := n
		consistently(t, time.Second, func() error {
			if countCalls("POST /iam/v1/serviceAccounts") != before {
				return fmt.Errorf("create called without an account")
			}
			return nil
		})
	}
	// Законный близнец: та же учётка с аннотацией доходит до Ready.
	annotateTenant(t, tn)
	waitSAReady(t, sa)
}

func TestSAAdoptsOwnAccountWithoutCreating(t *testing.T) {
	tn := newTenant(t, false)
	sa := newSA(tn, "zot-adopt")
	createSA(t, sa)
	uid := string(getSA(t, sa).UID)
	id := fakeK.PutServiceAccount(&iamv1.ServiceAccount{
		AccountId: tn.account, Name: "zot-adopt", Enabled: true,
		Labels: map[string]string{iamv1alpha1.LabelOwnerUID: uid, iamv1alpha1.LabelCluster: clusterName},
	})
	creates := countCalls("POST /iam/v1/serviceAccounts")
	annotateTenant(t, tn)
	cur := waitSAReady(t, sa)
	if cur.Status.ID != id {
		t.Fatalf("adopted id %q, want %q", cur.Status.ID, id)
	}
	if countCalls("POST /iam/v1/serviceAccounts") != creates {
		t.Fatal("create called although the own account exists")
	}
}

func TestSARefusesForeignAccountWithTheSameName(t *testing.T) {
	tn := newTenant(t, true)
	foreign := fakeK.PutServiceAccount(&iamv1.ServiceAccount{
		AccountId: tn.account, Name: "zot-taken", Enabled: true,
		Labels: map[string]string{iamv1alpha1.LabelOwnerUID: "someone-else", iamv1alpha1.LabelCluster: clusterName},
	})
	sa := newSA(tn, "zot-taken")
	createSA(t, sa)
	eventually(t, waitReady, func() error {
		cur := getSA(t, sa)
		if err := wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionConflict, metav1.ConditionTrue, iamv1alpha1.ReasonNotOwned); err != nil {
			return err
		}
		return wantCondition(cur.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonNotOwned)
	})
	if got := getSA(t, sa).Status.ID; got != "" {
		t.Fatalf("foreign account adopted: %s", got)
	}
	if r := remoteSA(t, foreign); r.GetLabels()[iamv1alpha1.LabelOwnerUID] != "someone-else" || r.GetDescription() != "" {
		t.Fatalf("foreign account modified: %v", r)
	}
}

func TestSADisabledInKanameStaysDriftedUntilResync(t *testing.T) {
	tn := newTenant(t, true)
	sa := newSA(tn, "zot-drift")
	createSA(t, sa)
	cur := waitSAReady(t, sa)
	enables := countCalls("POST /iam/v1/serviceAccounts/" + cur.Status.ID + ":enable")

	fakeK.SetEnabled(cur.Status.ID, false)
	eventually(t, waitReady, func() error {
		c := getSA(t, sa)
		if err := wantCondition(c.Status.Conditions, iamv1alpha1.ConditionDrifted, metav1.ConditionTrue, iamv1alpha1.ReasonDisabledExternally); err != nil {
			return err
		}
		return wantCondition(c.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonDisabledExternally)
	})
	consistently(t, 2*time.Second, func() error {
		if countCalls("POST /iam/v1/serviceAccounts/"+cur.Status.ID+":enable") != enables {
			return fmt.Errorf("operator re-enabled an account disabled in kaname")
		}
		if remoteSA(t, cur.Status.ID).GetEnabled() {
			return fmt.Errorf("account enabled again")
		}
		return nil
	})

	// Законный близнец: аннотация платформы разрешает восстановление один раз.
	patchObj(t, sa, func(o client.Object) {
		o.SetAnnotations(map[string]string{iamv1alpha1.AnnotationResyncDrift: "incident-42-closed"})
	})
	eventually(t, waitReady, func() error {
		c := getSA(t, sa)
		if !remoteSA(t, cur.Status.ID).GetEnabled() {
			return fmt.Errorf("not re-enabled")
		}
		if err := wantCondition(c.Status.Conditions, iamv1alpha1.ConditionDrifted, metav1.ConditionFalse, ""); err != nil {
			return err
		}
		if c.Status.ResyncNonce != "incident-42-closed" {
			return fmt.Errorf("resync nonce %q", c.Status.ResyncNonce)
		}
		return wantCondition(c.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
}

func TestSADeletedInKanameStaysDriftedUntilResync(t *testing.T) {
	tn := newTenant(t, true)
	sa := newSA(tn, "zot-gone")
	createSA(t, sa)
	cur := waitSAReady(t, sa)
	creates := countCalls("POST /iam/v1/serviceAccounts")
	fakeK.RemoveServiceAccount(cur.Status.ID)
	eventually(t, waitReady, func() error {
		return wantCondition(getSA(t, sa).Status.Conditions, iamv1alpha1.ConditionDrifted, metav1.ConditionTrue, iamv1alpha1.ReasonDeletedExternally)
	})
	consistently(t, 2*time.Second, func() error {
		if countCalls("POST /iam/v1/serviceAccounts") != creates {
			return fmt.Errorf("operator recreated an account deleted in kaname")
		}
		return nil
	})
	patchObj(t, sa, func(o client.Object) {
		o.SetAnnotations(map[string]string{iamv1alpha1.AnnotationResyncDrift: "restore-1"})
	})
	again := waitSAReady(t, sa)
	if again.Status.ID == "" || again.Status.ID == cur.Status.ID {
		t.Fatalf("not recreated: id %q (was %q)", again.Status.ID, cur.Status.ID)
	}
}

func TestSASpecDisableAndUpdateReachKaname(t *testing.T) {
	tn := newTenant(t, true)
	sa := newSA(tn, "zot-upd")
	createSA(t, sa)
	cur := waitSAReady(t, sa)
	patchObj(t, sa, func(o client.Object) {
		s := o.(*iamv1alpha1.ServiceAccount)
		s.Spec.Description = "CI robot v2"
		s.Spec.Labels = map[string]string{"registry": "abc123", "team": "a"}
		s.Spec.Enabled = ptr.To(false)
	})
	eventually(t, waitReady, func() error {
		r := remoteSA(t, cur.Status.ID)
		if r.GetEnabled() || r.GetDescription() != "CI robot v2" || r.GetLabels()["team"] != "a" ||
			r.GetLabels()[iamv1alpha1.LabelOwnerUID] != string(cur.UID) {
			return fmt.Errorf("kaname account = %v", r)
		}
		c := getSA(t, sa)
		if c.Status.ObservedGeneration != c.Generation {
			return fmt.Errorf("generation not observed")
		}
		return wantCondition(c.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, "")
	})
	// Отключение по spec — не дрейф.
	if err := wantCondition(getSA(t, sa).Status.Conditions, iamv1alpha1.ConditionDrifted, metav1.ConditionFalse, ""); err != nil {
		t.Fatal(err)
	}
}

// Учётка, отключённая ПО SPEC, включается снова по spec, без resync и без
// дрейфа. Близнец — TestSADisabledInKanameStaysDriftedUntilResync: отключение
// мимо оператора остаётся дрейфом.
func TestSADisabledBySpecIsEnabledAgainBySpec(t *testing.T) {
	tn := newTenant(t, true)
	sa := newSA(tn, "zot-toggle")
	createSA(t, sa)
	cur := waitSAReady(t, sa)
	patchObj(t, sa, func(o client.Object) { o.(*iamv1alpha1.ServiceAccount).Spec.Enabled = ptr.To(false) })
	eventually(t, waitReady, func() error {
		if remoteSA(t, cur.Status.ID).GetEnabled() {
			return fmt.Errorf("not disabled in kaname")
		}
		c := getSA(t, sa)
		if c.Status.ObservedGeneration != c.Generation {
			return fmt.Errorf("generation not observed")
		}
		return wantCondition(c.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, iamv1alpha1.ReasonDisabled)
	})
	patchObj(t, sa, func(o client.Object) { o.(*iamv1alpha1.ServiceAccount).Spec.Enabled = ptr.To(true) })
	eventually(t, waitReady, func() error {
		if !remoteSA(t, cur.Status.ID).GetEnabled() {
			return fmt.Errorf("not enabled again in kaname")
		}
		c := getSA(t, sa)
		if c.Status.ObservedGeneration != c.Generation {
			return fmt.Errorf("generation not observed")
		}
		if err := wantCondition(c.Status.Conditions, iamv1alpha1.ConditionDrifted, metav1.ConditionFalse, ""); err != nil {
			return err
		}
		return wantCondition(c.Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionTrue, iamv1alpha1.ReasonReconciled)
	})
	if c := getSA(t, sa); c.Status.ResyncNonce != "" {
		t.Fatalf("enabling by spec consumed a resync nonce %q", c.Status.ResyncNonce)
	}
}

func TestSAKeyRotatesWithOverlapAndRevokesThePrevious(t *testing.T) {
	tn := newTenant(t, true)
	k := pushKey()
	k.TTLSeconds = 7200
	k.Rotation = iamv1alpha1.KeyRotation{RenewBeforeSeconds: ptr.To[int64](1800), OverlapSeconds: ptr.To[int64](600)}
	sa := newSA(tn, "zot-rot", k)
	createSA(t, sa)
	cur := waitSAReady(t, sa)
	first := cur.Status.KeyStatusByName("push").KeyID

	// До окна замены — ключ прежний.
	clk.SetTime(clk.Now().Add(time.Hour))
	touch(t, sa)
	consistently(t, time.Second, func() error {
		if got := getSA(t, sa).Status.KeyStatusByName("push").KeyID; got != first {
			return fmt.Errorf("rotated before renewBefore: %s", got)
		}
		return nil
	})

	// В окне замены — новый ключ, прежний в перекрытии.
	clk.SetTime(clk.Now().Add(31 * time.Minute))
	touch(t, sa)
	var second string
	eventually(t, waitReady, func() error {
		ks := getSA(t, sa).Status.KeyStatusByName("push")
		if ks.KeyID == first || ks.KeyID == "" || ks.Previous == nil || ks.Previous.KeyID != first {
			return fmt.Errorf("key status %+v", ks)
		}
		second = ks.KeyID
		data, _ := fakeV.Get(vaultMount, vaultPath(tn, "zot-rot", "push"))
		if data["username"] != second {
			return fmt.Errorf("vault still holds %q", data["username"])
		}
		return nil
	})
	if len(fakeK.Keys(cur.Status.ID)) != 2 {
		t.Fatalf("overlap: kaname keys = %v", fakeK.Keys(cur.Status.ID))
	}

	// После перекрытия прежний ключ отозван.
	clk.SetTime(clk.Now().Add(11 * time.Minute))
	touch(t, sa)
	eventually(t, waitReady, func() error {
		keys := fakeK.Keys(cur.Status.ID)
		if len(keys) != 1 || keys[0].GetId() != second {
			return fmt.Errorf("kaname keys = %v", keys)
		}
		if ks := getSA(t, sa).Status.KeyStatusByName("push"); ks.Previous != nil {
			return fmt.Errorf("previous not cleared: %+v", ks.Previous)
		}
		return nil
	})
}

func TestSAKeyRevokedInKanameIsNotReissuedUntilResync(t *testing.T) {
	tn := newTenant(t, true)
	sa := newSA(tn, "zot-krev", pushKey())
	createSA(t, sa)
	cur := waitSAReady(t, sa)
	keyID := cur.Status.KeyStatusByName("push").KeyID
	issues := countCalls("POST /iam/v1/serviceAccounts/" + cur.Status.ID + "/keys")
	fakeK.RemoveKey(keyID)
	eventually(t, waitReady, func() error {
		c := getSA(t, sa)
		if err := wantCondition(c.Status.Conditions, iamv1alpha1.ConditionDrifted, metav1.ConditionTrue, iamv1alpha1.ReasonKeyRevoked); err != nil {
			return err
		}
		return wantCondition(c.Status.Conditions, iamv1alpha1.ConditionKeysReady, metav1.ConditionFalse, iamv1alpha1.ReasonKeyRevoked)
	})
	consistently(t, 2*time.Second, func() error {
		if countCalls("POST /iam/v1/serviceAccounts/"+cur.Status.ID+"/keys") != issues {
			return fmt.Errorf("key re-issued after a revocation in kaname")
		}
		return nil
	})
	patchObj(t, sa, func(o client.Object) {
		o.SetAnnotations(map[string]string{iamv1alpha1.AnnotationResyncDrift: "rekey-1"})
	})
	eventually(t, waitReady, func() error {
		ks := getSA(t, sa).Status.KeyStatusByName("push")
		if ks.KeyID == "" || ks.KeyID == keyID {
			return fmt.Errorf("key status %+v", ks)
		}
		return wantCondition(getSA(t, sa).Status.Conditions, iamv1alpha1.ConditionKeysReady, metav1.ConditionTrue, "")
	})
}

func TestSAVaultRecordLostIsReissued(t *testing.T) {
	tn := newTenant(t, true)
	sa := newSA(tn, "zot-vlost", pushKey())
	createSA(t, sa)
	cur := waitSAReady(t, sa)
	first := cur.Status.KeyStatusByName("push").KeyID
	fakeV.Delete(vaultMount, vaultPath(tn, "zot-vlost", "push"))
	touch(t, sa)
	eventually(t, waitReady, func() error {
		ks := getSA(t, sa).Status.KeyStatusByName("push")
		data, _ := fakeV.Get(vaultMount, vaultPath(tn, "zot-vlost", "push"))
		if ks.KeyID == first || data == nil || data["username"] != ks.KeyID {
			return fmt.Errorf("key %q vault %v", ks.KeyID, data != nil)
		}
		return nil
	})
}

func TestSADeletionWaitsForBindingsThenCleansEverything(t *testing.T) {
	tn := newTenant(t, true)
	reserve(t, tn, "abc123")
	sa := newSA(tn, "zot-del", pushKey())
	createSA(t, sa)
	cur := waitSAReady(t, sa)
	ab := newAB(tn, "zot-del-pusher", "zot-del", "registry.pusher", "abc123")
	createAB(t, ab)
	waitABReady(t, ab)

	if err := k8s.Delete(context.Background(), sa); err != nil {
		t.Fatal(err)
	}
	eventually(t, waitReady, func() error {
		return wantCondition(getSA(t, sa).Status.Conditions, iamv1alpha1.ConditionReady, metav1.ConditionFalse, iamv1alpha1.ReasonDeletionBlocked)
	})
	if remoteSA(t, cur.Status.ID) == nil || !remoteSA(t, cur.Status.ID).GetEnabled() {
		t.Fatal("account touched while a binding still refers to it")
	}
	if err := k8s.Delete(context.Background(), ab); err != nil {
		t.Fatal(err)
	}
	eventually(t, waitReady, func() error {
		err := k8s.Get(context.Background(), client.ObjectKeyFromObject(sa), &iamv1alpha1.ServiceAccount{})
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("SA CR still present: %w", err)
		}
		return nil
	})
	// Перепись остатков: учётки, ключей, выдач и записей Vault этого CR нет.
	if remoteSA(t, cur.Status.ID) != nil || len(fakeK.Keys(cur.Status.ID)) != 0 {
		t.Fatal("kaname account or keys survived the deletion")
	}
	for _, b := range fakeK.Bindings() {
		if b.GetLabels()[iamv1alpha1.LabelOwnerUID] == getUID(t, ab) && b.GetStatus() != iamv1.AccessBinding_REVOKED {
			t.Fatalf("binding %s survived", b.GetId())
		}
	}
	for _, p := range fakeV.Paths() {
		if strings.Contains(p, "/namespaces/"+tn.ns+"/") {
			t.Fatalf("vault record survived: %s", p)
		}
	}
	// Порядок: отключение раньше удаления.
	calls := strings.Join(fakeK.Calls(), "\n")
	if strings.Index(calls, cur.Status.ID+":disable") > strings.Index(calls, "DELETE /iam/v1/serviceAccounts/"+cur.Status.ID+"\n") &&
		strings.Contains(calls, "DELETE /iam/v1/serviceAccounts/"+cur.Status.ID+"\n") {
		t.Fatal("account deleted before it was disabled")
	}
	if !strings.Contains(calls, "POST /iam/v1/serviceAccounts/"+cur.Status.ID+":disable") {
		t.Fatal("account was not disabled before deletion")
	}
}

func TestSAOrphanDeletionLeavesKanameUntouched(t *testing.T) {
	tn := newTenant(t, true)
	sa := newSA(tn, "zot-orphan")
	sa.Spec.DeletionPolicy = iamv1alpha1.DeletionPolicyOrphan
	createSA(t, sa)
	cur := waitSAReady(t, sa)
	before := len(fakeK.Calls())
	if err := k8s.Delete(context.Background(), sa); err != nil {
		t.Fatal(err)
	}
	eventually(t, waitReady, func() error {
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(sa), &iamv1alpha1.ServiceAccount{}); !apierrors.IsNotFound(err) {
			return fmt.Errorf("still present: %w", err)
		}
		return nil
	})
	for _, c := range fakeK.Calls()[before:] {
		if strings.Contains(c, cur.Status.ID) && !strings.HasPrefix(c, "GET ") {
			t.Fatalf("orphan deletion called kaname: %s", c)
		}
	}
	if remoteSA(t, cur.Status.ID) == nil {
		t.Fatal("orphaned account removed")
	}
}

func getUID(t *testing.T, obj client.Object) string {
	t.Helper()
	return string(obj.GetUID())
}
