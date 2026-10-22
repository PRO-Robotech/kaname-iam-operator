#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: Apache-2.0
"""Инъекции: каждая роняет ОДИН факт продукта, и проба, его держащая, обязана
покраснеть. Сначала — контроль: те же пробы на неправленом дереве зелёные
(законный близнец). Инъекция, после которой проба осталась зелёной, — находка:
проба не способна упасть на своём предмете.

Исходы: 0 — контроль зелёный, все инъекции покраснели; 1 — находка (проба
промолчала, якорь инъекции не найден, контроль красный). Правка дерева
откатывается после каждой инъекции, в том числе на падении.
"""
import os
import subprocess
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
INJ = [
 ("I1 drift guard (disabled) removed", "internal/controller/serviceaccount_controller.go",
  "\t\tdefault:\n\t\t\tres, err := p.drift(iamv1alpha1.ReasonDisabledExternally,",
  "\t\tdefault:\n\t\t}\n\t\tif false {\n\t\t\tres, err := p.drift(iamv1alpha1.ReasonDisabledExternally,",
  "./internal/controller/", "TestSADisabledInKanameStaysDriftedUntilResync"),
 ("I2 ownership always true", "internal/controller/common.go",
  "\treturn labels[iamv1alpha1.LabelOwnerUID] == uid && labels[iamv1alpha1.LabelCluster] == cluster",
  "\treturn true",
  "./internal/controller/", "TestSARefusesForeignAccountWithTheSameName|TestABAdoptsOwnBindingAndRefusesForeignIdentical"),
 ("I3 intent not saved before issue", "internal/controller/serviceaccount_keys.go",
  "\t\t// Намерение — до вызова kaname: конфликт версии — выпуска нет.\n\t\tif err := p.save(ctx); err != nil {\n\t\t\treturn ctrl.Result{}, err, false\n\t\t}\n",
  "",
  "./internal/controller/", "TestKeyProtocolIntentPrecedesTheIssue"),
 ("I4 old binding revoked before the new one", "internal/controller/accessbinding_controller.go",
  "\t\tst.Replaced = &iamv1alpha1.ReplacedBinding{ID: st.ID}\n\t\tst.ID, st.BindingHash = \"\", \"\"\n",
  "\t\treturn p.revoke(ctx, st.ID)\n",
  "./internal/controller/", "TestABTargetChangeCreatesNewBindingBeforeRevokingTheOld"),
 ("I5 policy evaluation disabled", "internal/policy/policy.go",
  "\trole := ab.Spec.RoleRef.Name\n\tif !slices.Contains(p.AllowedRoles, role) {",
  "\trole := ab.Spec.RoleRef.Name\n\tif role == \"\" {\n\t\treturn nil\n\t}\n\treturn nil\n\tif !slices.Contains(p.AllowedRoles, role) {",
  "./internal/policy/ ./internal/controller/", "TestEvaluateRefusesEachBrokenFact|TestABPolicyRefusalsHaveLawfulTwins"),
 ("I6 sweep ignores ownership", "internal/controller/serviceaccount_keys.go",
  "\tfor _, k := range sorted {\n\t\tif !p.owned(k.GetLabels()) {\n\t\t\tcontinue\n\t\t}\n",
  "\tfor _, k := range sorted {\n",
  "./internal/controller/", "TestKeyProtocolSweepTouchesOnlyOwnStrays"),
 ("I7 FAILED_PRECONDITION classified Invalid", "internal/kaname/errors.go",
  "\t\tcodes.FailedPrecondition, codes.Aborted:\n\t\treturn ClassRetryable\n\tcase codes.InvalidArgument, codes.OutOfRange:",
  "\t\tcodes.Aborted:\n\t\treturn ClassRetryable\n\tcase codes.InvalidArgument, codes.OutOfRange, codes.FailedPrecondition:",
  "./internal/kaname/", "TestClassifyCoversEveryCode"),
 ("I8 emptypb not linked by the client", "internal/kaname/client.go",
  "\t_ \"google.golang.org/protobuf/types/known/emptypb\"\n", "",
  "./internal/kaname/", "TestClientPackageLinksEveryOperationResponseType"),
 ("I16 unknown operation error details abort decoding", "internal/kaname/client.go",
  "\t\tif _, isOp := out.(*operationpb.Operation); isOp {", "\t\tif _, isOp := out.(*operationpb.Operation); isOp && false {",
  "./internal/kaname/", "TestOperationErrorWithUnknownDetailsDecodes"),
 # Прежнюю замену держат двое: отзыв до второй замены и уборка своих лишних
 # выдач перед созданием (I20). Снятая по одному, она держится другим — поэтому
 # инъекция роняет обоих.
 ("I18 second replacement overwrites the pending one (both holders)", "internal/controller/accessbinding_controller.go",
  ("\t\tif st.Replaced != nil {\n\t\t\treturn p.revoke(ctx, st.Replaced.ID)\n\t\t}\n\t\t// Цель",
   "\t\tcase owned && (st.Replaced == nil || b.GetId() != st.Replaced.ID):"),
  ("\t\t// Цель", "\t\tcase owned && false:"),
  "./internal/controller/", "TestABSecondTargetChangeDoesNotForgetTheReplacedBinding"),
 ("I17 chart grants less than the controller markers", "charts/kaname-iam-operator/templates/rbac.yaml",
  "    resources: [serviceaccounts/finalizers, accessbindings/finalizers]", "    resources: [serviceaccounts/finalizers]",
  "./test/admission/", "TestChartRBACCoversTheGeneratedRole"),
 ("I9 operator may change spec (admission)", "charts/kaname-iam-operator/templates/admission.yaml",
  "(variables.isOperator && request.operation == 'UPDATE' && object.spec == oldObject.spec &&",
  "(variables.isOperator && request.operation == 'UPDATE' &&",
  "./test/admission/", "TestOperatorChangesOnlyFinalizersAndWritesStatus"),
 ("I10 test summary always green", "hack/testsummary/main.go",
  "func (s Summary) Verdict() error {\n", "func (s Summary) Verdict() error {\n\treturn nil\n",
  "./hack/testsummary/", "TestVerdict"),
 ("I11 vault double ignores CAS", "internal/fakes/vaultfake/vaultfake.go",
  "\t\tif err != nil || int(want) != cur {", "\t\tif err != nil || (int(want) != cur && false) {",
  "./internal/vault/", "TestContractAgainstTheFake"),
 ("I12 token cached past exp-60s", "internal/kaname/token.go",
  "now.Before(s.expires.Add(-TokenRefreshMargin))", "now.Before(s.expires)",
  "./internal/kaname/", "TestFederatedExchangeFormAndCache"),
 ("I13 deletion does not wait for bindings", "internal/controller/serviceaccount_controller.go",
  "\tif len(refs.Items) > 0 {\n\t\tnames", "\tif false {\n\t\tnames",
  "./internal/controller/", "TestSADeletionWaitsForBindingsThenCleansEverything"),
 ("I14 revoked key reissued without resync", "internal/controller/serviceaccount_keys.go",
  "\t\tif !p.resyncNow {\n\t\t\tp.keyDrift = append(p.keyDrift, spec.Name)",
  "\t\tif false {\n\t\t\tp.keyDrift = append(p.keyDrift, spec.Name)",
  "./internal/controller/", "TestSAKeyRevokedInKanameIsNotReissuedUntilResync"),
 ("I15 vault path segment with a slash", "internal/config/config.go",
  "\t\tif !segmentValueRe.MatchString(val) || strings.Contains(val, \"..\") {",
  "\t\tif val == \"\" {",
  "./internal/config/", "TestVaultPathRendersAndRefusesForeignSegments"),
 ("I19 binding finalize does not look up its own by labels", "internal/controller/accessbinding_controller.go",
  "\tfor _, acc := range accounts {", "\tfor _, acc := range accounts[:0] {",
  "./internal/controller/", "TestABDeletedDuringCreateLeavesNoLiveBinding"),
 ("I20 own stray binding kept", "internal/controller/accessbinding_controller.go",
  "\t\tcase owned && (st.Replaced == nil || b.GetId() != st.Replaced.ID):", "\t\tcase owned && false:",
  "./internal/controller/", "TestABTargetChangedDuringReplacementLeavesOneLiveBinding"),
 # Окно неподтверждённого создания: kaname заводит объект фоном, пустой
 # поиск сразу после ответа Create — не доказательство отсутствия. Без окна
 # краснеют фоновые варианты проб гонки (inline держит поиск по меткам).
 ("I30 unconfirmed binding create not awaited", "internal/controller/accessbinding_controller.go",
  "\tif st.PendingHash == \"\" {\n\t\treturn ctrl.Result{}, false\n\t}",
  "\tif true {\n\t\treturn ctrl.Result{}, false\n\t}",
  "./internal/controller/", "TestABDeletedDuringCreateLeavesNoLiveBinding|TestABTargetChangedDuringReplacementLeavesOneLiveBinding"),
 ("I31 unconfirmed account create not awaited", "internal/controller/serviceaccount_controller.go",
  "\tif st.CreatingSince == nil {\n\t\treturn ctrl.Result{}, false\n\t}",
  "\tif true {\n\t\treturn ctrl.Result{}, false\n\t}",
  "./internal/controller/", "TestSADeletedDuringCreateLeavesNoAccount"),
 ("I21 account finalize does not look up its own by name", "internal/controller/serviceaccount_controller.go",
  "\t\tfor _, acc := range accounts {", "\t\tfor _, acc := range accounts[:0] {",
  "./internal/controller/", "TestSADeletedDuringCreateLeavesNoAccount"),
 ("I22 disable by spec not remembered", "internal/controller/serviceaccount_controller.go",
  "\t\tcase st.DisabledBySpec:", "\t\tcase st.DisabledBySpec && false:",
  "./internal/controller/", "TestSADisabledBySpecIsEnabledAgainBySpec"),
 ("I23 tenant role accepted", "internal/kaname/client.go",
  "\t\t\t\tif r.GetName() == name && r.GetIsSystem() {", "\t\t\t\tif r.GetName() == name {",
  "./internal/kaname/", "TestFindRoleAcceptsOnlySystemRoles"),
 ("I24 admission guarantee not checked", "internal/controller/accessbinding_controller.go",
  "\t\tif g.Violation != nil && needs {", "\t\tif g.Violation != nil && needs && false {",
  "./internal/controller/", "TestABUserSubjectIsRefusedWithoutTheAdmissionGuarantee"),
 ("I25 admission binding mode not checked", "internal/policy/admission.go",
  "\tcase !slices.Contains(bnd.Spec.ValidationActions, admissionv1.Deny):", "\tcase false:",
  "./internal/policy/", "TestAdmissionGuaranteeHoldsOnlyWhenEveryFactHolds"),
 ("I26 foreign Vault record overwritten", "internal/controller/serviceaccount_keys.go",
  "\tif rec != nil && !p.ownsRecord(rec, spec.Name) {", "\tif rec != nil && false {",
  "./internal/controller/", "TestKeyProtocolDoesNotOverwriteAForeignRecord"),
 ("I27 foreign Vault record deleted", "internal/controller/serviceaccount_keys.go",
  "\tif !p.ownsRecord(rec, key) {\n\t\tp.r.Recorder", "\tif false {\n\t\tp.r.Recorder",
  "./internal/controller/", "TestKeyProtocolDeletionLeavesAForeignRecord"),
 ("I28 template without cluster accepted", "internal/config/config.go",
  "var requiredPlaceholders = []string{\"{cluster}\", \"{namespace}\", \"{name}\", \"{key}\"}",
  "var requiredPlaceholders = []string{\"{namespace}\", \"{name}\", \"{key}\"}",
  "./internal/config/", "TestParseRefusesEachBrokenFact"),
 ("I29 placeholder glued into a segment accepted", "internal/config/config.go",
  "\t\tif len(phs) > 0 && (len(phs) != 1 || phs[0] != seg) {", "\t\tif false {",
  "./internal/config/", "TestParseRefusesEachBrokenFact"),
 # Цель «вся область»: каскад на все объекты области ставит только платформа,
 # при гарантии допуска; цель — ровно одна ветвь; отпечаток различает ветви.
 ("I32 allInScope accepted from any author", "internal/policy/policy.go",
  "\t\tif !slices.Contains(p.PlatformPrincipals, creator) {\n\t\t\treturn forbidden(\"target: allInScope",
  "\t\tif false {\n\t\t\treturn forbidden(\"target: allInScope",
  "./internal/policy/ ./internal/controller/", "TestEvaluateRefusesEachBrokenFact|TestABAllInScopeRefusals"),
 ("I33 allInScope needs no admission guarantee", "internal/policy/admission.go",
  "\treturn ab.Spec.Target.AllInScope != nil ||", "\treturn false ||",
  "./internal/policy/ ./internal/controller/", "TestNeedsAdmissionGuaranteeOnlyForUserGroupAndAllInScope|TestABAllInScopeRefusals"),
 ("I34 allInScope bindings are never the same binding", "internal/controller/accessbinding_controller.go",
  "\tif b.GetStatus() == iamv1.AccessBinding_REVOKED {\n\t\treturn false\n\t}\n\treturn bindingHash(",
  "\tif b.GetStatus() == iamv1.AccessBinding_REVOKED || b.GetTarget().GetAllInScope() != nil {\n\t\treturn false\n\t}\n\treturn bindingHash(",
  "./internal/controller/", "TestABAdoptsOwnAllInScopeBindingAndLeavesForeignAlone"),
 ("I35 allInScope sent as an empty resource list", "internal/controller/accessbinding_controller.go",
  "\tif ab.Spec.Target.AllInScope == nil {\n\t\trefs :=", "\tif true {\n\t\trefs :=",
  "./internal/controller/", "TestABAllInScopeFromThePlatformGrantsTheWholeAccount"),
 ("I36 chart admits allInScope from any writer", "charts/kaname-iam-operator/templates/admission.yaml",
  "!variables.grant || !has(object.spec.target.allInScope) ||", "true ||",
  "./test/admission/", "TestAllInScopeOnlyFromThePlatform"),
 ("I37 chart judges finalizer changes as grants", "charts/kaname-iam-operator/templates/admission.yaml",
  "request.operation == 'CREATE' || object.spec != oldObject.spec", "true",
  "./test/admission/", "TestOperatorFinalizesPlatformOnlyBindings"),
 # Сужение политики: выдача, ставшая недопустимой, отзывается; гарантия
 # допуска судится на последнюю смену spec по свидетельству политик.
 ("I39 narrowed binding kept in kaname", "internal/controller/accessbinding_controller.go",
  "\tif !p.holds() {\n\t\tif !narrowed {", "\tif true {\n\t\tif !narrowed {",
  "./internal/controller/", "TestABNarrowedPlatformPrincipalsWithdrawUserGroupAndAllInScope|TestABNarrowedAllowedRolesWithdrawTheBinding"),
 ("I40 admission witness ignored", "internal/policy/admission.go",
  "\t\tif prev.Generation >= s.gen {", "\t\tif true {",
  "./internal/policy/", "TestAdmissionGuaranteeIsJudgedAtTheLastSpecChange"),
 ("I41 witness of the current generation accepted", "internal/policy/admission.go",
  "\t\tif prev.Generation >= s.gen {", "\t\tif prev.Generation > s.gen {",
  "./internal/policy/", "TestAdmissionGuaranteeIsJudgedAtTheLastSpecChange"),
 ("I42 reinstalled policy accepted by name", "internal/policy/admission.go",
  "rec.PolicyUID != \"\" && rec.PolicyUID == live.PolicyUID &&", "rec.PolicyUID != \"\" &&",
  "./internal/policy/", "TestAdmissionGuaranteeIsJudgedAtTheLastSpecChange"),
 # Второй круг: свидетельство по каждой политике и по её поколению,
 # засвидетельствование платформой, цель из чужого namespace, Orphan
 # запрещённой выдачи, запись свидетельства с проверкой версии.
 ("I44 policy changed in place accepted", "internal/policy/admission.go",
  "rec.PolicyUID == live.PolicyUID && rec.PolicyGeneration == live.PolicyGeneration &&", "rec.PolicyUID == live.PolicyUID &&",
  "./internal/policy/ ./internal/controller/", "TestAdmissionGuaranteeIsJudgedAtTheLastSpecChange|TestABAdmissionPolicyChangedInPlaceKeepsTheConfirmedBinding"),
 ("I45 witness record re-dated on every pass", "internal/policy/admission.go",
  "\t\tlive.Generation = prev.Generation\n", "",
  "./internal/policy/ ./internal/controller/", "TestAdmissionGuaranteeKeepsEachPolicyWitness|TestABAdmissionGuardGrowingKeepsALawfulBinding"),
 ("I46 records of policies left out of the guard dropped", "internal/policy/admission.go",
  "\t\tif !slices.Contains(names, rec.Name) {\n\t\t\tnext = append(next, rec)", "\t\tif false {\n\t\t\tnext = append(next, rec)",
  "./internal/policy/", "TestAdmissionGuaranteeKeepsEachPolicyWitness"),
 ("I47 rewitness honoured before the policies were seen", "internal/policy/admission.go",
  "if nonce != \"\" && sw.inForce && bad == nil {", "if nonce != \"\" && (sw.inForce || true) && bad == nil {",
  "./internal/policy/ ./internal/controller/", "TestAdmissionGuaranteeRewitnessByThePlatform|TestABReinstalledGuardWithdrawsAndThePlatformRewitnessRestores"),
 ("I48 rewitness never honoured", "internal/policy/admission.go",
  "\t\t\tg.Rewitnessed, late = true, nil\n", "\t\t\tg.Rewitnessed = true\n",
  "./internal/policy/ ./internal/controller/", "TestAdmissionGuaranteeRewitnessByThePlatform|TestABReinstalledGuardWithdrawsAndThePlatformRewitnessRestores"),
 ("I49 guarantee loss reported as a narrowing", "internal/controller/accessbinding_controller.go",
  "\tif v.Admission {\n\t\treason = iamv1alpha1.ReasonAdmissionGuaranteeLost", "\tif false {\n\t\treason = iamv1alpha1.ReasonAdmissionGuaranteeLost",
  "./internal/controller/", "TestABReinstalledGuardWithdrawsAndThePlatformRewitnessRestores|TestABAdmissionPolicyChangedInPlaceKeepsTheConfirmedBinding"),
 ("I50 target of another namespace only refused", "internal/controller/accessbinding_controller.go",
  "\tif v != nil && v.Reason == iamv1alpha1.ReasonForbidden {\n\t\treturn v, nil, nil", "\tif false {\n\t\treturn v, nil, nil",
  "./internal/controller/", "TestABTargetMovedToAnotherNamespaceIsWithdrawn"),
 ("I51 pending target masks a foreign one", "internal/policy/policy.go",
  "\t\tcase v.Reason == iamv1alpha1.ReasonForbidden:\n\t\t\treturn v, nil", "\t\tcase v.Reason == iamv1alpha1.ReasonForbidden && pending == nil:\n\t\t\treturn v, nil",
  "./internal/policy/", "TestResolveTargets"),
 ("I52 Orphan keeps a forbidden binding", "internal/controller/accessbinding_controller.go",
  "\t\tif forbid == nil && !p.narrowed() {\n\t\t\treturn p.removeFinalizer(ctx)", "\t\tif true {\n\t\t\treturn p.removeFinalizer(ctx)",
  "./internal/controller/", "TestABOrphanDeletionWithdrawsAForbiddenBinding"),
 # Orphan держат двое: запрет, увиденный сверкой на удалении (unseen), и
 # уже начатый отзыв (lost: на удалении поколение растёт, и гарантия сверкой
 # не отказывает). Каждый держатель снимается отдельно.
 ("I53 Orphan judged by the withdrawal already started only", "internal/controller/accessbinding_controller.go",
  "\t\tif forbid == nil && !p.narrowed() {\n\t\t\treturn p.removeFinalizer(ctx)", "\t\tif !p.narrowed() {\n\t\t\treturn p.removeFinalizer(ctx)",
  "./internal/controller/", "TestABOrphanDeletionWithdrawsAForbiddenBinding"),
 ("I54 Orphan judged by the policy seen at deletion only", "internal/controller/accessbinding_controller.go",
  "\t\tif forbid == nil && !p.narrowed() {\n\t\t\treturn p.removeFinalizer(ctx)", "\t\tif forbid == nil {\n\t\t\treturn p.removeFinalizer(ctx)",
  "./internal/controller/", "TestABOrphanDeletionWithdrawsAForbiddenBinding"),
 ("I55 status written without the resourceVersion check", "internal/controller/accessbinding_controller.go",
  "\tif err := p.r.Status().Update(ctx, p.ab); err != nil {",
  "\tfrom := p.ab.DeepCopy()\n\tfrom.Status = *p.saved\n\tif err := p.r.Status().Patch(ctx, p.ab, client.MergeFrom(from)); err != nil {",
  "./internal/controller/", "TestABWitnessWriteLosesToAConcurrentSpecChange"),
 ("I56 chart admits rewitness from any writer", "charts/kaname-iam-operator/templates/admission.yaml",
  "(variables.annotations[?'iam.kaname.in-cloud.io/rewitness'].orValue('') == variables.oldAnnotations[?'iam.kaname.in-cloud.io/rewitness'].orValue('')) ||",
  "true ||",
  "./test/admission/", "TestRewitnessAnnotationOnlyFromThePlatform"),
 # Третий круг: подтверждение гарантии переживает правку политик на месте
 # (смену values чарта) — для того же spec и created-by и не дольше
 # переустановки; версия политики вступает в силу по истечении срока, и
 # старшинство политики над объектом судится с тем же сроком; свидетельство —
 # с первого прохода, отказ — только выдачам, которым гарантия нужна; Orphan
 # с неразрешимым типом цели завершается.
 ("I57 confirmation ignored: an in-place change revokes a confirmed binding", "internal/policy/admission.go",
  "\tif late != nil && confirmedGen != 0 && confirmedGen == sw.gen && confirmedBy == createdBy {", "\tif false {",
  "./internal/policy/ ./test/admission/ ./internal/controller/",
  "TestAdmissionGuaranteeConfirmedSpecSurvivesAnInPlaceChange|TestChartValuesUpgradeKeepsAPermissibleBinding|TestABAdmissionPolicyChangedInPlaceKeepsTheConfirmedBinding"),
 ("I58 confirmation not tied to created-by", "internal/policy/admission.go",
  "confirmedGen == sw.gen && confirmedBy == createdBy {", "confirmedGen == sw.gen {",
  "./internal/policy/", "TestAdmissionGuaranteeConfirmedSpecSurvivesAnInPlaceChange"),
 ("I59 confirmation survives a reinstall", "internal/policy/admission.go",
  "\tif sw.reinstalled || bad != nil {\n\t\tconfirmedGen, confirmedBy = 0, \"\"", "\tif bad != nil {\n\t\tconfirmedGen, confirmedBy = 0, \"\"",
  "./internal/policy/", "TestAdmissionGuaranteeConfirmedSpecSurvivesAnInPlaceChange"),
 ("I60 a seen version trusted before it takes effect", "internal/policy/admission.go",
  "\tcase seen && sameVersion(prev, live) && prev.PendingSince != nil:", "\tcase seen && sameVersion(prev, live) && prev.PendingSince != nil && false:",
  "./internal/policy/ ./internal/controller/", "TestAdmissionGuaranteeWaitsUntilThePolicyTakesEffect|TestABReinstalledGuardWithdrawsAndThePlatformRewitnessRestores"),
 ("I61 a seen version never takes effect", "internal/policy/admission.go",
  "\t\tif since := prev.PendingSince.Time; s.now.Before(since.Add(s.delay)) {", "\t\tif since := prev.PendingSince.Time; true || s.now.Before(since.Add(s.delay)) {",
  "./internal/policy/", "TestAdmissionGuaranteeWaitsUntilThePolicyTakesEffect"),
 ("I62 policy age judged without the enforcement delay", "internal/policy/admission.go",
  "\treturn object.Sub(policy) >= delay+time.Second", "\treturn !policy.After(object)",
  "./internal/policy/", "TestAdmissionGuaranteeWaitsUntilThePolicyTakesEffect"),
 ("I63 witness only for bindings that need the guarantee", "internal/controller/accessbinding_controller.go",
  "needs || len(p.r.Config.Policy.AdmissionGuard) > 0 {", "needs {",
  "./internal/controller/", "TestABWitnessIsKeptBeforeTheBindingNeedsTheGuarantee"),
 ("I64 guarantee refusal counted for every binding", "internal/controller/accessbinding_controller.go",
  "\t\tif g.Violation != nil && needs {", "\t\tif g.Violation != nil {",
  "./internal/controller/", "TestABCreatesTheBindingInKaname"),
 ("I65 Orphan with an unresolvable target type waits forever", "internal/controller/accessbinding_controller.go",
  "\t\tcase meta.IsNoMatchError(err):", "\t\tcase meta.IsNoMatchError(err) && false:",
  "./internal/controller/", "TestABOrphanDeletionWithAnUnresolvableTargetTypeCompletes"),
 ("I66 enforcement delay below the refresh interval accepted", "internal/config/config.go",
  "\tif d := p.AdmissionEnforcementDelay.Duration; d < minAdmissionEnforcementDelay {", "\tif d := p.AdmissionEnforcementDelay.Duration; d < 0 {",
  "./internal/config/", "TestParseRefusesEachBrokenFact"),
 ("I43 status policy left out of the admission guarantee", "charts/kaname-iam-operator/templates/_helpers.tpl",
  " (printf \"%s-status\" (include \"kio.fullname\" .))", "",
  "./test/admission/", "TestChartAdmissionGuardIsSatisfiedByItsOwnPolicies"),
 ("I38 CRD accepts both or neither target arm", "config/crd/bases/iam.kaname.in-cloud.io_accessbindings.yaml",
  "rule: has(self.resources) != has(self.allInScope)", "rule: \"true\"",
  "./api/v1alpha1/", "TestAccessBindingCreateRefusalsAndTwins|TestAccessBindingImmutableFieldsAndMutableTarget"),
]


def go_vet(path, pkgs):
    """go vet инъецированного дерева: пакет правленого файла и пакеты пробы.
    Инъекция, после которой дерево не собирается, судит не продукт, а
    компилятор: такая — находка NOT-COMPILED, а не красное."""
    if not path.endswith(".go"):
        return 0, ""
    targets = ["./" + os.path.dirname(path) + "/"] + [p for p in pkgs.split() if p != "./" + os.path.dirname(path) + "/"]
    r = subprocess.run(["go", "vet", *targets], cwd=ROOT, capture_output=True, text=True, timeout=900)
    return r.returncode, (r.stdout + r.stderr).strip()


def go_test(pkgs, run):
    cmd = ["go", "test", *pkgs.split(), "-count=1", "-run", "^(" + run + ")$"]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=900)
    out = r.stdout + r.stderr
    lines = [l.strip() for l in out.splitlines() if l.strip().startswith("--- FAIL") or "_test.go:" in l]
    return r.returncode, lines, out


def main():
    findings = 0
    print("ИНЪЕКЦИЯ\tКОНТРОЛЬ\tИСХОД\tТЕКСТ ОТКАЗА")
    for name, path, old, new, pkgs, run in INJ:
        p = os.path.join(ROOT, path)
        src = open(p).read()
        # Свойство, у которого два держателя, роняется только обоими сразу:
        # old и new тогда — кортежи пар, каждая со своим якорем.
        pairs = list(zip(old, new)) if isinstance(old, tuple) else [(old, new)]
        missing = [o for o, _ in pairs if src.count(o) != 1]
        if missing:
            print(f"{name}\t-\tNOT-APPLIED\tякорь найден {src.count(missing[0])} раз")
            findings += 1
            continue
        injected = src
        for o, n in pairs:
            injected = injected.replace(o, n)
        rc, lines, out = go_test(pkgs, run)
        if rc != 0:
            print(f"{name}\tRED\tCONTROL-FAILED\t{(lines or [out[-200:]])[0][:200]}")
            findings += 1
            continue
        open(p, "w").write(injected)
        try:
            vrc, vout = go_vet(path, pkgs)
            if vrc != 0:
                print(f"{name}\tGREEN\tNOT-COMPILED\t{vout.splitlines()[-1][:200] if vout else vrc}")
                findings += 1
                continue
            rc, lines, out = go_test(pkgs, run)
        finally:
            open(p, "w").write(src)
        if rc != 0 and any(l.startswith("--- FAIL") for l in lines):
            text = next((l for l in lines if "_test.go:" in l), lines[0])
            print(f"{name}\tGREEN\tRED\t{text[:220]}")
        else:
            print(f"{name}\tGREEN\tMISSED rc={rc}\t{(lines or [out[-200:]])[0][:200]}")
            findings += 1
    print(f"инъекций {len(INJ)} · находок {findings}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
