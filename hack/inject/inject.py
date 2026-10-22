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
  "\tif policy.NeedsAdmissionGuarantee(ab) {", "\tif policy.NeedsAdmissionGuarantee(ab) && false {",
  "./internal/controller/", "TestABUserSubjectIsRefusedWithoutTheAdmissionGuarantee"),
 ("I25 admission binding mode not checked", "internal/policy/admission.go",
  "\t\tcase !slices.Contains(bnd.Spec.ValidationActions, admissionv1.Deny):", "\t\tcase false:",
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
  "\tif w == nil || w.Generation >= gen {", "\tif true {",
  "./internal/policy/", "TestAdmissionGuaranteeIsJudgedAtTheLastSpecChange"),
 ("I41 witness of the current generation accepted", "internal/policy/admission.go",
  "\tif w == nil || w.Generation >= gen {", "\tif w == nil || w.Generation > gen {",
  "./internal/policy/", "TestAdmissionGuaranteeIsJudgedAtTheLastSpecChange"),
 ("I42 reinstalled policy accepted by name", "internal/policy/admission.go",
  "{ return recorded != \"\" && recorded == live }", "{ return recorded != \"\" }",
  "./internal/policy/", "TestAdmissionGuaranteeIsJudgedAtTheLastSpecChange"),
 ("I43 status policy left out of the admission guarantee", "charts/kaname-iam-operator/templates/_helpers.tpl",
  " (printf \"%s-status\" (include \"kio.fullname\" .))", "",
  "./test/admission/", "TestChartAdmissionGuardIsSatisfiedByItsOwnPolicies"),
 ("I38 CRD accepts both or neither target arm", "config/crd/bases/iam.kaname.in-cloud.io_accessbindings.yaml",
  "rule: has(self.resources) != has(self.allInScope)", "rule: \"true\"",
  "./api/v1alpha1/", "TestAccessBindingCreateRefusalsAndTwins|TestAccessBindingImmutableFieldsAndMutableTarget"),
]


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
