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
  "\t\tif !p.resyncNow {\n\t\t\treturn p.drift(iamv1alpha1.ReasonDisabledExternally,",
  "\t\tif false {\n\t\t\treturn p.drift(iamv1alpha1.ReasonDisabledExternally,",
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
  "\t\tif err != nil || int(want) != cur {", "\t\tif err != nil {",
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
        if src.count(old) != 1:
            print(f"{name}\t-\tNOT-APPLIED\tякорь найден {src.count(old)} раз")
            findings += 1
            continue
        rc, lines, out = go_test(pkgs, run)
        if rc != 0:
            print(f"{name}\tRED\tCONTROL-FAILED\t{(lines or [out[-200:]])[0][:200]}")
            findings += 1
            continue
        open(p, "w").write(src.replace(old, new))
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
