// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Package admission_test — проба чарта и ограждения допуска: чарт
// рендерится helm, его ValidatingAdmissionPolicy применяются к настоящему
// kube-apiserver (envtest), и каждое отрицание проверяется вместе с законным
// близнецом от имени настоящих пользователей (имперсонация).
package admission_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/config"
	"github.com/PRO-Robotech/kaname-iam-operator/internal/policy"
)

const (
	release   = "kio"
	releaseNS = "kaname-iam-system"
	tenantNS  = "cust01"

	registryOperator = "system:serviceaccount:registry-system:registry-operator"
	argo             = "system:serviceaccount:argocd:argocd-application-controller"
	platform         = "system:serviceaccount:platform-system:onboarding"
	operatorUser     = "system:serviceaccount:kaname-iam-system:kaname-iam-operator"
	stranger         = "system:serviceaccount:cust01:default"
	nsController     = "system:serviceaccount:kube-system:namespace-controller"
)

var (
	restCfg  *rest.Config
	scheme   = runtime.NewScheme()
	rendered []*unstructured.Unstructured
	repoRoot = filepath.Join("..", "..")
	// seal — печать свидетельства допуска оператора проб.
	seal = func() *policy.WitnessSeal {
		s, err := policy.NewWitnessSeal(bytes.Repeat([]byte{7}, policy.WitnessKeyBytes))
		if err != nil {
			panic(err)
		}
		return s
	}()
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		fmt.Fprintln(os.Stderr, "admission suite: KUBEBUILDER_ASSETS is not set — run through `make test`; the suite is NOT executed")
		return 3
	}
	out, err := helmTemplate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "helm template:", err)
		return 1
	}
	rendered, err = decodeAll(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "decode chart:", err)
		return 1
	}
	_ = clientgoscheme.AddToScheme(scheme)
	_ = iamv1alpha1.AddToScheme(scheme)
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join(repoRoot, "charts", "kaname-iam-operator", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	restCfg, err = env.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest:", err)
		return 1
	}
	defer func() { _ = env.Stop() }()
	admin, _ := client.New(restCfg, client.Options{Scheme: scheme})
	ctx := context.Background()
	for _, ns := range []string{releaseNS, tenantNS} {
		if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
			fmt.Fprintln(os.Stderr, "namespace:", err)
			return 1
		}
	}
	n := 0
	for _, obj := range rendered {
		if !strings.HasPrefix(obj.GetKind(), "ValidatingAdmissionPolicy") {
			continue
		}
		if err := admin.Create(ctx, obj.DeepCopy()); err != nil {
			fmt.Fprintln(os.Stderr, "apply", obj.GetKind(), obj.GetName(), err)
			return 1
		}
		n++
	}
	if n != 6 {
		fmt.Fprintf(os.Stderr, "chart rendered %d admission objects, want 6 (3 policies + 3 bindings)\n", n)
		return 1
	}
	return m.Run()
}

func helmTemplate(extra ...string) ([]byte, error) {
	args := append([]string{"template", release, filepath.Join(repoRoot, "charts", "kaname-iam-operator"),
		"--namespace", releaseNS, "-f", filepath.Join("testdata", "values.yaml")}, extra...)
	cmd := exec.Command("helm", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}
	return out, nil
}

func decodeAll(data []byte) ([]*unstructured.Unstructured, error) {
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var out []*unstructured.Unstructured
	for {
		u := &unstructured.Unstructured{}
		if err := dec.Decode(&u.Object); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		if len(u.Object) > 0 {
			out = append(out, u)
		}
	}
}

// as — клиент от имени user. Группа system:masters даёт право RBAC, но не
// снимает ограждения допуска: оно судит имя пользователя.
func as(t *testing.T, user string) client.Client {
	t.Helper()
	cfg := rest.CopyConfig(restCfg)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: []string{"system:masters", "system:authenticated"}}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var seq int

func sa() *iamv1alpha1.ServiceAccount {
	seq++
	return &iamv1alpha1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("sa-%d", seq), Namespace: tenantNS},
		Spec:       iamv1alpha1.ServiceAccountSpec{Name: fmt.Sprintf("zot-%d", seq)},
	}
}

func ab(role string, subjects ...iamv1alpha1.Subject) *iamv1alpha1.AccessBinding {
	seq++
	if len(subjects) == 0 {
		subjects = []iamv1alpha1.Subject{{ServiceAccountRef: &iamv1alpha1.LocalServiceAccountRef{Name: "zot"}}}
	}
	return &iamv1alpha1.AccessBinding{
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("ab-%d", seq), Namespace: tenantNS},
		Spec: iamv1alpha1.AccessBindingSpec{
			Subjects: subjects, RoleRef: iamv1alpha1.RoleRef{Name: role},
			Target: iamv1alpha1.Target{Resources: []iamv1alpha1.ResourceRef{{Type: "registry.registries", ID: "abc123"}}},
		},
	}
}

func denied(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("admitted; want denial naming %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("denial %q does not name %q", err, want)
	}
}

func admitted(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("lawful twin denied: %v", err)
	}
}

// Статус проверки типов политик пишет kube-controller-manager, которого в
// envtest нет. Компиляцию выражений доказывают законные близнецы ниже: с
// failurePolicy: Fail политика с неразобранным выражением отказала бы и им.

func TestOnlyConfiguredWritersCreateAndDelete(t *testing.T) {
	ctx := context.Background()
	denied(t, as(t, stranger).Create(ctx, sa()), "may not CREATE")
	for _, w := range []string{registryOperator, argo, platform} {
		admitted(t, as(t, w).Create(ctx, sa()))
	}
	obj := sa()
	admitted(t, as(t, registryOperator).Create(ctx, obj))
	denied(t, as(t, stranger).Delete(ctx, obj), "may not DELETE")
	denied(t, as(t, operatorUser).Delete(ctx, obj), "may not DELETE")
	admitted(t, as(t, nsController).Delete(ctx, obj))
}

func TestOperatorChangesOnlyFinalizersAndWritesStatus(t *testing.T) {
	ctx := context.Background()
	obj := sa()
	admitted(t, as(t, registryOperator).Create(ctx, obj))
	op := as(t, operatorUser)
	cur := &iamv1alpha1.ServiceAccount{}
	if err := op.Get(ctx, client.ObjectKeyFromObject(obj), cur); err != nil {
		t.Fatal(err)
	}
	spec := cur.DeepCopy()
	spec.Spec.Description = "changed by the operator"
	denied(t, op.Update(ctx, spec), "may not UPDATE")
	ann := cur.DeepCopy()
	ann.Annotations = map[string]string{"x": "y"}
	denied(t, op.Update(ctx, ann), "may not UPDATE")
	fin := cur.DeepCopy()
	fin.Finalizers = append(fin.Finalizers, iamv1alpha1.Finalizer)
	admitted(t, op.Update(ctx, fin))

	st := &iamv1alpha1.ServiceAccount{}
	_ = op.Get(ctx, client.ObjectKeyFromObject(obj), st)
	st.Status.ID = "sva1"
	admitted(t, op.Status().Update(ctx, st))
	_ = op.Get(ctx, client.ObjectKeyFromObject(obj), st)
	st.Status.ID = "sva-forged"
	denied(t, as(t, registryOperator).Status().Update(ctx, st), "may not write the status")
}

func TestBindingRoleSubjectsAndPrincipals(t *testing.T) {
	ctx := context.Background()
	w := as(t, registryOperator)
	denied(t, w.Create(ctx, ab("registry.admin")), "is not in the allowed roles")
	admitted(t, w.Create(ctx, ab("registry.pusher")))

	anon := iamv1alpha1.Subject{SystemClass: &iamv1alpha1.SystemClassRef{Name: "anonymous"}}
	denied(t, w.Create(ctx, ab("registry.pusher", anon)), "system class subject")
	admitted(t, w.Create(ctx, ab("registry.public.read", anon)))

	user := iamv1alpha1.Subject{User: &iamv1alpha1.PrincipalRef{ID: "usr1"}}
	denied(t, w.Create(ctx, ab("registry.pusher", user)), "platform principal")
	admitted(t, as(t, platform).Create(ctx, ab("registry.pusher", user)))
}

// Цель «вся область» ставит только принципал платформы — при создании и при
// смене цели. Законные близнецы: та же выдача от платформы и выдача с
// перечнем от писателя.
func TestAllInScopeOnlyFromThePlatform(t *testing.T) {
	ctx := context.Background()
	whole := func() *iamv1alpha1.AccessBinding {
		b := ab("registry.pusher")
		b.Spec.Scope.Type = iamv1alpha1.ScopeAccount
		b.Spec.Target = iamv1alpha1.Target{AllInScope: &iamv1alpha1.AllInScope{}}
		return b
	}
	w := as(t, registryOperator)
	denied(t, w.Create(ctx, whole()), "allInScope target is accepted only from a platform principal")
	admitted(t, as(t, platform).Create(ctx, whole()))

	named := ab("registry.pusher")
	admitted(t, w.Create(ctx, named))
	flip := func(c client.Client) error {
		cur := &iamv1alpha1.AccessBinding{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(named), cur); err != nil {
			t.Fatal(err)
		}
		cur.Spec.Target = iamv1alpha1.Target{AllInScope: &iamv1alpha1.AllInScope{}}
		return c.Update(ctx, cur)
	}
	denied(t, flip(w), "allInScope target is accepted only from a platform principal")
	admitted(t, flip(as(t, platform)))
}

// Выдачи, которые ставит только платформа (субъект user, вся область), оператор
// обязан брать под финализатор и снимать его: правка без смены spec — не
// выдача, и ограда принципала платформы её не судит. Близнец-отрицание: та же
// правка с изменённым spec отвергается.
func TestOperatorFinalizesPlatformOnlyBindings(t *testing.T) {
	ctx := context.Background()
	user := ab("registry.pusher", iamv1alpha1.Subject{User: &iamv1alpha1.PrincipalRef{ID: "usr1"}})
	whole := ab("registry.pusher")
	whole.Spec.Target = iamv1alpha1.Target{AllInScope: &iamv1alpha1.AllInScope{}}
	op := as(t, operatorUser)
	for _, obj := range []*iamv1alpha1.AccessBinding{user, whole} {
		admitted(t, as(t, platform).Create(ctx, obj))
		cur := &iamv1alpha1.AccessBinding{}
		if err := op.Get(ctx, client.ObjectKeyFromObject(obj), cur); err != nil {
			t.Fatal(err)
		}
		spec := cur.DeepCopy()
		spec.Finalizers = append(spec.Finalizers, iamv1alpha1.Finalizer)
		spec.Spec.Labels = map[string]string{"team": "x"}
		// Отказывают обе политики (писателей и выдач); какая названа первой —
		// порядок сервера, поэтому судится сам отказ.
		if err := op.Update(ctx, spec); err == nil || !apierrors.IsForbidden(err) {
			t.Fatalf("operator spec change on a platform-only binding: %v, want a denial", err)
		}
		fin := cur.DeepCopy()
		fin.Finalizers = append(fin.Finalizers, iamv1alpha1.Finalizer)
		admitted(t, op.Update(ctx, fin))
		if err := op.Get(ctx, client.ObjectKeyFromObject(obj), cur); err != nil {
			t.Fatal(err)
		}
		cur.Finalizers = nil
		admitted(t, op.Update(ctx, cur))
	}
}

func TestResyncAnnotationOnlyFromThePlatform(t *testing.T) {
	ctx := context.Background()
	obj := sa()
	admitted(t, as(t, registryOperator).Create(ctx, obj))
	set := func(c client.Client, v string) error {
		cur := &iamv1alpha1.ServiceAccount{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), cur); err != nil {
			t.Fatal(err)
		}
		cur.Annotations = map[string]string{iamv1alpha1.AnnotationResyncDrift: v}
		return c.Update(ctx, cur)
	}
	denied(t, set(as(t, registryOperator), "n1"), "resync-drift is set only by a platform principal")
	admitted(t, set(as(t, platform), "n1"))
}

// Аннотацию rewitness — просьбу засвидетельствовать политики допуска для
// текущего spec — ставит только платформа: по ней оператор восстанавливает
// выдачи пользователям и на всю область без смены spec. Близнец — то же
// значение от принципала платформы.
func TestRewitnessAnnotationOnlyFromThePlatform(t *testing.T) {
	ctx := context.Background()
	obj := ab("registry.pusher")
	admitted(t, as(t, registryOperator).Create(ctx, obj))
	set := func(c client.Client, v string) error {
		cur := &iamv1alpha1.AccessBinding{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), cur); err != nil {
			t.Fatal(err)
		}
		cur.Annotations = map[string]string{iamv1alpha1.AnnotationRewitness: v}
		return c.Update(ctx, cur)
	}
	denied(t, set(as(t, registryOperator), "n1"), "rewitness is set only by a platform principal")
	admitted(t, set(as(t, platform), "n1"))
	denied(t, set(as(t, registryOperator), "n2"), "rewitness is set only by a platform principal")
}

func TestCreatedByAnnotationIsAuthentic(t *testing.T) {
	ctx := context.Background()
	spoof := sa()
	spoof.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: platform}
	denied(t, as(t, registryOperator).Create(ctx, spoof), "must name the creating user")
	own := sa()
	own.Annotations = map[string]string{iamv1alpha1.AnnotationCreatedBy: registryOperator}
	admitted(t, as(t, registryOperator).Create(ctx, own))
	cur := &iamv1alpha1.ServiceAccount{}
	if err := as(t, platform).Get(ctx, client.ObjectKeyFromObject(own), cur); err != nil {
		t.Fatal(err)
	}
	cur.Annotations[iamv1alpha1.AnnotationCreatedBy] = platform
	denied(t, as(t, platform).Update(ctx, cur), "created-by is immutable")
}

// Чарт держит CRD той же ревизии, что config/crd/bases: два места об одном
// предмете сверяются байт в байт.
func TestChartCRDsMatchTheGeneratedOnes(t *testing.T) {
	gen, err := filepath.Glob(filepath.Join(repoRoot, "config", "crd", "bases", "*.yaml"))
	if err != nil || len(gen) == 0 {
		t.Fatalf("no generated CRDs: %v", err)
	}
	for _, g := range gen {
		want, _ := os.ReadFile(g)
		got, err := os.ReadFile(filepath.Join(repoRoot, "charts", "kaname-iam-operator", "crds", filepath.Base(g)))
		if err != nil || !bytes.Equal(want, got) {
			t.Errorf("chart CRD %s differs from %s: run make manifests", filepath.Base(g), g)
		}
	}
}

func find(kind, nameSuffix string) *unstructured.Unstructured {
	for _, o := range rendered {
		if o.GetKind() == kind && strings.HasSuffix(o.GetName(), nameSuffix) {
			return o
		}
	}
	return nil
}

func TestDeploymentCarriesTheFederatedEntryAndLeaderElection(t *testing.T) {
	u := find("Deployment", "")
	if u == nil {
		t.Fatal("no Deployment rendered")
	}
	var d appsv1.Deployment
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &d); err != nil {
		t.Fatal(err)
	}
	c := d.Spec.Template.Spec.Containers[0]
	args := strings.Join(c.Args, " ")
	for _, want := range []string{"--leader-elect=true", "--metrics-secure=true", "--config=/etc/kaname-iam-operator/config.yaml"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q lack %s", args, want)
		}
	}
	env := map[string]string{}
	for _, e := range c.Env {
		if e.ValueFrom != nil && e.ValueFrom.FieldRef != nil {
			env[e.Name] = e.ValueFrom.FieldRef.FieldPath
		}
	}
	if env["POD_NAMESPACE"] != "metadata.namespace" || env["SERVICE_ACCOUNT_NAME"] != "spec.serviceAccountName" {
		t.Errorf("downward env = %v", env)
	}
	sc := c.SecurityContext
	if sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Errorf("container security context = %+v", sc)
	}
	var projected *corev1.ServiceAccountTokenProjection
	for _, v := range d.Spec.Template.Spec.Volumes {
		if v.Projected != nil {
			for _, s := range v.Projected.Sources {
				if s.ServiceAccountToken != nil {
					projected = s.ServiceAccountToken
				}
			}
		}
	}
	if projected == nil || projected.Audience != "vault" {
		t.Errorf("vault projected token = %+v", projected)
	}
}

// witnessKeySecret — имя Secret ключа печати свидетельства из аргументов
// оператора в Deployment чарта.
func witnessKeySecret(t *testing.T) string {
	t.Helper()
	u := find("Deployment", "")
	if u == nil {
		t.Fatal("no Deployment rendered")
	}
	var d appsv1.Deployment
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &d); err != nil {
		t.Fatal(err)
	}
	for _, a := range d.Spec.Template.Spec.Containers[0].Args {
		if name, ok := strings.CutPrefix(a, "--witness-key-secret="); ok && name != "" {
			return name
		}
	}
	t.Fatal("the Deployment does not name the witness key secret (--witness-key-secret)")
	return ""
}

func TestRBACIsNarrow(t *testing.T) {
	u := find("Role", "-self")
	if u == nil {
		t.Fatal("no Role rendered")
	}
	var r rbacv1.Role
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &r); err != nil {
		t.Fatal(err)
	}
	var token *rbacv1.PolicyRule
	for i := range r.Rules {
		for _, res := range r.Rules[i].Resources {
			if res == "serviceaccounts/token" {
				token = &r.Rules[i]
			}
		}
	}
	if token == nil || len(token.ResourceNames) != 1 || token.ResourceNames[0] != "kaname-iam-operator" {
		t.Fatalf("serviceaccounts/token rule = %+v: the operator may mint a token only for itself", token)
	}
	// Secret своего namespace: читается только ключ печати свидетельства, тот,
	// что называет аргумент оператора; заводить можно (create именем не
	// сужается), читать и править прочие — нет.
	key := witnessKeySecret(t)
	reads := 0
	for _, rule := range r.Rules {
		if !slices.Contains(rule.Resources, "secrets") {
			continue
		}
		for _, v := range rule.Verbs {
			switch {
			case v == "create":
			case v == "get" && len(rule.ResourceNames) == 1 && rule.ResourceNames[0] == key:
				reads++
			default:
				t.Errorf("Role grants %s on secrets %v: the operator reads only its witness key %s", v, rule.ResourceNames, key)
			}
		}
	}
	if reads != 1 {
		t.Errorf("Role grants get on the witness key secret %s %d times, want once", key, reads)
	}
	cr := find("ClusterRole", "-manager")
	if cr == nil {
		t.Fatal("no manager ClusterRole")
	}
	raw, _ := yaml.Marshal(cr.Object)
	if strings.Contains(string(raw), "secrets") {
		t.Error("manager ClusterRole reaches secrets")
	}
	if !strings.Contains(string(raw), "registryidreservations") {
		t.Error("manager ClusterRole lacks get on the target resolver resource")
	}
}

// Права оператора объявлены дважды: маркерами kubebuilder (config/rbac,
// controller-gen) и чартом. Чарт обязан покрывать каждое правило маркеров:
// иначе установленный оператор получает отказ там, где код его ждёт.
func TestChartRBACCoversTheGeneratedRole(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "config", "rbac", "role.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var gen rbacv1.ClusterRole
	if err := yaml.Unmarshal(raw, &gen); err != nil {
		t.Fatal(err)
	}
	if len(gen.Rules) == 0 {
		t.Fatal("generated role has no rules: the census read nothing")
	}
	u := find("ClusterRole", "-manager")
	if u == nil {
		t.Fatal("no manager ClusterRole rendered")
	}
	var chart rbacv1.ClusterRole
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &chart); err != nil {
		t.Fatal(err)
	}
	granted := map[string]bool{}
	for _, r := range chart.Rules {
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					granted[g+"/"+res+"/"+v] = true
				}
			}
		}
	}
	n := 0
	for _, r := range gen.Rules {
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					n++
					if !granted[g+"/"+res+"/"+v] {
						t.Errorf("chart does not grant %s %s/%s required by the controller markers", v, g, res)
					}
				}
			}
		}
	}
	t.Logf("generated permissions checked: %d", n)
}

func TestChartRefusesAnIncompleteConfig(t *testing.T) {
	_, err := helmTemplate("--set", "config.clusterName=")
	if err == nil || !strings.Contains(err.Error(), "config.clusterName is required") {
		t.Fatalf("render without clusterName: %v", err)
	}
	_, err = helmTemplate("--set", "config.policy.allowedRoles=null")
	if err == nil || !strings.Contains(err.Error(), "allowedRoles must name at least one role") {
		t.Fatalf("render without allowed roles: %v", err)
	}
}

// renderedConfig — config.yaml оператора из ConfigMap рендера, разобранный
// тем же Parse, что и на старте процесса.
func renderedConfig(t *testing.T, objs []*unstructured.Unstructured) *config.Config {
	t.Helper()
	for _, o := range objs {
		if o.GetKind() != "ConfigMap" || !strings.HasSuffix(o.GetName(), "-config") {
			continue
		}
		raw, _, err := unstructured.NestedString(o.Object, "data", "config.yaml")
		if err != nil || raw == "" {
			t.Fatalf("config.yaml absent in %s: %v", o.GetName(), err)
		}
		c, err := config.Parse([]byte(raw))
		if err != nil {
			t.Fatalf("rendered config refused by the operator: %v", err)
		}
		return c
	}
	t.Fatal("no operator ConfigMap rendered")
	return nil
}

// Гарантия допуска, которую оператор сверяет для субъектов user/group, держится
// ровно политиками этого чарта: названные в config имена — его политики,
// поставленные в настоящий kube-apiserver, и проверка оператора их принимает.
// Без допуска перечень пуст — оператор user/group не примет.
func TestChartAdmissionGuardIsSatisfiedByItsOwnPolicies(t *testing.T) {
	c := renderedConfig(t, rendered)
	// Политика status — в гарантии: свидетельство политик в status подлинно,
	// только пока status пишет один оператор.
	if len(c.Policy.AdmissionGuard) != 3 || !slices.ContainsFunc(c.Policy.AdmissionGuard, func(n string) bool { return strings.HasSuffix(n, "-status") }) {
		t.Fatalf("admissionGuard = %v, want the writers, bindings and status policies", c.Policy.AdmissionGuard)
	}
	for _, n := range c.Policy.AdmissionGuard {
		if find("ValidatingAdmissionPolicy", n) == nil || find("ValidatingAdmissionPolicyBinding", n) == nil {
			t.Fatalf("admissionGuard names %s, which the chart does not render with its binding", n)
		}
	}
	admin, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	created := &iamv1alpha1.AccessBinding{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(time.Now().Add(time.Minute)), Generation: 1}}
	g, err := policy.CheckAdmissionGuarantee(context.Background(), admin, c.Policy, seal, created, time.Now())
	if v := g.Violation; err != nil || v != nil {
		t.Fatalf("the operator refuses the chart's own admission policies: %v %v", v, err)
	}
	out, err := helmTemplate("--set", "admission.enabled=false")
	if err != nil {
		t.Fatal(err)
	}
	objs, err := decodeAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if off := renderedConfig(t, objs); len(off.Policy.AdmissionGuard) != 0 {
		t.Fatalf("admission disabled, yet admissionGuard = %v", off.Policy.AdmissionGuard)
	}
}

// upgrade — helm upgrade политик допуска: spec каждой политики и привязки из
// рендера objs ставится на стоящий объект (uid тот же; где spec сменился,
// metadata.generation растёт). Возвращает поколения после правки по имени.
func upgrade(t *testing.T, admin client.Client, objs []*unstructured.Unstructured) map[string]int64 {
	t.Helper()
	ctx := context.Background()
	gens := map[string]int64{}
	for _, o := range objs {
		if !strings.HasPrefix(o.GetKind(), "ValidatingAdmissionPolicy") {
			continue
		}
		cur := &unstructured.Unstructured{}
		cur.SetGroupVersionKind(o.GroupVersionKind())
		if err := admin.Get(ctx, client.ObjectKey{Name: o.GetName()}, cur); err != nil {
			t.Fatalf("upgrade: get %s %s: %v", o.GetKind(), o.GetName(), err)
		}
		cur.Object["spec"] = o.Object["spec"]
		if err := admin.Update(ctx, cur); err != nil {
			t.Fatalf("upgrade: update %s %s: %v", o.GetKind(), o.GetName(), err)
		}
		gens[o.GetKind()+"/"+o.GetName()] = cur.GetGeneration()
	}
	return gens
}

// renderWith — рендер чарта с allowedRoles roles.
func renderWith(t *testing.T, roles ...string) []*unstructured.Unstructured {
	t.Helper()
	b, _ := json.Marshal(roles)
	out, err := helmTemplate("--set-json", "config.policy.allowedRoles="+string(b))
	if err != nil {
		t.Fatal(err)
	}
	objs, err := decodeAll(out)
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

// Смена values чарта (helm upgrade) правит политики допуска на месте: роли
// перечня — в выражении политики выдач, и её metadata.generation растёт.
// Выдача, допустимая и до, и после смены, чью гарантию проход подтвердил до
// правки, остаётся допустимой — до срока вступления новой версии в силу и
// после него: оператор её не отзывает. Близнец — upgrade, сужающий перечень
// ролей под выдачу: выдача недопустима, и оператор её отзывает. Политики —
// отрендеренные чартом, в настоящем kube-apiserver; сверка оператора — та
// же, что в проходе (Evaluate, затем гарантия допуска).
func TestChartValuesUpgradeKeepsAPermissibleBinding(t *testing.T) {
	admin, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { upgrade(t, admin, rendered) })
	ctx := context.Background()
	verdict := func(c *config.Config, ab *iamv1alpha1.AccessBinding, now time.Time) (*policy.Violation, *iamv1alpha1.AdmissionWitness) {
		t.Helper()
		if v := policy.Evaluate(c.Policy, ab); v != nil {
			return v, ab.Status.AdmissionWitness
		}
		g, err := policy.CheckAdmissionGuarantee(ctx, admin, c.Policy, seal, ab, now)
		if err != nil {
			t.Fatal(err)
		}
		return g.Violation, g.Witness
	}
	base := renderedConfig(t, rendered)
	// Выдача пользователю от принципала платформы, созданная позже политик.
	ab := &iamv1alpha1.AccessBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "upgraded", Namespace: tenantNS, Generation: 1,
			CreationTimestamp: metav1.NewTime(time.Now().Add(time.Minute)),
			Annotations:       map[string]string{iamv1alpha1.AnnotationCreatedBy: platform}},
		Spec: iamv1alpha1.AccessBindingSpec{
			Subjects: []iamv1alpha1.Subject{{User: &iamv1alpha1.PrincipalRef{ID: "usr-upgrade"}}},
			RoleRef:  iamv1alpha1.RoleRef{Name: "registry.pusher"},
			Target:   iamv1alpha1.Target{Resources: []iamv1alpha1.ResourceRef{{Type: "registry.registries", ID: "abc123"}}},
		},
	}
	before := upgrade(t, admin, rendered)
	now := time.Now().Add(2 * time.Minute)
	v, w := verdict(base, ab, now)
	if v != nil {
		t.Fatalf("precondition: the binding is refused before the upgrade: %v", v)
	}
	ab.Status.AdmissionWitness = w

	widened := renderWith(t, "registry.puller", "registry.pusher", "registry.public.read", "registry.extra")
	after := upgrade(t, admin, widened)
	bindingsPolicy := ""
	for k := range after {
		if strings.HasPrefix(k, "ValidatingAdmissionPolicy/") && strings.HasSuffix(k, "-bindings") {
			bindingsPolicy = k
		}
	}
	if bindingsPolicy == "" || after[bindingsPolicy] <= before[bindingsPolicy] {
		t.Fatalf("precondition: the upgrade did not change %s in place (generation %d, was %d)", bindingsPolicy, after[bindingsPolicy], before[bindingsPolicy])
	}
	cfg := renderedConfig(t, widened)
	for _, at := range []time.Duration{time.Second, cfg.Policy.AdmissionEnforcementDelay.Duration + 2*time.Second} {
		v, w := verdict(cfg, ab, now.Add(at))
		if v != nil {
			t.Fatalf("%s after the widening upgrade the permissible binding is refused: %v", at, v)
		}
		ab.Status.AdmissionWitness = w
	}

	narrowed := renderWith(t, "registry.puller", "registry.public.read")
	upgrade(t, admin, narrowed)
	if v, _ := verdict(renderedConfig(t, narrowed), ab, now.Add(time.Minute)); v == nil || !strings.Contains(v.Message, "registry.pusher") {
		t.Fatalf("twin: the upgrade narrowing allowedRoles under the binding kept it: %v", v)
	}
}
