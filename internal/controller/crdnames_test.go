// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/restmapper"

	iamv1alpha1 "github.com/PRO-Robotech/kaname-iam-operator/api/v1alpha1"
)

// crdName — имена одного ресурса так, как их видит kube-apiserver:
// вид, множественное и единственное число, короткие имена. Все они —
// слова, которыми kubectl и RBAC адресуют ресурс без группы.
type crdName struct {
	group    string
	kind     string
	plural   string
	singular string
	short    []string
}

// words — все слова ресурса, по которым его адресуют без группы. Пустое
// единственное число kube-apiserver выводит из вида строчными.
func (n crdName) words() []string {
	singular := n.singular
	if singular == "" {
		singular = strings.ToLower(n.kind)
	}
	w := []string{strings.ToLower(n.kind), n.plural, singular}
	return append(w, n.short...)
}

// collisions — слова ресурса own, которыми уже адресуется ресурс другой
// группы из others: каждое такое слово делает адресацию без группы
// неоднозначной. Ресурсы своей группы между собой не судятся.
func collisions(own crdName, others []crdName) []string {
	var found []string
	mine := own.words()
	for _, o := range others {
		if o.group == own.group {
			continue
		}
		for _, w := range o.words() {
			if slices.Contains(mine, w) {
				found = append(found, w+" ↔ "+o.group+"/"+o.plural)
			}
		}
	}
	sort.Strings(found)
	return slices.Compact(found)
}

// serverNames — перепись ресурсов kube-apiserver по предпочтительным
// версиям; подресурсы («serviceaccounts/token») — не ресурсы и не судятся.
func serverNames(t *testing.T, dc discovery.DiscoveryInterfaceWithContext) []crdName {
	t.Helper()
	lists, err := discovery.ServerPreferredResourcesWithContext(t.Context(), dc)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	var out []crdName
	for _, l := range lists {
		gv, err := schema.ParseGroupVersion(l.GroupVersion)
		if err != nil {
			t.Fatalf("group version %q: %v", l.GroupVersion, err)
		}
		for _, r := range l.APIResources {
			if strings.Contains(r.Name, "/") {
				continue
			}
			out = append(out, crdName{group: gv.Group, kind: r.Kind, plural: r.Name, singular: r.SingularName, short: r.ShortNames})
		}
	}
	return out
}

// TestCRDKindsCarryTheIAMPrefixAndCollideWithNothing — виды группы
// iam.kaname.in-cloud.io названы с префиксом IAM, и ни одно их слово (вид,
// множественное, единственное, короткое имя) не совпадает со словом
// ресурса другой группы, в том числе core ServiceAccount: kubectl get
// iamsa и iamab разрешаются однозначно без группы, а serviceaccount — к
// core v1. Перепись — по kube-apiserver envtest с установленными CRD
// config/crd/bases, а не по выписанному перечню.
func TestCRDKindsCarryTheIAMPrefixAndCollideWithNothing(t *testing.T) {
	dc, err := discovery.NewDiscoveryClientForConfig(restCfg)
	if err != nil {
		t.Fatalf("discovery client: %v", err)
	}
	all := serverNames(t, dc)

	group := iamv1alpha1.GroupVersion.Group
	var own []crdName
	coreSA := false
	for _, n := range all {
		if n.group == group {
			own = append(own, n)
		}
		if n.group == "" && n.plural == "serviceaccounts" {
			coreSA = true
		}
	}
	// Предпосылка: перепись прочитала и свои ресурсы, и core ServiceAccount —
	// иначе «совпадений нет» значило бы «смотреть было не на что».
	t.Logf("перепись: ресурсов %d, групп iam.kaname.in-cloud.io — %d, core serviceaccounts — %v", len(all), len(own), coreSA)
	if len(own) != 2 || !coreSA {
		t.Fatalf("предпосылка не выполнена: ресурсов группы %s %d (ожидалось 2), core serviceaccounts найден: %v", group, len(own), coreSA)
	}

	want := map[string]crdName{
		"iamserviceaccounts": {group: group, kind: "IAMServiceAccount", plural: "iamserviceaccounts", singular: "iamserviceaccount", short: []string{"iamsa"}},
		"iamaccessbindings":  {group: group, kind: "IAMAccessBinding", plural: "iamaccessbindings", singular: "iamaccessbinding", short: []string{"iamab"}},
	}
	for _, n := range own {
		w, ok := want[n.plural]
		if !ok {
			t.Errorf("ресурс %s/%s (вид %s, короткие %v) не из ожидаемых: %v", group, n.plural, n.kind, n.short, keys(want))
			continue
		}
		if n.kind != w.kind || n.singular != w.singular || !slices.Equal(n.short, w.short) {
			t.Errorf("ресурс %s/%s: вид %q единственное %q короткие %v, ожидалось вид %q единственное %q короткие %v",
				group, n.plural, n.kind, n.singular, n.short, w.kind, w.singular, w.short)
		}
		if c := collisions(n, all); len(c) > 0 {
			t.Errorf("ресурс %s/%s (вид %s) совпадает словами с ресурсами других групп: %v", group, n.plural, n.kind, c)
		}
	}

	// Разрешение без группы — так, как его делает kubectl: короткое имя
	// раскрывается по discovery, затем ищется ресурс во всех группах.
	mapper := restmapper.NewShortcutExpanderWithContext(
		restmapper.NewDeferredDiscoveryRESTMapperWithContext(memory.NewMemCacheClientWithContext(dc)), dc, nil)
	for word, wantGroup := range map[string]string{
		"iamsa": group, "iamab": group,
		"iamserviceaccount": group, "iamaccessbinding": group,
		"serviceaccount": "", "serviceaccounts": "",
	} {
		got, err := mapper.ResourcesForWithContext(t.Context(), schema.GroupVersionResource{Resource: word})
		if err != nil {
			t.Errorf("kubectl get %s: не разрешается: %v", word, err)
			continue
		}
		groups := map[string]bool{}
		for _, g := range got {
			groups[g.Group] = true
		}
		if len(groups) != 1 || !groups[wantGroup] {
			t.Errorf("kubectl get %s: разрешается в группы %v, ожидалась ровно одна %q", word, keys(groups), wantGroup)
		}
	}
}

// TestCRDNameCollisionJudgeFiresAndStaysSilent — судья совпадений
// краснеет на настоящем дефекте (вид, совпавший с core ServiceAccount
// множественным и единственным числом) и молчит на законном близнеце
// (тот же ресурс с префиксом IAM) и на соседе своей группы.
func TestCRDNameCollisionJudgeFiresAndStaysSilent(t *testing.T) {
	core := crdName{group: "", kind: "ServiceAccount", plural: "serviceaccounts", singular: "serviceaccount", short: []string{"sa"}}
	sibling := crdName{group: "iam.kaname.in-cloud.io", kind: "IAMAccessBinding", plural: "iamaccessbindings", singular: "iamaccessbinding", short: []string{"iamab"}}

	defect := crdName{group: "iam.kaname.in-cloud.io", kind: "ServiceAccount", plural: "serviceaccounts", singular: "serviceaccount", short: []string{"ksa"}}
	if got, want := collisions(defect, []crdName{core, sibling}), []string{"serviceaccount ↔ /serviceaccounts", "serviceaccounts ↔ /serviceaccounts"}; !slices.Equal(got, want) {
		t.Errorf("дефект: совпадения %v, ожидались %v", got, want)
	}
	shortOnly := crdName{group: "iam.kaname.in-cloud.io", kind: "IAMServiceAccount", plural: "iamserviceaccounts", singular: "iamserviceaccount", short: []string{"sa"}}
	if got := collisions(shortOnly, []crdName{core}); !slices.Equal(got, []string{"sa ↔ /serviceaccounts"}) {
		t.Errorf("короткое имя core: совпадения %v, ожидалось одно sa", got)
	}
	twin := crdName{group: "iam.kaname.in-cloud.io", kind: "IAMServiceAccount", plural: "iamserviceaccounts", singular: "iamserviceaccount", short: []string{"iamsa"}}
	if got := collisions(twin, []crdName{core, sibling}); len(got) != 0 {
		t.Errorf("законный близнец: совпадения %v, ожидалось ни одного", got)
	}
	if got := collisions(twin, []crdName{{group: twin.group, kind: twin.kind, plural: twin.plural}}); len(got) != 0 {
		t.Errorf("ресурс своей группы судится: %v", got)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
