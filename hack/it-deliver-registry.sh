#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: Apache-2.0
#
# it-deliver-registry.sh — доставка манифеста модуля registry стенду kaname
# интеграционного прогона.
#
# Зачем. Проба выдачи на всю область (test/integration/allinscope_test.go)
# спрашивает у настоящего kaname, доходит ли registry.pusher на аккаунт до
# каждого репозитория каждого реестра аккаунта. Для этого стенду нужны роль
# registry.pusher и личность модуля kacho-registry с правом писать кортежи
# (ими прогон регистрирует реестры): обе заводит только ДОСТАВЛЕННЫЙ манифест
# модуля (manifests.dir), а чарт kaname закреплённой ревизии монтирования
# доставки не несёт. Поэтому скрипт кладёт манифест ConfigMap'ом стенда,
# монтирует его в выкат службы и включает доставку её же ручками
# (KANAME_MANIFESTS__DIR, KANAME_MANIFESTS__REQUIRED), после чего ждёт выката.
#
# Манифест собирается из двух половин. Раздел resources kaname на старте
# сверяет с каноном своего образа побайтово — он берётся у ЗАКРЕПЛЁННОЙ
# ревизии kaname (её фикстура доставки registry), а не переписывается здесь.
# Роли и посев — test/integration/testdata/registry-roles-and-seed.yaml.
#
# Окружение (обязательное):
#   KIO_STAND_KUBECONFIG, KIO_STAND_CONTEXT, KIO_STAND_NAMESPACE,
#   KIO_STAND_RELEASE — как у hack/it-stand.sh;
#   KANAME_SRC — клон kaname на закреплённой ревизии.
#
# Исходы: 0 — служба поднялась с доставленным манифестом; 1 — находка (служба
# отвергла манифест либо не поднялась с ним); 75 — условие не создано.
set -uo pipefail

RC_UNMET=75
unmet() { printf 'it-deliver-registry: УСЛОВИЕ НЕ СОЗДАНО: %s\n' "$*" >&2; exit "$RC_UNMET"; }
fail() { printf 'it-deliver-registry: НАХОДКА: %s\n' "$*" >&2; exit 1; }

for v in KIO_STAND_KUBECONFIG KIO_STAND_CONTEXT KIO_STAND_NAMESPACE KIO_STAND_RELEASE KANAME_SRC; do
	[ -n "${!v:-}" ] || unmet "переменная $v не задана"
done
command -v kubectl >/dev/null || unmet "нет kubectl"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$KANAME_SRC/internal/manifest/testdata/registry.public-read-fixture.yaml"
TAIL="$HERE/test/integration/testdata/registry-roles-and-seed.yaml"
[ -s "$FIXTURE" ] || unmet "нет фикстуры доставки registry у kaname: $FIXTURE"
[ -s "$TAIL" ] || unmet "нет ролей и посева: $TAIL"

K=(kubectl --kubeconfig "$KIO_STAND_KUBECONFIG" --context "$KIO_STAND_CONTEXT" -n "$KIO_STAND_NAMESPACE")
REL="$KIO_STAND_RELEASE"
CM="$REL-kio-it-manifests"
MOUNT=/etc/kaname-delivered

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kio-it-deliver.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# Раздел resources — ровно от строки `resources:` до строки `roles:`; оба
# заголовка в фикстуре по одному, иначе вырезка неоднозначна.
[ "$(grep -c '^resources:$' "$FIXTURE")" = 1 ] && [ "$(grep -c '^roles:$' "$FIXTURE")" = 1 ] \
	|| unmet "фикстура $FIXTURE не той формы: заголовки resources/roles не по одному"
{
	printf '# Доставка интеграционного прогона kaname-iam-operator.\napiVersion: iam/v1\nmodule: registry\n\n'
	awk '/^resources:$/{f=1} /^roles:$/{f=0} f' "$FIXTURE"
	cat "$TAIL"
} > "$WORK/registry.yaml"
n=$(grep -c '^  - name: \(registries\|repositories\)$' "$WORK/registry.yaml")
[ "$n" = 2 ] || unmet "вырезка resources дала $n ресурсов registry, ожидалось 2"

"${K[@]}" create configmap "$CM" --from-file=registry.yaml="$WORK/registry.yaml" --dry-run=client -o yaml \
	| "${K[@]}" apply -f - >/dev/null || unmet "ConfigMap $CM не записан"

container="$("${K[@]}" get deploy "$REL" -o 'jsonpath={.spec.template.spec.containers[0].name}')" \
	|| unmet "выкат $REL не прочитан"
[ -n "$container" ] || unmet "у выката $REL нет контейнера"
patch=$(cat <<EOF
{"spec":{"template":{"spec":{
  "volumes":[{"name":"kio-it-manifests","configMap":{"name":"$CM"}}],
  "containers":[{"name":"$container",
    "volumeMounts":[{"name":"kio-it-manifests","mountPath":"$MOUNT","readOnly":true}],
    "env":[{"name":"KANAME_MANIFESTS__DIR","value":"$MOUNT"},{"name":"KANAME_MANIFESTS__REQUIRED","value":"true"}]}]}}}}
EOF
)
"${K[@]}" patch deploy "$REL" --type strategic -p "$patch" >/dev/null || unmet "выкат $REL не правится"
if ! "${K[@]}" rollout status "deploy/$REL" --timeout=300s; then
	"${K[@]}" logs "deploy/$REL" -c "$container" --tail=80 >&2 || true
	fail "служба не поднялась с доставленным манифестом registry"
fi
# Перепись доставки — в журнале пода НОВОГО выката: самый поздний под по
# выборке выката (прежний может ещё завершаться).
sel="$("${K[@]}" get deploy "$REL" -o 'go-template={{range $k, $v := .spec.selector.matchLabels}}{{$k}}={{$v}},{{end}}')"
pod="$("${K[@]}" get pods -l "${sel%,}" --sort-by=.metadata.creationTimestamp -o 'jsonpath={.items[-1:].metadata.name}')"
[ -n "$pod" ] || unmet "под выката $REL не найден (выборка ${sel%,})"
"${K[@]}" logs "$pod" -c "$container" > "$WORK/pod.log" 2>&1 || unmet "журнал пода $pod не прочитан"
census="$(grep -m1 'manifests_read' "$WORK/pod.log" || true)"
if [ -z "$census" ]; then
	tail -40 "$WORK/pod.log" >&2
	fail "под $pod не напечатал перепись доставки манифестов (строк журнала $(wc -l < "$WORK/pod.log"))"
fi
printf 'it-deliver-registry: под %s: %s\n' "$pod" "$census"
printf '%s\n' "$census" | grep -Eq 'manifests_read"?[:=]1([^0-9]|$)' \
	|| fail "служба не отчиталась о прочтении ровно одного доставленного манифеста"
