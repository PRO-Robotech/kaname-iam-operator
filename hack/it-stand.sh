#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: Apache-2.0
#
# it-stand.sh — интеграционная проба оператора против стенда kaname.
#
# Скрипт берёт из кластера стенда (контекст — ЯВНЫЙ, текущий не трогается)
# лист бутстрап-контура и УЦ службы, поднимает переадресацию портов к
# REST-фронту, токен-эндпоинту и внутреннему gRPC и гонит
# `go test -tags=integration ./test/integration/`. Адресов и учётных данных в
# дереве нет: всё приходит из окружения вызова и снимается ловушкой на выходе,
# в том числе на падении.
#
# Окружение (обязательное):
#   KIO_STAND_KUBECONFIG     кубконфиг кластера стенда
#   KIO_STAND_CONTEXT        контекст в нём (явный)
#   KIO_STAND_NAMESPACE      namespace стенда
#   KIO_STAND_RELEASE        имя релиза kaname на стенде (Service <релиз>,
#                            <релиз>-internal, Secret <релиз>-server-tls,
#                            ConfigMap <релиз>-config)
#   KIO_STAND_BOOTSTRAP_TLS_SECRET  Secret листа круга чеканки бутстрапа
# Окружение (необязательное):
#   KIO_STAND_ROLE           роль, чьи правила покрывают тип цели (vpc.network.view)
#   KIO_STAND_TARGET_TYPE    тип цели выдачи (vpc.network)
#
# Исходы: код `go test`; 75 — условие не создано (стенд недостижим, нет
# секрета, переадресация не поднялась): вердикта о дереве нет.
set -uo pipefail

RC_UNMET=75
unmet() { printf 'it-stand: УСЛОВИЕ НЕ СОЗДАНО: %s\n' "$*" >&2; exit "$RC_UNMET"; }

for v in KIO_STAND_KUBECONFIG KIO_STAND_CONTEXT KIO_STAND_NAMESPACE KIO_STAND_RELEASE KIO_STAND_BOOTSTRAP_TLS_SECRET; do
	[ -n "${!v:-}" ] || unmet "переменная $v не задана"
done
command -v kubectl >/dev/null || unmet "нет kubectl"
command -v python3 >/dev/null || unmet "нет python3"

K=(kubectl --kubeconfig "$KIO_STAND_KUBECONFIG" --context "$KIO_STAND_CONTEXT" -n "$KIO_STAND_NAMESPACE")
REL="$KIO_STAND_RELEASE"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kio-it-stand.XXXXXX")"
chmod 700 "$WORK"
PIDS=()
cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	rm -rf "$WORK"
}
trap cleanup EXIT

secret_key() { # secret key file
	"${K[@]}" get secret "$1" -o "jsonpath={.data.${2//./\\.}}" | base64 -d > "$3" || unmet "секрет $1/$2 не прочитан"
	[ -s "$3" ] || unmet "секрет $1/$2 пуст"
	chmod 600 "$3"
}
secret_key "$KIO_STAND_BOOTSTRAP_TLS_SECRET" tls.crt "$WORK/boot-tls.crt"
secret_key "$KIO_STAND_BOOTSTRAP_TLS_SECRET" tls.key "$WORK/boot-tls.key"
secret_key "$REL-server-tls" ca.crt "$WORK/server-ca.crt"

# Адресаты — из конфигурации службы, а не литералом: издатель (aud
# утверждения) и адресат REST-фронта (audience обмена).
"${K[@]}" get configmap "$REL-config" -o 'jsonpath={.data.config\.yaml}' > "$WORK/config.yaml" || unmet "ConfigMap $REL-config не прочитан"
read -r ISSUER AUDIENCE < <(python3 - "$WORK/config.yaml" <<'PY'
import sys, yaml
c = yaml.safe_load(open(sys.argv[1])) or {}
a = c.get("authn", {})
print(a.get("token-signing", {}).get("issuer", ""), a.get("audience", "") or a.get("presented-credential", {}).get("audience", ""))
PY
)
[ -n "${ISSUER:-}" ] && [ -n "${AUDIENCE:-}" ] || unmet "в конфигурации службы нет издателя или адресата"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
REST=$(free_port); TOKEN=$(free_port); INTERNAL=$(free_port)
"${K[@]}" port-forward "svc/$REL" "$REST:9098" "$TOKEN:9096" > "$WORK/pf1.log" 2>&1 &
PIDS+=($!)
"${K[@]}" port-forward "svc/$REL-internal" "$INTERNAL:9091" > "$WORK/pf2.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do
	if grep -q "Forwarding from 127.0.0.1:$TOKEN" "$WORK/pf1.log" && grep -q "Forwarding from 127.0.0.1:$INTERNAL" "$WORK/pf2.log"; then
		break
	fi
	sleep 1
done
grep -q "Forwarding from 127.0.0.1:$INTERNAL" "$WORK/pf2.log" || unmet "переадресация портов не поднялась"

export KIO_IT_KANAME_REST_URL="https://127.0.0.1:$REST"
export KIO_IT_KANAME_TOKEN_URL="https://127.0.0.1:$TOKEN/iam/v1/token"
export KIO_IT_KANAME_INTERNAL_ADDR="127.0.0.1:$INTERNAL"
export KIO_IT_KANAME_TLS_DIR="$WORK"
export KIO_IT_KANAME_REST_SERVER_NAME="$REL.$KIO_STAND_NAMESPACE.svc"
export KIO_IT_KANAME_INTERNAL_SERVER_NAME="$REL-internal.$KIO_STAND_NAMESPACE.svc"
export KIO_IT_ASSERTION_AUDIENCE="$ISSUER"
export KIO_IT_TOKEN_AUDIENCE="$AUDIENCE"
export KIO_IT_ROLE="${KIO_STAND_ROLE:-vpc.network.view}"
export KIO_IT_TARGET_TYPE="${KIO_STAND_TARGET_TYPE:-vpc.network}"

go test -tags=integration ./test/integration/ -count=1 -v -timeout 20m "$@"
