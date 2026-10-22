{{- define "kio.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kio.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "kio.name" . -}}
{{- end -}}
{{- end -}}

{{- define "kio.labels" -}}
app.kubernetes.io/name: {{ include "kio.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "kio.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kio.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kio.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* Пользователь k8s оператора: субъект FEDERATED-входа и писатель /status. */}}
{{- define "kio.operatorUser" -}}
{{- printf "system:serviceaccount:%s:%s" .Release.Namespace .Values.serviceAccount.name -}}
{{- end -}}

{{- define "kio.vaultTokenPath" -}}/var/run/secrets/vault/token{{- end -}}
{{- define "kio.kanameCAPath" -}}/etc/kaname-iam-operator/kaname-ca/{{ .Values.kanameCA.key }}{{- end -}}
{{- define "kio.vaultCAPath" -}}/etc/kaname-iam-operator/vault-ca/{{ .Values.vaultCA.key }}{{- end -}}

{{/* Политики допуска, держащие подлинность created-by и субъектов user/group
(каждая — с привязкой того же имени). Без допуска перечень пуст, и оператор
субъектов user/group не принимает. */}}
{{- define "kio.admissionGuard" -}}
{{- if .Values.admission.enabled -}}
{{- toYaml (list (printf "%s-writers" (include "kio.fullname" .)) (printf "%s-bindings" (include "kio.fullname" .))) -}}
{{- else -}}
[]
{{- end -}}
{{- end -}}

{{/* config.yaml оператора: обязательные поля — required, отказ рендера. */}}
{{- define "kio.config" -}}
{{- $c := .Values.config -}}
{{- if not $c.policy.allowedRoles -}}
{{- fail "config.policy.allowedRoles must name at least one role" -}}
{{- end -}}
{{- $kaname := dict "apiURL" (required "config.kaname.apiURL is required" $c.kaname.apiURL) "audience" (required "config.kaname.audience is required" $c.kaname.audience) "callTimeout" $c.kaname.callTimeout "assertionTTL" $c.kaname.assertionTTL "createGrace" $c.kaname.createGrace "qps" $c.kaname.qps "burst" $c.kaname.burst -}}
{{- if $c.kaname.tokenURL }}{{- $_ := set $kaname "tokenURL" $c.kaname.tokenURL -}}{{- end -}}
{{- if $c.kaname.requestedAudience }}{{- $_ := set $kaname "requestedAudience" $c.kaname.requestedAudience -}}{{- end -}}
{{- if .Values.kanameCA.secretName }}{{- $_ := set $kaname "caFile" (include "kio.kanameCAPath" .) -}}{{- end -}}
{{- $vault := dict "address" (required "config.vault.address is required" $c.vault.address) "authMount" $c.vault.authMount "role" $c.vault.role "callTimeout" $c.vault.callTimeout "tokenPath" (include "kio.vaultTokenPath" .) -}}
{{- if .Values.vaultCA.secretName }}{{- $_ := set $vault "caFile" (include "kio.vaultCAPath" .) -}}{{- end -}}
{{- $policy := deepCopy $c.policy -}}
{{- $_ := set $policy "admissionGuard" (include "kio.admissionGuard" . | fromYamlArray) -}}
{{- $out := dict "clusterName" (required "config.clusterName is required" $c.clusterName) "kaname" $kaname "vault" $vault "policy" $policy "delivery" $c.delivery "keys" $c.keys -}}
{{- toYaml $out -}}
{{- end -}}
