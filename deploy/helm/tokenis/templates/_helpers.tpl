{{- define "tokenis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tokenis.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "tokenis.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "tokenis.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "tokenis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tokenis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tokenis.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tokenis.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The full tokenis.toml: the user's config plus the sections the chart owns. */}}
{{- define "tokenis.toml" -}}
{{- $cfg := .Values.config -}}
{{- range $section := list "[server]" "[state]" "[ops]" "[ops." -}}
{{- if regexMatch (printf "(?m)^\\s*\\%s" $section) $cfg -}}
{{- fail (printf "config must not contain %s: the chart renders it from values (server.*, stateDatabase, admin, metrics)" $section) -}}
{{- end -}}
{{- end -}}
{{- $host := urlParse .Values.server.publicUrl -}}
{{ $cfg }}

# -- rendered by the Helm chart --------------------------------------------
[server]
transport = "http"
host = "0.0.0.0"
port = 8000
public_url = {{ .Values.server.publicUrl | quote }}
allowed_hosts = [{{ range $i, $h := .Values.server.allowedHosts }}{{ if $i }}, {{ end }}{{ $h | quote }}{{ end }}]
stateless = true
log_format = {{ .Values.server.logFormat | quote }}
max_concurrency = {{ .Values.server.maxConcurrency }}
{{- with .Values.server.taintHeader }}
taint_header = {{ . | quote }}
{{- end }}

[state]
backend = "postgres"
url_env = "TOKENIS_STATE_URL"

[ops]
{{- if and .Values.admin.enabled .Values.admin.existingSecret }}
admin_token_env = "TOKENIS_ADMIN_TOKEN"
{{- end }}
{{- if .Values.metrics.tokenSecret }}
metrics_token_env = "TOKENIS_METRICS_TOKEN"
{{- end }}
{{- with .Values.admin.oidc }}
{{- if and $.Values.admin.enabled .enabled }}
{{- if .sessionSecret.existingSecret }}
session_secret_env = "TOKENIS_CONSOLE_SESSION_SECRET"
{{- end }}

[ops.oidc]
issuer = {{ required "admin.oidc.issuer is required" .issuer | quote }}
client_id = {{ required "admin.oidc.clientId is required" .clientId | quote }}
{{- if .clientSecret.existingSecret }}
client_secret_env = "TOKENIS_OIDC_CLIENT_SECRET"
{{- end }}
identity_claim = {{ .identityClaim | quote }}
{{- with .rolesClaim }}
roles_claim = {{ . | quote }}
{{- end }}
admins = {{ .admins | toJson }}
auditors = {{ .auditors | toJson }}
viewers = {{ .viewers | toJson }}
users = {{ .users | default list | toJson }}
session_hours = {{ .sessionHours }}
{{- with .displayName }}
display_name = {{ . | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- with .Values.ask }}
{{- if .enabled }}
{{- if regexMatch "(?m)^\\s*\\[ask" $cfg }}
{{- fail "config must not contain [ask]: the chart renders it from values (ask.*)" }}
{{- end }}

[ask]
provider = {{ .provider | quote }}
model = {{ required "ask.model is required" .model | quote }}
{{- with .baseUrl }}
base_url = {{ . | quote }}
{{- end }}
{{- if .apiKey.existingSecret }}
api_key_env = "TOKENIS_ASK_API_KEY"
{{- end }}
tool_protocol = {{ .toolProtocol | quote }}
{{- with .reasoningEffort }}
reasoning_effort = {{ . | quote }}
{{- end }}
questions_per_hour = {{ .questionsPerHour }}
timeout_seconds = {{ .timeoutSeconds }}
language = {{ .language | quote }}
{{- with .displayName }}
display_name = {{ . | quote }}
{{- end }}
suggestions = {{ .suggestions | default list | toJson }}
{{- with .labels }}

[ask.labels]
{{- range $column, $label := . }}
{{ $column }} = {{ $label | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}
