{{/* Helm standard labels */}}
{{- define "swoll-server.helm_std_labels" }}
chart: {{ .Chart.Name }}-{{ .Chart.Version }}
heritage: {{ .Release.Service }}
release: {{ .Release.Name }}
app: {{ template "toplevel.name" . }}
{{- end }}

{{- define "swoll-server.annotations" }}
prometheus.io/scrape: "true"
prometheus.io/port: "{{ .Values.listenPort }}"
{{- end }}

{{- define "swoll-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "toplevel.name" -}}
{{- default (.Template.BasePath | split "/" )._0 .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "swoll-server.fullname" -}}
{{- printf "%s-%s" .Chart.Name .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "toplevel.fullname" -}}
{{- $name := default (.Template.BasePath | split "/" )._0 .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "swoll-server.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "swoll-server.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{- define "daemonset.apiVersion" -}}
{{- if semverCompare "<1.9-0" .Capabilities.KubeVersion.GitVersion -}}
{{- print "extensions/v1beta1" -}}
{{- else -}}
{{- print "apps/v1" -}}
{{- end -}}
{{- end -}}

{{- define "swoll-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "swoll-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "swoll-server.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}


{{- define "swoll-server.labels" -}}
helm.sh/chart: {{ include "swoll-server.chart" . }}
{{ include "swoll-server.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
