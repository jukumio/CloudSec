#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

echo "[1/3] Routine shell and configuration reads."
kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  echo pbl-normal-admin >/tmp/openmetadata-normal-session
  cat /etc/hostname
  cat /www/index.html
  id
  uname -a
'

echo "[2/3] Create, update, read, and remove a temporary file."
kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  echo created >/tmp/openmetadata-normal.tmp
  echo updated >>/tmp/openmetadata-normal.tmp
  cat /tmp/openmetadata-normal.tmp
  rm -f /tmp/openmetadata-normal.tmp /tmp/openmetadata-normal-session
'

echo "[3/3] Run a normal curl health check from the frontend Pod."
kubectl -n "${NS}" exec -c curl-client "${POD}" -- sh -c '
  curl -fsS http://127.0.0.1/ >/tmp/openmetadata-health-response
  cat /tmp/openmetadata-health-response
  rm -f /tmp/openmetadata-health-response
'

echo
echo "Falco: kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --prefix --since=10m | grep PBL_EVENT"
