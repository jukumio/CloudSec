#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"

echo "[OpenMetadata:abnormal_1] Reconnaissance of environment and credential locations."
kubectl -n "${NS}" exec "${POD}" -- sh -c '
  sleep 1
  env >/tmp/openmetadata-env-snapshot
  cat /proc/1/environ >/dev/null
  for path in /root/.aws/credentials /root/.ssh/id_rsa /root/.kube/config /etc/shadow; do
    if [ -e "$path" ]; then
      ls -l "$path" >/dev/null
    fi
  done
  rm -f /tmp/openmetadata-env-snapshot
  sleep 1
'

echo "Falco: kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --prefix --since=10m | grep PBL_EVENT"
