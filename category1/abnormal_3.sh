#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

echo "[OpenMetadata:abnormal_3] Executing a safe payload/reverse-shell simulation."
kubectl -n "${NS}" exec -c frontend "${POD}" -- sh -c '
  cat >/tmp/openmetadata-payload.sh <<EOF
#!/bin/sh
id
uname -a
echo reverse-shell-simulation-no-network
EOF
  chmod +x /tmp/openmetadata-payload.sh
  /bin/sh /tmp/openmetadata-payload.sh
  sleep 1
  rm -f /tmp/openmetadata-payload.sh
'

echo "No malware or outbound reverse-shell connection was created."
echo "Falco: kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --prefix --since=10m | grep PBL_EVENT"
