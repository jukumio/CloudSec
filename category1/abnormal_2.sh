#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-pbl-security}"
POD="$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"
TOKEN="/var/run/secrets/kubernetes.io/serviceaccount/token"

echo "[OpenMetadata:abnormal_2] Reading the mounted ServiceAccount token."
kubectl -n "${NS}" exec "${POD}" -- sh -c "sleep 1; cat '${TOKEN}' >/dev/null; sleep 1"

echo "Falco: kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --prefix --since=10m | grep PBL_EVENT"
