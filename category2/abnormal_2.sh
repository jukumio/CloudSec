#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-pbl-security}"
FRONTEND="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
TARGETS=(
  frontend
  backend
  db
  kubernetes.default.svc
  "$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].status.podIP}')"
  "$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].status.podIP}')"
  "$(kubectl -n "${NS}" get pod -l app=db -o jsonpath='{.items[0].status.podIP}')"
)

echo "[Hildegard:abnormal_2] Rapid discovery across multiple Pods and Services."
for round in 1 2; do
  for target in "${TARGETS[@]}"; do
    echo "round=${round} target=${target}:80"
    kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- nc -z -w 1 "${target}" 80 >/dev/null 2>&1 || true
  done
done
echo "Discovery burst completed; compare destination count and frequency in Hubble."
