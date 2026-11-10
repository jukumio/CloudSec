#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-pbl-security}"
FRONTEND="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
TARGETS=(
  backend
  db
  "$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].status.podIP}')"
  "$(kubectl -n "${NS}" get pod -l app=db -o jsonpath='{.items[0].status.podIP}')"
)
while IFS= read -r node_ip; do
  [[ -n "${node_ip}" ]] && TARGETS+=("${node_ip}")
done < <(kubectl get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')
PORTS=(22 443 2379 10250 3306 6379)

echo "[Hildegard:abnormal_3] Multi-target, multi-port probing."
for target in "${TARGETS[@]}"; do
  for port in "${PORTS[@]}"; do
    echo "probe target=${target} port=${port}"
    kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- nc -z -w 1 "${target}" "${port}" >/dev/null 2>&1 || true
  done
done
echo "Probing completed; inspect destination and port fan-out in Hubble."
