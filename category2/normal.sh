#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-pbl-security}"
ROUNDS="${ROUNDS:-3}"
FRONTEND="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
BACKEND="$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"

for i in $(seq 1 "${ROUNDS}"); do
  echo "[normal ${i}/${ROUNDS}] frontend -> backend"
  kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -qO- -T 5 http://backend

  echo "[normal ${i}/${ROUNDS}] backend -> db"
  kubectl -n "${NS}" exec "${BACKEND}" -- wget -qO- -T 5 http://db

  echo "[normal ${i}/${ROUNDS}] DNS and local health checks"
  kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- nslookup backend.pbl-security.svc.cluster.local >/dev/null
  kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -qO- -T 5 http://127.0.0.1/ >/dev/null

  if ! kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -qO- -T 1 http://backend >/dev/null; then
    kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -qO- -T 5 http://backend >/dev/null
  fi
done

echo "Hubble: hubble observe --namespace ${NS} --since 10m --output compact"
