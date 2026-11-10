#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-pbl-security}"
FRONTEND="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

echo "[Hildegard:abnormal_1] frontend -> db, a service outside the normal path."
if kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -qO- -T 3 http://db; then
  echo "Unexpected success: NetworkPolicy did not block frontend -> db." >&2
  exit 1
fi
echo "Blocked as expected; inspect the new destination in Hubble."
