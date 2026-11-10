#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-pbl-security}"
SA="pbl-crypto-platform-app"
ensure_lab_identity() {
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pbl-crypto-platform-app
  namespace: ${NS}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pbl-crypto-platform-reader
  namespace: ${NS}
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pbl-crypto-platform-reader
  namespace: ${NS}
subjects:
  - kind: ServiceAccount
    name: pbl-crypto-platform-app
    namespace: ${NS}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pbl-crypto-platform-reader
YAML
  TOKEN="$(kubectl -n "${NS}" create token "${SA}" --duration=10m)"
  SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
  K=(kubectl --kubeconfig=/dev/null --server="${SERVER}" --insecure-skip-tls-verify --token="${TOKEN}" -n "${NS}")
}

ensure_lab_identity

POD="$("${K[@]}" get pod -l app=backend -o jsonpath='{.items[0].metadata.name}')"
URI="${SERVER}/api/v1/namespaces/${NS}/pods/${POD}/exec?command=id&stdout=true&stderr=true"
RESPONSE="$(mktemp)"
trap 'rm -f "${RESPONSE}"' EXIT

echo "[Crypto-platform:abnormal_2] The same ServiceAccount attempts pods/exec on ${POD}."
STATUS="$(curl -k -sS -o "${RESPONSE}" -w '%{http_code}' -X POST   -H "Authorization: Bearer ${TOKEN}" "${URI}")"
cat "${RESPONSE}"
if [[ "${STATUS}" != "403" ]]; then
  echo "Expected HTTP 403, got ${STATUS}." >&2
  exit 1
fi
echo "Forbidden as expected. Audit identity: system:serviceaccount:${NS}:${SA}"
