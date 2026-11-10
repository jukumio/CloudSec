#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-pbl-security}"
SA="pbl-crypto-platform-app"
BURSTS="${BURSTS:-6}"
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

echo "[Crypto-platform:abnormal_3] Rapid enumeration with the same ServiceAccount."
for i in $(seq 1 "${BURSTS}"); do
  echo "burst=${i}/${BURSTS} resource=pods"
  "${K[@]}" get pods >/dev/null
  echo "burst=${i}/${BURSTS} resource=secrets"
  "${K[@]}" get secrets >/dev/null 2>&1 || true
  echo "burst=${i}/${BURSTS} resource=configmaps"
  "${K[@]}" get configmaps >/dev/null
done
echo "Burst completed. Compare resource, verb, target, status, and frequency for system:serviceaccount:${NS}:${SA}."
