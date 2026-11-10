#!/usr/bin/env bash
set -euo pipefail

# WSL non-login shells do not always inherit snap's command directory.
export PATH="${PATH}:/snap/bin"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_CONTEXT="${EXPECTED_CONTEXT:-kind-pbl-security}"
CURRENT_CONTEXT="$(kubectl config current-context)"
if [[ "${CURRENT_CONTEXT}" != "${EXPECTED_CONTEXT}" ]]; then
  printf 'Expected lab context %s, found %s. No changes made.\n' \
    "${EXPECTED_CONTEXT}" "${CURRENT_CONTEXT}" >&2
  exit 1
fi

RUN_DIR="${ROOT_DIR}/results/category1/deployment-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "${RUN_DIR}"
helm list --namespace falco --filter '^falco$' --output json >"${RUN_DIR}/release-before.json"
read -r CHART_VERSION PREVIOUS_REVISION < <(
  python3 -c '
import json, sys
releases = json.load(open(sys.argv[1], encoding="utf-8"))
if len(releases) != 1 or releases[0]["status"] != "deployed":
    sys.exit("Expected exactly one deployed falco release")
release = releases[0]
chart = release["chart"]
if not chart.startswith("falco-"):
    sys.exit("Unexpected Helm chart: " + chart)
print(chart[len("falco-"):], release["revision"])
' "${RUN_DIR}/release-before.json"
)
if [[ -z "${CHART_VERSION:-}" || -z "${PREVIOUS_REVISION:-}" ]]; then
  printf 'Could not identify the installed chart and revision.\n' >&2
  exit 1
fi

helm get values falco --namespace falco --output yaml >"${RUN_DIR}/values-before.yaml"
helm history falco --namespace falco --output json >"${RUN_DIR}/history-before.json"
cp "${ROOT_DIR}/category1/falco-values-v2.yaml" "${RUN_DIR}/falco-values-v2.yaml"

# Render first, keep the installed chart version, and roll back on failed rollout.
# The supplemental rules use a separate customRules map key; baseline rules remain.
helm upgrade falco falcosecurity/falco --namespace falco \
  --version "${CHART_VERSION}" --reuse-values \
  --values "${ROOT_DIR}/category1/falco-values-v2.yaml" \
  --dry-run >"${RUN_DIR}/helm-dry-run.txt"
helm upgrade falco falcosecurity/falco --namespace falco \
  --version "${CHART_VERSION}" --reuse-values \
  --values "${ROOT_DIR}/category1/falco-values-v2.yaml" \
  --atomic --wait --timeout 10m | tee "${RUN_DIR}/helm-upgrade.txt"
kubectl rollout status daemonset/falco --namespace falco --timeout=10m
helm list --namespace falco --filter '^falco$' --output json >"${RUN_DIR}/release-after.json"
helm get values falco --namespace falco --output yaml >"${RUN_DIR}/values-after.yaml"

printf '\nV2 rules ready alongside the baseline. Deployment evidence: %s\n' "${RUN_DIR}"
printf 'To restore the previous Helm revision after evaluation:\n'
printf 'helm rollback falco %s --namespace falco --wait --timeout 10m\n' "${PREVIOUS_REVISION}"
