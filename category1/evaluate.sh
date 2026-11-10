#!/usr/bin/env bash
# Controlled, non-destructive Category 1 evaluation against an existing lab.
set -euo pipefail
export PATH="${PATH}:/snap/bin"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS="${NS:-pbl-security}"
FALCO_NS="${FALCO_NS:-falco}"
SETTLE_SECONDS="${SETTLE_SECONDS:-5}"
CASE_GAP_SECONDS="${CASE_GAP_SECONDS:-1}"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'HELP'
Usage: bash category1/evaluate.sh

Requires an existing, healthy PBL cluster and kubectl, helm, python3.
Runs 7 benign and 8 safe attack simulations in frontend/backend only.
No malware, external connections, token output, or Kubernetes changes.
Stores commands' outputs, case time windows, active Helm values, full Falco
logs, and a per-case analysis in results/category1/evaluation-<UTC>-<pid>/.

NS=pbl-security FALCO_NS=falco SETTLE_SECONDS=5 CASE_GAP_SECONDS=1
CASE_GAP_SECONDS separates test windows; SETTLE_SECONDS allows log flushing.
The analyzer evaluates only PBL custom Warning-or-higher alerts. Default
Falco alerts are retained and reported separately. A missing alert is an
observed non-match, not proof of an event-loss-free detector.
HELP
  exit 0
fi
if [[ $# -ne 0 ]]; then
  printf 'Unknown argument. Use --help.\n' >&2
  exit 2
fi
for cmd in kubectl helm python3 date; do
  command -v "${cmd}" >/dev/null || { printf 'Required command missing: %s\n' "${cmd}" >&2; exit 1; }
done
for duration in "${SETTLE_SECONDS}" "${CASE_GAP_SECONDS}"; do
  [[ "${duration}" =~ ^[0-9]+$ ]] || { printf 'Wait durations must be nonnegative integer seconds.\n' >&2; exit 2; }
done

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN_DIR="${ROOT_DIR}/results/category1/evaluation-${RUN_ID}"
mkdir -p "${ROOT_DIR}/results/category1"
mkdir "${RUN_DIR}"
mkdir "${RUN_DIR}/commands" "${RUN_DIR}/logs"
python3 - "${ROOT_DIR}" "${RUN_DIR}" <<'PY'
import datetime, hashlib, json, pathlib, sys
repo, run = map(pathlib.Path, sys.argv[1:])
snapshot = run / 'sources'
snapshot.mkdir()
files = []
for relative in ('category1/evaluate.sh', 'category1/analyze_results.py',
                 'category1/falco-values.yaml', 'category1/falco-values-v2.yaml'):
    source = repo / relative
    if not source.is_file():
        raise SystemExit(f'Missing evaluation source: {relative}')
    data = source.read_bytes()
    destination = snapshot / source.name
    destination.write_bytes(data)
    files.append(dict(repository_path=relative, snapshot_path='sources/' + source.name,
                      sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data)))
manifest = dict(schema_version=1, captured_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                captured_before_cases=True, captured_after_run=False, files=files,
                note='Repository source snapshot at run start; active-helm-values.json records deployed runtime values.')
(snapshot / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
MANIFEST="${RUN_DIR}/cases.jsonl"
: >"${MANIFEST}"
printf 'Results: %s\n' "${RUN_DIR}"

kubectl config current-context >"${RUN_DIR}/context.txt"
if [[ "$(cat "${RUN_DIR}/context.txt")" != "kind-pbl-security" ]]; then
  printf 'Refusing to run outside the expected kind-pbl-security lab context.\n' >&2
  exit 1
fi
kubectl -n "${FALCO_NS}" get pods -l app.kubernetes.io/name=falco -o json >"${RUN_DIR}/falco-before.json"
kubectl -n "${FALCO_NS}" get daemonset falco -o json >"${RUN_DIR}/daemonset-before.json"
kubectl -n "${NS}" get pods -o json >"${RUN_DIR}/workloads-before.json"
helm get values falco -n "${FALCO_NS}" -o json >"${RUN_DIR}/active-helm-values.json"

# Resolve the actual workload container IDs. They also let the analyzer
# attribute cross-agent events with missing Kubernetes metadata correctly.
python3 - "${RUN_DIR}" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
pods = json.loads((root / 'falco-before.json').read_text())['items']
ds = json.loads((root / 'daemonset-before.json').read_text())['status']
def healthy(pod):
    return (not pod['metadata'].get('deletionTimestamp')
            and any(c['type'] == 'Ready' and c['status'] == 'True'
                    for c in pod.get('status', {}).get('conditions', []))
            and any(c['name'] == 'falco' and 'running' in c.get('state', {})
                    for c in pod.get('status', {}).get('containerStatuses', [])))
desired = ds.get('desiredNumberScheduled', 0)
if desired < 1 or ds.get('numberReady', 0) != desired or len(pods) != desired or not all(map(healthy, pods)):
    raise SystemExit('Falco preflight failed: all desired Falco pods must be Ready.')
workloads = json.loads((root / 'workloads-before.json').read_text())['items']
targets = {}
for app, container in [('frontend', 'frontend'), ('frontend', 'curl-client'), ('backend', 'backend')]:
    candidates = [p for p in workloads if p['metadata'].get('labels', {}).get('app') == app
                  and not p['metadata'].get('deletionTimestamp')
                  and any(c['type'] == 'Ready' and c['status'] == 'True'
                          for c in p.get('status', {}).get('conditions', []))]
    if len(candidates) != 1:
        raise SystemExit(f'Expected exactly one Ready {app} pod, got {len(candidates)}.')
    p = candidates[0]
    statuses = [c for c in p['status'].get('containerStatuses', []) if c['name'] == container]
    if len(statuses) != 1 or not statuses[0].get('ready') or 'running' not in statuses[0].get('state', {}):
        raise SystemExit(f'Target container is not Ready: {container}')
    targets[container] = {'pod': p['metadata']['name'], 'container': container,
                          'pod_uid': p['metadata']['uid'], 'restart_count': statuses[0].get('restartCount', 0),
                          'container_id': statuses[0]['containerID'].split('://', 1)[-1]}
(root / 'targets.json').write_text(json.dumps(targets, indent=2) + '\n')
(root / 'falco-pods.txt').write_text(''.join(p['metadata']['name'] + '\n' for p in pods))
PY

target_field() {
  python3 - "${RUN_DIR}/targets.json" "$1" "$2" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))[sys.argv[2]][sys.argv[3]])
PY
}
FRONTEND_POD="$(target_field frontend pod)"
BACKEND_POD="$(target_field backend pod)"
SINCE_TIME="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
START_NS="$(date +%s%N)"
printf '%s\n' "${SINCE_TIME}" >"${RUN_DIR}/since-time.txt"

run_case() {
  local case_id="$1" truth="$2" target="$3" description="$4" expected_base="$5" expected_v2="$6"
  shift 6
  local started ended exit_code
  started="$(date +%s%N)"
  printf '[%s] %s\n' "${case_id}" "${description}"
  if "$@" >"${RUN_DIR}/commands/${case_id}.stdout" 2>"${RUN_DIR}/commands/${case_id}.stderr"; then
    exit_code=0
  else
    exit_code=$?
    printf '  Command failed (exit %s); excluded from detection metrics.\n' "${exit_code}" >&2
  fi
  ended="$(date +%s%N)"
  python3 - "${MANIFEST}" "${RUN_DIR}/targets.json" "${case_id}" "${truth}" "${target}" \
    "${description}" "${expected_base}" "${expected_v2}" "${started}" "${ended}" "${exit_code}" <<'PY'
import json, sys
manifest, targets_path, case_id, truth, target, description, base, v2, start, end, rc = sys.argv[1:]
row = dict(case_id=case_id, ground_truth=truth, description=description,
           expected_baseline=base, expected_v2=v2, start_ns=int(start), end_ns=int(end),
           exit_code=int(rc), **json.load(open(targets_path))[target])
with open(manifest, 'a') as output:
    output.write(json.dumps(row) + '\n')
PY
  sleep "${CASE_GAP_SECONDS}"
}

normal_config() {
  kubectl -n "${NS}" exec "${FRONTEND_POD}" -c frontend -- sh -c \
    'set -eu; cat /etc/hostname >/dev/null; cat /www/index.html >/dev/null'
}
normal_temp() {
  kubectl -n "${NS}" exec "${FRONTEND_POD}" -c frontend -- sh -c '
    set -eu
    path="$1"
    test ! -e "$path"
    trap '\''rm -f "$path"'\'' 0
    umask 077
    printf created >"$path"
    printf updated >>"$path"
    cat "$path" >/dev/null
  ' pbl-eval "/tmp/openmetadata-normal-${RUN_ID}.tmp"
}
normal_health() {
  kubectl -n "${NS}" exec "${FRONTEND_POD}" -c curl-client -- sh -c '
    set -eu
    path=/tmp/openmetadata-health-response
    test ! -e "$path"
    trap '\''rm -f "$path"'\'' 0
    umask 077
    curl -fsS http://127.0.0.1/ >"$path"
    test -s "$path"
  '
}
benign_env() {
  kubectl -n "${NS}" exec "${BACKEND_POD}" -c backend -- sh -c 'env >/dev/null'
}
benign_path_mention() {
  kubectl -n "${NS}" exec "${FRONTEND_POD}" -c frontend -- sh -c \
    'printf "%s\n" /tmp/openmetadata-payload.sh >/dev/null'
}
environment_discovery() {
  kubectl -n "${NS}" exec "${BACKEND_POD}" -c backend -- sh -c \
    'set -eu; env >/dev/null; cat /proc/1/environ >/dev/null'
}
sensitive_read() {
  local reader="$1" path="$2"
  kubectl -n "${NS}" exec "${BACKEND_POD}" -c backend -- sh -c '
    set -eu
    case "$1" in
      cat) cat "$2" >/dev/null ;;
      head) head -c 1 "$2" >/dev/null ;;
      *) exit 2 ;;
    esac
  ' pbl-eval "${reader}" "${path}"
}
temporary_script() {
  local path="$1" mode="$2"
  kubectl -n "${NS}" exec "${FRONTEND_POD}" -c frontend -- sh -c '
    set -eu
    path="$1"
    mode="$2"
    test ! -e "$path"
    trap '\''rm -f "$path"'\'' 0
    umask 077
    printf '\''#!/bin/sh\nprintf "pbl-local-simulation\\n" >/dev/null\n'\'' >"$path"
    case "$mode" in
      direct) /bin/sh "$path" ;;
      source) /bin/sh -c '\''. "$1"'\'' pbl-eval "$path" ;;
      *) exit 2 ;;
    esac
  ' pbl-eval "${path}" "${mode}"
}

run_case N01 benign frontend 'Routine configuration reads' TN TN normal_config
run_case N02 benign frontend 'Routine temporary text file operations' TN TN normal_temp
run_case N03 benign curl-client 'Loopback HTTP health check' TN TN normal_health
run_case N04 benign backend 'Authorized administrator inspects environment' FP TN benign_env
run_case N05 benign frontend 'Print a path string without executing a payload' FP TN benign_path_mention
run_case N06 benign frontend 'Authorized maintenance script in /tmp' TN FP \
  temporary_script "/tmp/pbl-eval-approved-${RUN_ID}.sh" direct
run_case N07 benign backend 'Authorized maintenance reads the mounted token (discard contents)' FP FP \
  sensitive_read cat /var/run/secrets/kubernetes.io/serviceaccount/token
run_case A01 attack backend 'Simulated environment and credential discovery' TP TP environment_discovery
run_case A02 attack backend 'Read ServiceAccount token with cat (discard contents)' TP TP \
  sensitive_read cat /var/run/secrets/kubernetes.io/serviceaccount/token
run_case A03 attack backend 'Read token with alternate reader head (discard contents)' FN TP \
  sensitive_read head /var/run/secrets/kubernetes.io/serviceaccount/token
run_case A04 attack backend 'Read process environment with alternate reader head' FN TP \
  sensitive_read head /proc/1/environ
run_case A05 attack frontend 'Execute original fixed-name safe payload marker' TP TP \
  temporary_script /tmp/openmetadata-payload.sh direct
run_case A06 attack frontend 'Execute a renamed safe payload marker in /tmp' FN TP \
  temporary_script "/tmp/pbl-eval-renamed-${RUN_ID}.sh" direct
run_case A07 attack frontend 'Source a renamed script using shell builtins only' FN FN \
  temporary_script "/tmp/pbl-eval-sourced-${RUN_ID}.sh" source
run_case A08 attack backend 'Simulated attacker inspects only environment variables' TP FN benign_env

END_NS="$(date +%s%N)"
sleep "${SETTLE_SECONDS}"
capture_complete=true
: >"${RUN_DIR}/log-collection.jsonl"
while IFS= read -r falco_pod; do
  capture_rc=0
  kubectl -n "${FALCO_NS}" logs "${falco_pod}" -c falco \
    --since-time="${SINCE_TIME}" --tail=-1 --timestamps=false \
    >"${RUN_DIR}/logs/${falco_pod}.log" 2>"${RUN_DIR}/logs/${falco_pod}.stderr" || capture_rc=$?
  if [[ ${capture_rc} -ne 0 ]]; then capture_complete=false; fi
  printf '{"pod":"%s","exit_code":%s}\n' "${falco_pod}" "${capture_rc}" >>"${RUN_DIR}/log-collection.jsonl"
done <"${RUN_DIR}/falco-pods.txt"
if ! kubectl -n "${FALCO_NS}" get pods -l app.kubernetes.io/name=falco -o json >"${RUN_DIR}/falco-after.json"; then
  capture_complete=false
fi
if ! kubectl -n "${FALCO_NS}" get daemonset falco -o json >"${RUN_DIR}/daemonset-after.json"; then
  capture_complete=false
fi
if ! kubectl -n "${NS}" get pods -o json >"${RUN_DIR}/workloads-after.json"; then
  capture_complete=false
fi
python3 - "${RUN_DIR}/run.json" "${NS}" "${START_NS}" "${END_NS}" "${capture_complete}" "${SETTLE_SECONDS}" <<'PY'
import json, sys
path, namespace, start, end, complete, settle = sys.argv[1:]
with open(path, 'w') as output:
    json.dump(dict(schema_version=1, namespace=namespace, start_ns=int(start), end_ns=int(end),
                   log_collection_complete=complete == 'true', settle_seconds=int(settle),
                   event_drop_metrics_checked=False, ground_truth_source='controlled test-case intent'),
              output, indent=2)
    output.write('\n')
PY
python3 "${ROOT_DIR}/category1/analyze_results.py" "${RUN_DIR}"
printf '\nEvaluation complete: %s/summary.md\n' "${RUN_DIR}"
