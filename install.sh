#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-pbl-security}"
NAMESPACE="${NAMESPACE:-pbl-security}"
KIND_VERSION="${KIND_VERSION:-v0.24.0}"
CILIUM_VERSION="${CILIUM_VERSION:-1.16.3}"
HUBBLE_VERSION="${HUBBLE_VERSION:-v1.16.3}"
CILIUM_WAIT_DURATION="${CILIUM_WAIT_DURATION:-15m}"
WORKLOAD_WAIT_DURATION="${WORKLOAD_WAIT_DURATION:-30m}"
FALCO_HELM_REPO="${FALCO_HELM_REPO:-https://falcosecurity.github.io/charts}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATED_DIR="${ROOT_DIR}/.generated"
INSTALL_BIN_DIR="${INSTALL_BIN_DIR:-/usr/local/bin}"
SUDO=""
CLI_ARCH=""

log() {
  printf '[install] %s\n' "$*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

prepare_host() {
  if [[ "$(uname -s)" != "Linux" ]] || ! need_cmd apt-get; then
    printf 'This installer supports Ubuntu/Debian Linux with apt-get.\n' >&2
    exit 1
  fi

  if [[ "${EUID}" -ne 0 ]] && { ! need_cmd curl || ! need_cmd docker || ! need_cmd gzip || ! need_cmd tar; }; then
    if ! need_cmd sudo; then
      printf 'sudo is required. Run this script as root or install sudo first.\n' >&2
      exit 1
    fi
    SUDO="sudo"
    sudo -v
  fi

  case "$(uname -m)" in
    x86_64) CLI_ARCH="amd64" ;;
    aarch64|arm64) CLI_ARCH="arm64" ;;
    *)
      printf 'Unsupported CPU architecture: %s\n' "$(uname -m)" >&2
      exit 1
      ;;
  esac

  if ! need_cmd curl || ! need_cmd docker || ! need_cmd gzip || ! need_cmd tar; then
    log "Installing base packages required by the lab."
    ${SUDO} apt-get update
    ${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y \
      ca-certificates curl docker.io gzip tar
  fi

  if [[ ! -d "${INSTALL_BIN_DIR}" ]]; then
    mkdir -p "${INSTALL_BIN_DIR}"
  fi
  if [[ ! -w "${INSTALL_BIN_DIR}" ]]; then
    if [[ "${EUID}" -ne 0 ]]; then
      SUDO="sudo"
      sudo -v
    fi
  fi
  export PATH="${INSTALL_BIN_DIR}:${PATH}"
}

install_and_check_docker() {
  if ! docker info >/dev/null 2>&1; then
    log "Enabling Docker Engine."
    if [[ "${EUID}" -ne 0 ]] && [[ -z "${SUDO}" ]]; then
      SUDO="sudo"
      sudo -v
    fi
    if need_cmd systemctl; then
      ${SUDO} systemctl enable --now docker
    else
      ${SUDO} service docker start
    fi
  fi

  if [[ "${EUID}" -ne 0 ]] && ! id -nG "${USER}" | tr ' ' '\n' | grep -qx docker; then
    ${SUDO} usermod -aG docker "${USER}"
    cat <<EOF

[install] Docker was installed and ${USER} was added to the docker group.
[install] Log out and back in, then run ./install.sh again.
EOF
    exit 0
  fi

  if ! docker info >/dev/null 2>&1; then
    cat >&2 <<'EOF'
Docker is installed, but this shell cannot access the Docker daemon.
Log out and back in to refresh group membership, then run ./install.sh again.
EOF
    exit 1
  fi
}

install_kind_if_missing() {
  if need_cmd kind; then
    return
  fi

  log "kind not found. Installing kind ${KIND_VERSION} into ${INSTALL_BIN_DIR}."
  curl -Lo /tmp/kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${CLI_ARCH}"
  chmod +x /tmp/kind
  ${SUDO} mv /tmp/kind "${INSTALL_BIN_DIR}/kind"
}

install_kubectl_if_missing() {
  if need_cmd kubectl; then
    return
  fi

  log "kubectl not found. Installing latest stable kubectl into ${INSTALL_BIN_DIR}."
  local stable
  stable="$(curl -L -s https://dl.k8s.io/release/stable.txt)"
  curl -Lo /tmp/kubectl "https://dl.k8s.io/release/${stable}/bin/linux/${CLI_ARCH}/kubectl"
  chmod +x /tmp/kubectl
  ${SUDO} mv /tmp/kubectl "${INSTALL_BIN_DIR}/kubectl"
}

install_helm_if_missing() {
  if need_cmd helm; then
    return
  fi

  log "helm not found. Installing helm."
  curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | \
    ${SUDO} env HELM_INSTALL_DIR="${INSTALL_BIN_DIR}" USE_SUDO=false bash
}

install_cilium_cli_if_missing() {
  if need_cmd cilium; then
    return
  fi

  log "cilium CLI not found. Installing latest cilium CLI into /usr/local/bin."
  local archive
  archive="/tmp/cilium-linux-${CLI_ARCH}.tar.gz"
  curl -L --fail -o "${archive}" \
    "https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-${CLI_ARCH}.tar.gz"
  ${SUDO} tar xzf "${archive}" -C "${INSTALL_BIN_DIR}"
  rm -f "${archive}"
}

install_hubble_cli_if_missing() {
  if need_cmd hubble && hubble version 2>/dev/null | grep -q "hubble ${HUBBLE_VERSION}@"; then
    return
  fi

  log "Installing Hubble CLI ${HUBBLE_VERSION} into ${INSTALL_BIN_DIR}."
  local archive
  archive="/tmp/hubble-linux-${CLI_ARCH}.tar.gz"
  curl -L --fail -o "${archive}" \
    "https://github.com/cilium/hubble/releases/download/${HUBBLE_VERSION}/hubble-linux-${CLI_ARCH}.tar.gz"
  ${SUDO} tar xzf "${archive}" -C "${INSTALL_BIN_DIR}"
  rm -f "${archive}"
}

write_audit_files() {
  mkdir -p "${GENERATED_DIR}/audit"

  cat >"${GENERATED_DIR}/audit/audit-policy.yaml" <<'YAML'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: ""
        resources: ["secrets", "serviceaccounts"]
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  - level: Metadata
    resources:
      - group: ""
        resources: ["pods", "services", "secrets", "serviceaccounts"]
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  - level: Metadata
    omitStages:
      - RequestReceived
YAML

  cat >"${GENERATED_DIR}/kind-config.yaml" <<YAML
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: ${GENERATED_DIR}/audit
        containerPath: /etc/kubernetes/audit
      - hostPath: ${GENERATED_DIR}/audit-logs
        containerPath: /var/log/kubernetes
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            audit-log-path: /var/log/kubernetes/audit.log
            audit-policy-file: /etc/kubernetes/audit/audit-policy.yaml
            audit-log-maxage: "7"
            audit-log-maxbackup: "3"
            audit-log-maxsize: "100"
          extraVolumes:
            - name: audit-policy
              hostPath: /etc/kubernetes/audit
              mountPath: /etc/kubernetes/audit
              readOnly: true
              pathType: Directory
            - name: audit-logs
              hostPath: /var/log/kubernetes
              mountPath: /var/log/kubernetes
              readOnly: false
              pathType: DirectoryOrCreate
  - role: worker
  - role: worker
YAML
}

create_cluster() {
  if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
    log "kind cluster ${CLUSTER_NAME} already exists."
    return
  fi

  mkdir -p "${GENERATED_DIR}/audit-logs"
  write_audit_files
  log "Creating kind cluster ${CLUSTER_NAME} with Kubernetes Audit Log enabled."
  kind create cluster --name "${CLUSTER_NAME}" --config "${GENERATED_DIR}/kind-config.yaml"
}

configure_kernel_limits() {
  log "Ensuring enough inotify instances for Falco, Cilium, and Hubble."
  docker exec --privileged "${CLUSTER_NAME}-control-plane" \
    sysctl -w fs.inotify.max_user_instances=8192 >/dev/null
}

install_cilium_and_hubble() {
  if helm list --namespace kube-system --all --short | grep -qx cilium; then
    log "Cilium release already exists. Waiting for its core components."
  else
    log "Installing Cilium ${CILIUM_VERSION}."
    cilium install --version "${CILIUM_VERSION}" --wait \
      --wait-duration "${CILIUM_WAIT_DURATION}"
  fi
  kubectl rollout status daemonset/cilium --namespace kube-system \
    --timeout="${CILIUM_WAIT_DURATION}"
  kubectl rollout status deployment/cilium-operator --namespace kube-system \
    --timeout="${CILIUM_WAIT_DURATION}"

  if kubectl rollout status deployment/hubble-relay --namespace kube-system \
    --timeout=5s >/dev/null 2>&1 &&
    kubectl rollout status deployment/hubble-ui --namespace kube-system \
      --timeout=5s >/dev/null 2>&1; then
    log "Hubble Relay and UI are already ready."
  else
    log "Enabling Hubble."
    cilium hubble enable --ui
    kubectl rollout restart daemonset/cilium --namespace kube-system
    kubectl rollout status daemonset/cilium --namespace kube-system \
      --timeout="${CILIUM_WAIT_DURATION}"
    kubectl rollout restart deployment/hubble-relay deployment/hubble-ui \
      --namespace kube-system
    kubectl rollout status deployment/hubble-relay --namespace kube-system \
      --timeout="${CILIUM_WAIT_DURATION}"
    kubectl rollout status deployment/hubble-ui --namespace kube-system \
      --timeout="${CILIUM_WAIT_DURATION}"
  fi
  cilium status --wait --interactive=false \
    --wait-duration "${CILIUM_WAIT_DURATION}"
}

install_falco() {
  log "Installing Falco."
  helm repo add falcosecurity "${FALCO_HELM_REPO}" >/dev/null
  helm repo update >/dev/null
  helm upgrade --install falco falcosecurity/falco \
    --namespace falco \
    --create-namespace \
    --set tty=true \
    --set falco.json_output=true \
    --set falco.rule_matching=all \
    --values "${ROOT_DIR}/category1/falco-values.yaml" \
    --wait \
    --timeout "${WORKLOAD_WAIT_DURATION}"
  kubectl rollout status daemonset/falco --namespace falco \
    --timeout="${WORKLOAD_WAIT_DURATION}"
}

deploy_workload() {
  log "Deploying PBL workload into namespace ${NAMESPACE}."
  kubectl apply -f "${ROOT_DIR}/workload"
  kubectl -n "${NAMESPACE}" rollout status deployment/frontend \
    --timeout="${WORKLOAD_WAIT_DURATION}"
  kubectl -n "${NAMESPACE}" rollout status deployment/backend \
    --timeout="${WORKLOAD_WAIT_DURATION}"
  kubectl -n "${NAMESPACE}" rollout status deployment/db \
    --timeout="${WORKLOAD_WAIT_DURATION}"
}

print_next_steps() {
  cat <<EOF

Installation complete.

Useful commands:
  kubectl get pods -n ${NAMESPACE}
  kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --prefix -f
  cilium hubble port-forward &
  hubble observe --namespace ${NAMESPACE} --follow
  docker exec ${CLUSTER_NAME}-control-plane tail -f /var/log/kubernetes/audit.log

Run labs:
  cd ${ROOT_DIR} && ./category1/normal.sh && ./category1/abnormal_1.sh && ./category1/abnormal_2.sh && ./category1/abnormal_3.sh
  cd ${ROOT_DIR} && ./category2/normal.sh && ./category2/abnormal_1.sh && ./category2/abnormal_2.sh && ./category2/abnormal_3.sh
  cd ${ROOT_DIR} && ./category3/normal.sh && ./category3/abnormal_1.sh && ./category3/abnormal_2.sh && ./category3/abnormal_3.sh
EOF
}

main() {
  prepare_host
  install_and_check_docker
  install_kind_if_missing
  install_kubectl_if_missing
  install_helm_if_missing
  install_cilium_cli_if_missing
  install_hubble_cli_if_missing
  create_cluster
  configure_kernel_limits
  install_cilium_and_hubble
  install_falco
  deploy_workload
  print_next_steps
}

main "$@"
