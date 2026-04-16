#!/usr/bin/env bash
set -euo pipefail

REPO="crazy0x70/CyberMonitor"
INSTALL_DIR="/opt/CyberMonitor"
CONF_DIR="/etc/cybermonitor"

usage() {
  cat <<'EOF'
用法：
  bash agent.sh --server-url http://<ip>:25012 --agent-token <token> [--node-id node-xxxx] [--net-iface eth0] [--disable-update] [--version v0.1.0]
EOF
}

die() {
  echo "错误: $*" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "请使用 root 运行"
  fi
}

require_systemd() {
  command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd"
}

require_curl() {
  command -v curl >/dev/null 2>&1 || die "请先安装 curl"
}

detect_arch() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7) echo "armv7" ;;
    *) die "不支持的架构: ${arch}" ;;
  esac
}

resolve_version() {
  local version="$1"
  if [[ -n "${version}" ]]; then
    echo "${version}"
    return
  fi
  local latest_url
  latest_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"
  version="${latest_url##*/}"
  if [[ "${version}" == "latest" ]]; then
    version=""
  fi
  if [[ -z "${version}" ]]; then
    version="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | \
      sed -n 's/.*"tag_name": *"\\([^"]*\\)".*/\\1/p' | head -n 1)"
  fi
  if [[ -z "${version}" ]]; then
    die "无法获取最新版本，请使用版本号手动指定"
  fi
  echo "${version}"
}

download_binary() {
  local version="$1"
  local arch="$2"
  local os="linux"
  local asset="cyber-monitor-agent-${os}-${arch}"
  local url="https://github.com/${REPO}/releases/download/${version}/${asset}"
  local target="${INSTALL_DIR}/cyber-monitor-agent"
  mkdir -p "${INSTALL_DIR}"
  curl -fL "${url}" -o "${target}"
  chmod +x "${target}"
  echo "${target}"
}

write_agent_token_file() {
  local token="$1"
  printf '%s\n' "${token}" > "${INSTALL_DIR}/.cybermonitor-agent-token"
  chmod 600 "${INSTALL_DIR}/.cybermonitor-agent-token"
}

generate_node_id() {
  local random_hex
  random_hex="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  echo "node-${random_hex}"
}

register_agent() {
  local server_url="$1"
  local bootstrap_token="$2"
  local node_id="$3"
  local endpoint="${server_url%/}/api/v1/agent/register?node_id=${node_id}"
  local response
  response="$(curl -fsSL -X POST -H "X-AGENT-TOKEN: ${bootstrap_token}" "${endpoint}")" || \
    die "Agent 注册失败，请检查 Server 地址与 Agent Token"
  local node_token
  node_token="$(printf '%s' "${response}" | sed -n 's/.*"agent_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  [[ -n "${node_token}" ]] || die "Agent 注册成功但未返回专属凭据"
  echo "${node_token}"
}

write_conf() {
  mkdir -p "${CONF_DIR}"
  cat > "${CONF_DIR}/agent.conf" <<EOF
CM_SERVER_URL=${1}
CM_NODE_ID=${2}
CM_AGENT_TOKEN_FILE=${INSTALL_DIR}/.cybermonitor-agent-token
CM_NET_IFACE=${3}
CM_DISABLE_UPDATE=${4}
EOF
}

write_service_file() {
  local service_file="$1"
  local bin="$2"
  cat > "${service_file}" <<EOF
[Unit]
Description=CyberMonitor Agent
After=network.target

[Service]
Type=simple
EnvironmentFile=${CONF_DIR}/agent.conf
ExecStart=${bin}
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

enable_service() {
  local service="$1"
  systemctl daemon-reload
  systemctl enable --now "${service}"
}

install_agent() {
  local server_url="$1"
  local bootstrap_token="$2"
  local node_id="$3"
  local net_iface="$4"
  local disable_update="$5"
  local version="$6"
  [[ -z "${server_url}" ]] && die "必须提供 --server-url"
  [[ -z "${bootstrap_token}" ]] && die "必须提供 --agent-token"
  [[ -n "${node_id}" ]] || node_id="$(generate_node_id)"

  local arch
  arch="$(detect_arch)"
  version="$(resolve_version "${version}")"
  local node_token
  node_token="$(register_agent "${server_url}" "${bootstrap_token}" "${node_id}")"

  local bin
  bin="$(download_binary "${version}" "${arch}")"
  write_agent_token_file "${node_token}"
  write_conf "${server_url}" "${node_id}" "${net_iface}" "${disable_update}"

  local service="cyber-monitor-agent"
  local service_file="/etc/systemd/system/${service}.service"
  write_service_file "${service_file}" "${bin}"
  enable_service "${service}"
  echo "已安装并启动 ${service}"
  echo "Node ID: ${node_id}"
}

main() {
  require_root
  require_systemd
  require_curl

  local server_url=""
  local token=""
  local node_id=""
  local net_iface=""
  local disable_update="0"
  local version=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server-url)
        server_url="$2"
        shift 2
        ;;
      --agent-token)
        token="$2"
        shift 2
        ;;
      --node-id)
        node_id="$2"
        shift 2
        ;;
      --net-iface)
        net_iface="$2"
        shift 2
        ;;
      --disable-update)
        disable_update="1"
        shift
        ;;
      --version)
        version="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "未知参数: $1"
        ;;
    esac
  done

  install_agent "${server_url}" "${token}" "${node_id}" "${net_iface}" "${disable_update}" "${version}"
}

main "$@"
