#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./install-common.sh
source "${SCRIPT_DIR}/install-common.sh"

usage() {
  cat <<'EOF'
用法：
  bash agent.sh --server-url http://<ip>:25012 --agent-token <token> [--node-id node-xxxx] [--net-iface eth0] [--disable-update] [--version v0.1.0]
EOF
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
  bin="$(download_binary "agent" "${version}" "${arch}")"
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
