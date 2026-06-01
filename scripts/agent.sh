#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./install-common.sh
source "${SCRIPT_DIR}/install-common.sh"

require_value() {
  local option="$1"
  local value="${2:-}"
  if [[ -z "${value}" || "${value}" == --* ]]; then
    die "${option} 需要参数"
  fi
  printf '%s\n' "${value}"
}

usage() {
  cat <<'EOF'
用法：
  bash agent.sh --server-url http://<ip>:25012 --agent-token <token> [--node-id node-xxxx] [--net-iface eth0] [--disable-update] [--version v0.6.0]
  未指定 --node-id 时会复用本机已保存 ID；没有保存 ID 时自动生成。
  指定版本必须包含 SHA256SUMS；旧版本请使用该版本对应的旧安装脚本。
EOF
}

write_conf() {
  local server_url="$1"
  local net_iface="$2"
  local disable_update="$3"
  mkdir -p "${CONF_DIR}"
  {
    write_systemd_env "CM_SERVER_URL" "${server_url}" || return 1
    write_systemd_env "CM_NODE_ID_FILE" "${INSTALL_DIR}/.cybermonitor-node-id" || return 1
    write_systemd_env "CM_AGENT_TOKEN_FILE" "${INSTALL_DIR}/.cybermonitor-agent-token" || return 1
    write_systemd_env "CM_NET_IFACE" "${net_iface}" || return 1
    write_systemd_env "CM_DISABLE_UPDATE" "${disable_update}" || return 1
  } > "${CONF_DIR}/agent.conf"
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
  systemctl daemon-reload &&
    systemctl enable "${service}" &&
    systemctl restart "${service}"
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
  validate_systemd_unit_paths || die "systemd unit 路径包含非法值"
  node_id="$(resolve_node_id "${node_id}")"
  validate_agent_local_config "${server_url}" "${node_id}" "${net_iface}" "${disable_update}" || die "本地 Agent 配置包含非法值"

  local arch
  arch="$(detect_arch)"
  version="$(resolve_version "${version}")"

  local service="cyber-monitor-agent"
  local service_file="${SYSTEMD_SERVICE_DIR}/${service}.service"
  local token_file="${INSTALL_DIR}/.cybermonitor-agent-token"
  local node_id_file="${INSTALL_DIR}/.cybermonitor-node-id"
  local token_backup=""
  local node_id_backup=""
  local conf_backup=""
  local service_backup=""
  local service_existed=""
  local service_enabled=""
  local service_active=""
  capture_service_state "${service}" service_existed service_enabled service_active
  if ! backup_file_if_exists "${token_file}" token_backup ||
    ! backup_file_if_exists "${node_id_file}" node_id_backup ||
    ! backup_file_if_exists "${CONF_DIR}/agent.conf" conf_backup ||
    ! backup_file_if_exists "${service_file}" service_backup; then
    cleanup_file_backup "${token_backup}"
    cleanup_file_backup "${node_id_backup}"
    cleanup_file_backup "${conf_backup}"
    cleanup_file_backup "${service_backup}"
    die "安装 ${service} 失败，无法创建回滚备份"
  fi

  local bin
  local node_token=""
  local node_registered="0"
  if ! download_binary "agent" "${version}" "${arch}" bin ||
    ! { node_token="$(register_agent "${server_url}" "${bootstrap_token}" "${node_id}")" && node_registered="1"; } ||
    ! write_agent_token_file "${node_token}" ||
    ! write_node_id_file "${node_id}" ||
    ! write_conf "${server_url}" "${net_iface}" "${disable_update}" ||
    ! write_service_file "${service_file}" "${bin}" ||
    ! enable_service "${service}"; then
    if [[ "${node_registered}" != "1" || -n "${node_id_backup}" ]]; then
      restore_file_backup "${node_id_file}" "${node_id_backup}" || true
    fi
    if ! rollback_install_failure "agent" "${service}" "${token_file}" "${token_backup}" "${CONF_DIR}/agent.conf" "${conf_backup}" "${service_file}" "${service_backup}" "${service_existed}" "${service_enabled}" "${service_active}"; then
      die "启动 ${service} 失败；回滚后服务仍未运行"
    fi
    die "安装 ${service} 失败，已执行回滚流程"
  fi
  cleanup_file_backup "${token_backup}"
  cleanup_file_backup "${node_id_backup}"
  cleanup_file_backup "${conf_backup}"
  cleanup_file_backup "${service_backup}"
  cleanup_binary_backup
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
        server_url="$(require_value "$1" "${2:-}")"
        shift 2
        ;;
      --agent-token)
        token="$(require_value "$1" "${2:-}")"
        shift 2
        ;;
      --node-id)
        node_id="$(require_value "$1" "${2:-}")"
        shift 2
        ;;
      --net-iface)
        net_iface="$(require_value "$1" "${2:-}")"
        shift 2
        ;;
      --disable-update)
        disable_update="1"
        shift
        ;;
      --version)
        version="$(require_value "$1" "${2:-}")"
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

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
