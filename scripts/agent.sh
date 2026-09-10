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
  支持 Linux（systemd）与 macOS（launchd）。
  未指定 --node-id 时会复用本机已保存 ID；没有保存 ID 时自动生成。
  指定版本必须包含 SHA256SUMS；旧版本请使用该版本对应的旧安装脚本。
EOF
}

write_conf_linux() {
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

# macOS 没有 systemd EnvironmentFile，launchd 通过 plist 的
# EnvironmentVariables 注入；agent.conf 仅作 KEY=value 记录，
# 便于人工核对，同时保持与卸载脚本清理路径一致。
write_conf_macos() {
  local server_url="$1"
  local net_iface="$2"
  local disable_update="$3"
  mkdir -p "${CONF_DIR}"
  cat > "${CONF_DIR}/agent.conf" <<EOF
CM_SERVER_URL=${server_url}
CM_NODE_ID_FILE=${INSTALL_DIR}/.cybermonitor-node-id
CM_AGENT_TOKEN_FILE=${INSTALL_DIR}/.cybermonitor-agent-token
CM_NET_IFACE=${net_iface}
CM_DISABLE_UPDATE=${disable_update}
EOF
}

plist_escape() {
  local value="$1"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  value="${value//\"/&quot;}"
  value="${value//\'/&apos;}"
  printf '%s' "${value}"
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

MACOS_AGENT_LABEL="io.github.crazy0x70.cyber-monitor-agent"

# root 安装为系统级服务（/Library/LaunchDaemons，开机自启）；
# 普通用户安装为用户级服务（~/Library/LaunchAgents，登录自启）。
macos_launchd_dir() {
  if [[ "$(id -u)" -eq 0 ]]; then
    printf '%s' "${MACOS_LAUNCHD_DIR}"
  else
    printf '%s/Library/LaunchAgents' "${HOME}"
  fi
}

macos_launchd_domain() {
  if [[ "$(id -u)" -eq 0 ]]; then
    printf '%s' "system"
  else
    printf 'gui/%s' "$(id -u)"
  fi
}

macos_agent_log_path() {
  if [[ "$(id -u)" -eq 0 ]]; then
    printf '%s' "/var/log/cybermonitor-agent.log"
  else
    printf '%s/Library/Logs/cybermonitor-agent.log' "${HOME}"
  fi
}

write_launchd_plist() {
  local plist_path="$1"
  local bin="$2"
  local server_url="$3"
  local net_iface="$4"
  local disable_update="$5"
  local log_path
  log_path="$(macos_agent_log_path)"
  cat > "${plist_path}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${MACOS_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${bin}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>CM_SERVER_URL</key>
        <string>$(plist_escape "${server_url}")</string>
        <key>CM_NODE_ID_FILE</key>
        <string>${INSTALL_DIR}/.cybermonitor-node-id</string>
        <key>CM_AGENT_TOKEN_FILE</key>
        <string>${INSTALL_DIR}/.cybermonitor-agent-token</string>
        <key>CM_NET_IFACE</key>
        <string>$(plist_escape "${net_iface}")</string>
        <key>CM_DISABLE_UPDATE</key>
        <string>${disable_update}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${log_path}</string>
    <key>StandardErrorPath</key>
    <string>${log_path}</string>
</dict>
</plist>
EOF
}

enable_service() {
  local service="$1"
  systemctl daemon-reload &&
    systemctl enable "${service}" &&
    systemctl restart "${service}"
}

enable_launchd_service() {
  local plist_path="$1"
  local domain
  domain="$(macos_launchd_domain)"
  # 幂等重装：先移除可能存在的旧实例，忽略不存在错误。
  launchctl bootout "${domain}" "${plist_path}" >/dev/null 2>&1 || true
  if launchctl bootstrap "${domain}" "${plist_path}" 2>/dev/null; then
    return 0
  fi
  # 旧版 macOS 无 bootstrap/bootout，退回 load 语法。
  launchctl unload -w "${plist_path}" >/dev/null 2>&1 || true
  launchctl load -w "${plist_path}"
}

launchd_service_running() {
  # bootstrap 返回后进程可能仍在启动，等待一拍再确认状态。
  sleep 1
  launchctl print "$(macos_launchd_domain)/${MACOS_AGENT_LABEL}" 2>/dev/null | grep -q 'state = running'
}

install_agent_linux() {
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
    ! write_conf_linux "${server_url}" "${net_iface}" "${disable_update}" ||
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

install_agent_macos() {
  local server_url="$1"
  local bootstrap_token="$2"
  local node_id="$3"
  local net_iface="$4"
  local disable_update="$5"
  local version="$6"
  [[ -z "${server_url}" ]] && die "必须提供 --server-url"
  [[ -z "${bootstrap_token}" ]] && die "必须提供 --agent-token"
  command -v launchctl >/dev/null 2>&1 || die "未检测到 launchctl"
  normalize_macos_user_paths
  node_id="$(resolve_node_id "${node_id}")"
  validate_agent_local_config "${server_url}" "${node_id}" "${net_iface}" "${disable_update}" || die "本地 Agent 配置包含非法值"

  local arch
  arch="$(detect_arch)"
  version="$(resolve_version "${version}")"

  local plist_dir
  plist_dir="$(macos_launchd_dir)"
  mkdir -p "${plist_dir}"
  local plist_path="${plist_dir}/${MACOS_AGENT_LABEL}.plist"
  local token_file="${INSTALL_DIR}/.cybermonitor-agent-token"
  local node_id_file="${INSTALL_DIR}/.cybermonitor-node-id"
  local token_backup=""
  local node_id_backup=""
  local conf_backup=""
  local plist_backup=""
  if ! backup_file_if_exists "${token_file}" token_backup ||
    ! backup_file_if_exists "${node_id_file}" node_id_backup ||
    ! backup_file_if_exists "${CONF_DIR}/agent.conf" conf_backup ||
    ! backup_file_if_exists "${plist_path}" plist_backup; then
    cleanup_file_backup "${token_backup}"
    cleanup_file_backup "${node_id_backup}"
    cleanup_file_backup "${conf_backup}"
    cleanup_file_backup "${plist_backup}"
    die "安装 CyberMonitor Agent 失败，无法创建回滚备份"
  fi

  local bin
  local node_token=""
  local node_registered="0"
  if ! download_binary "agent" "${version}" "${arch}" bin ||
    ! { node_token="$(register_agent "${server_url}" "${bootstrap_token}" "${node_id}")" && node_registered="1"; } ||
    ! write_agent_token_file "${node_token}" ||
    ! write_node_id_file "${node_id}" ||
    ! write_conf_macos "${server_url}" "${net_iface}" "${disable_update}" ||
    ! write_launchd_plist "${plist_path}" "${bin}" "${server_url}" "${net_iface}" "${disable_update}" ||
    ! enable_launchd_service "${plist_path}" ||
    ! launchd_service_running; then
    launchctl bootout "$(macos_launchd_domain)" "${plist_path}" >/dev/null 2>&1 || true
    if [[ "${node_registered}" != "1" || -n "${node_id_backup}" ]]; then
      restore_file_backup "${node_id_file}" "${node_id_backup}" || true
    fi
    restore_file_backup "${token_file}" "${token_backup}" || true
    restore_file_backup "${CONF_DIR}/agent.conf" "${conf_backup}" || true
    restore_file_backup "${plist_path}" "${plist_backup}" || true
    restore_binary_backup "agent" || true
    # 重装前已有旧 plist 时，把旧服务重新拉起。
    if [[ -n "${plist_backup}" ]]; then
      launchctl bootstrap "$(macos_launchd_domain)" "${plist_path}" >/dev/null 2>&1 || true
    fi
    die "安装 CyberMonitor Agent 失败，已执行回滚流程"
  fi
  cleanup_file_backup "${token_backup}"
  cleanup_file_backup "${node_id_backup}"
  cleanup_file_backup "${conf_backup}"
  cleanup_file_backup "${plist_backup}"
  cleanup_binary_backup
  echo "已安装并启动 ${MACOS_AGENT_LABEL}（macOS / launchd）"
  echo "Node ID: ${node_id}"
  echo "日志: $(macos_agent_log_path)"
}

install_agent() {
  case "$(detect_os)" in
    linux) install_agent_linux "$@" ;;
    macos) install_agent_macos "$@" ;;
  esac
}

main() {
  case "$(detect_os)" in
    linux)
      require_root
      require_systemd
      ;;
    # macOS 允许普通用户安装（用户级 LaunchAgent）；root 则安装系统级 LaunchDaemon。
  esac
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
