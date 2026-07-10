#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./install-common.sh
source "${SCRIPT_DIR}/install-common.sh"

SERVER_DATA_OWNED_MARKER=".cybermonitor-server-data"

print_install_menu() {
  cat <<'EOF'
CyberMonitor 一键脚本
1) 安装主控
2) 安装被控
0) 退出
EOF
}

print_remove_menu() {
  cat <<'EOF'
卸载选项
1) 卸载主控
2) 卸载被控
0) 退出
EOF
}

generate_admin_password() {
  local password=""
  if command -v openssl >/dev/null 2>&1; then
    password="$(openssl rand -base64 18 | tr -d '\n' | tr '+/' '-_' | cut -c1-24)"
  fi
  if [[ -z "${password}" ]]; then
    password="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n' | cut -c1-24)"
  fi
  [[ "${#password}" -eq 24 ]] || return 1
  printf '%s\n' "${password}"
}

write_server_conf() {
  local listen="$1"
  local data_dir="$2"
  local admin_pass="${3:-}"
  mkdir -p "${CONF_DIR}"
  local old_umask
  old_umask="$(umask)"
  umask 077
  if ! {
    write_systemd_env "CM_LISTEN" "${listen}" &&
      write_systemd_env "CM_DATA_DIR" "${data_dir}" &&
      { [[ -z "${admin_pass}" ]] || write_systemd_env "CM_ADMIN_PASS" "${admin_pass}"; }
  } > "${CONF_DIR}/server.conf"; then
    umask "${old_umask}"
    return 1
  fi
  umask "${old_umask}"
  chmod 600 "${CONF_DIR}/server.conf" || return 1
}

write_agent_conf() {
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
  local description="$2"
  local env_file="$3"
  local bin="$4"
  cat > "${service_file}" <<EOF
[Unit]
Description=${description}
After=network.target

[Service]
Type=simple
EnvironmentFile=${env_file}
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

read_admin_settings() {
  local data_dir="$1"
  local state_file="${data_dir}/state.json"
  local admin_path=""
  local admin_user=""

  for _ in {1..20}; do
    if [[ -f "${state_file}" ]]; then
      admin_path="$(sed -n 's/.*"admin_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${state_file}" | head -n 1)"
      admin_user="$(sed -n 's/.*"admin_user"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${state_file}" | head -n 1)"
      if [[ -n "${admin_path}" && -n "${admin_user}" ]]; then
        break
      fi
    fi
    sleep 1
  done
  if [[ -z "${admin_path}" || -z "${admin_user}" ]]; then
    return 1
  fi
  echo -e "${admin_path}\t${admin_user}"
}

is_valid_ipv4() {
  local ip="$1"
  [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local o
  IFS='.' read -r -a o <<< "${ip}"
  for part in "${o[@]}"; do
    if ((part < 0 || part > 255)); then
      return 1
    fi
  done
  return 0
}

resolve_host_port() {
  local listen="$1"
  local host=""
  local port=""
  if [[ "${listen}" == *":"* ]]; then
    if [[ "${listen}" == \[*\]*:* ]]; then
      host="${listen%%]:*}"
      host="${host#[}"
      port="${listen##*:}"
    else
      host="${listen%:*}"
      port="${listen##*:}"
    fi
  else
    port="${listen}"
  fi
  if [[ -z "${port}" ]]; then
    port="25012"
  fi
  if [[ -z "${host}" || "${host}" == "0.0.0.0" || "${host}" == "::" || "${host}" == "[::]" ]]; then
    host="127.0.0.1"
  fi
  echo "${host} ${port}"
}

print_admin_info() {
  local listen="$1"
  local data_dir="$2"
  local admin_pass="$3"
  local admin_path admin_user
  if ! read -r admin_path admin_user < <(read_admin_settings "${data_dir}"); then
    echo "无法读取管理后台信息，请稍后查看服务日志。"
    return
  fi
  if [[ "${admin_path}" != /* ]]; then
    admin_path="/${admin_path}"
  fi
  local host port
  read -r host port < <(resolve_host_port "${listen}")
  local admin_url="http://${host}:${port}${admin_path}"
  echo "管理后台地址: ${admin_url}"
  echo "初始管理员账号: ${admin_user}"
  if [[ -n "${admin_pass}" ]]; then
    echo "初始管理员密码: ${admin_pass}"
  else
    echo "初始管理员密码: 已设置，请使用重置密码命令获取新密码。"
  fi
}

install_server() {
  local listen="$1"
  local data_dir="$2"
  local version="$3"
  local data_dir_created=""
  validate_systemd_unit_paths || die "systemd unit 路径包含非法值"
  reject_unsafe_path "${data_dir}" || die "数据目录包含不安全路径"
  local arch
  arch="$(detect_arch)"
  version="$(resolve_version "${version}")"
  local admin_pass=""
  if [[ ! -f "${data_dir}/state.json" ]]; then
    admin_pass="$(generate_admin_password)" || die "生成管理员初始密码失败"
  fi
  if [[ ! -e "${data_dir}" ]]; then
    data_dir_created="1"
  fi
  mkdir -p "${data_dir}"
  if [[ "${data_dir_created}" == "1" ]] && ! mark_server_data_dir_owned "${data_dir}"; then
    cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
    die "安装 cyber-monitor-server 失败，无法标记数据目录归属"
  fi

  local service="cyber-monitor-server"
  local service_file="${SYSTEMD_SERVICE_DIR}/${service}.service"
  local conf_backup=""
  local service_backup=""
  local service_existed=""
  local service_enabled=""
  local service_active=""
  capture_service_state "${service}" service_existed service_enabled service_active
  if ! backup_file_if_exists "${CONF_DIR}/server.conf" conf_backup ||
    ! backup_file_if_exists "${service_file}" service_backup; then
    cleanup_file_backup "${conf_backup}"
    cleanup_file_backup "${service_backup}"
    cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
    die "安装 ${service} 失败，无法创建回滚备份"
  fi

  local bin
  if ! download_binary "server" "${version}" "${arch}" bin ||
    ! write_server_conf "${listen}" "${data_dir}" "${admin_pass}" ||
    ! write_service_file "${service_file}" "CyberMonitor Server" "${CONF_DIR}/server.conf" "${bin}" ||
    ! enable_service "${service}"; then
    if ! rollback_install_failure "server" "${service}" "" "" "${CONF_DIR}/server.conf" "${conf_backup}" "${service_file}" "${service_backup}" "${service_existed}" "${service_enabled}" "${service_active}"; then
      cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
      die "启动 ${service} 失败；回滚后服务仍未运行"
    fi
    cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
    die "安装 ${service} 失败，已执行回滚流程"
  fi
  if [[ -n "${admin_pass}" ]] && (! write_server_conf "${listen}" "${data_dir}" || ! systemctl restart "${service}"); then
    if ! rollback_install_failure "server" "${service}" "" "" "${CONF_DIR}/server.conf" "${conf_backup}" "${service_file}" "${service_backup}" "${service_existed}" "${service_enabled}" "${service_active}"; then
      cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
      die "清理 ${service} 初始管理员密码失败；回滚后服务仍未运行"
    fi
    cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
    die "安装 ${service} 失败，已执行回滚流程"
  fi
  cleanup_file_backup "${conf_backup}"
  cleanup_file_backup "${service_backup}"
  cleanup_binary_backup
  echo "已安装并启动 ${service}"
  print_admin_info "${listen}" "${data_dir}" "${admin_pass}"
}

install_agent() {
  local server_url="$1"
  local bootstrap_token="$2"
  local node_id="$3"
  local net_iface="$4"
  local disable_update="$5"
  local version="$6"
  [[ -z "${server_url}" ]] && die "被控需要填写 Server 地址"
  [[ -z "${bootstrap_token}" ]] && die "被控需要填写 Token"
  validate_systemd_unit_paths || die "systemd unit 路径包含非法值"

  local arch
  arch="$(detect_arch)"
  version="$(resolve_version "${version}")"
  node_id="$(resolve_node_id "${node_id}")"
  validate_agent_local_config "${server_url}" "${node_id}" "${net_iface}" "${disable_update}" || die "本地 Agent 配置包含非法值"

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
    ! write_agent_conf "${server_url}" "${net_iface}" "${disable_update}" ||
    ! write_service_file "${service_file}" "CyberMonitor Agent" "${CONF_DIR}/agent.conf" "${bin}" ||
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

uninstall_service() {
  local type="$1"
  local service="cyber-monitor-${type}"
  local service_file="${SYSTEMD_SERVICE_DIR}/${service}.service"
  reject_unsafe_path "${service_file}" || die "拒绝清理包含不安全路径的服务文件"
  reject_unsafe_path "${INSTALL_DIR}/cyber-monitor-${type}" || die "拒绝清理包含不安全路径的安装文件"
  systemctl disable --now "${service}" >/dev/null 2>&1 || true
  rm -f "${service_file}"
  rm -f "${INSTALL_DIR}/cyber-monitor-${type}"
  systemctl daemon-reload
  echo "已卸载 ${service}"
}

read_server_data_dir() {
  local data_dir=""
  if [[ -f "${CONF_DIR}/server.conf" ]]; then
    data_dir="$(sed -n 's/^CM_DATA_DIR=//p' "${CONF_DIR}/server.conf" | head -n 1)"
    data_dir="$(strip_systemd_env_quotes "${data_dir}")"
  fi
  if [[ -z "${data_dir}" ]]; then
    data_dir="/opt/CyberMonitor/data"
  fi
  echo "${data_dir}"
}

cleanup_created_data_dir() {
  local data_dir="$1"
  local created="$2"
  if [[ "${created}" != "1" || -z "${data_dir}" || "${data_dir}" == "/" ]]; then
    return 0
  fi
  rm -f -- "${data_dir}/${SERVER_DATA_OWNED_MARKER}" 2>/dev/null || true
  rmdir "${data_dir}" 2>/dev/null || echo "保留非空数据目录: ${data_dir}" >&2
}

mark_server_data_dir_owned() {
  local data_dir="$1"
  [[ -n "${data_dir}" && "${data_dir}" != "/" ]] || return 1
  reject_unsafe_path "${data_dir}" || return 1
  touch "${data_dir}/${SERVER_DATA_OWNED_MARKER}"
}

server_data_dir_is_owned() {
  local data_dir="$1"
  [[ -f "${data_dir}/${SERVER_DATA_OWNED_MARKER}" ]]
}

server_data_dir_is_mountpoint_or_unknown() {
  local data_dir="$1"
  command -v mountpoint >/dev/null 2>&1 || return 0
  mountpoint -q -- "${data_dir}"
  local status="$?"
  if [[ "${status}" -eq 32 ]]; then
    return 1
  fi
  return 0
}

cleanup_server_config() {
  local data_dir="$1"
  local install_real=""
  local data_real=""
  reject_unsafe_path "${CONF_DIR}/server.conf" || die "拒绝清理包含不安全路径的主控配置"
  reject_unsafe_path "${INSTALL_DIR}" || die "拒绝清理包含不安全路径的安装目录"
  reject_unsafe_path "${CONF_DIR}" || die "拒绝清理包含不安全路径的配置目录"
  if [[ -n "${data_dir}" && "${data_dir}" != "/" ]]; then
    reject_unsafe_path "${data_dir}" || die "拒绝清理包含不安全路径的数据目录"
    install_real="$(realpath -m -- "${INSTALL_DIR}")"
    data_real="$(realpath -m -- "${data_dir}")"
  fi
  rm -f "${CONF_DIR}/server.conf"
  if [[ -n "${data_real}" && "${data_real}" != "${install_real}" && "${data_real}" == "${install_real}/"* ]]; then
    if ! server_data_dir_is_owned "${data_real}"; then
      echo "未自动删除未标记为 CyberMonitor 管理的数据目录: ${data_dir}"
    elif server_data_dir_is_mountpoint_or_unknown "${data_real}"; then
      echo "未自动删除挂载点或无法确认挂载状态的数据目录: ${data_dir}"
    else
      rm -rf -- "${data_real}"
    fi
  elif [[ -n "${data_dir}" && "${data_dir}" != "/" ]]; then
    echo "未自动删除自定义数据目录: ${data_dir}"
  fi
  rmdir "${INSTALL_DIR}" 2>/dev/null || true
  rmdir "${CONF_DIR}" 2>/dev/null || true
}

cleanup_agent_config() {
  reject_unsafe_path "${CONF_DIR}/agent.conf" || die "拒绝清理包含不安全路径的 Agent 配置"
  reject_unsafe_path "${INSTALL_DIR}/.cybermonitor-agent-token" || die "拒绝清理包含不安全路径的 Agent token"
  reject_unsafe_path "${INSTALL_DIR}/.cybermonitor-node-id" || die "拒绝清理包含不安全路径的节点 ID"
  reject_unsafe_path "${CONF_DIR}" || die "拒绝清理包含不安全路径的配置目录"
  reject_unsafe_path "${INSTALL_DIR}" || die "拒绝清理包含不安全路径的安装目录"
  rm -f "${CONF_DIR}/agent.conf"
  rm -f "${INSTALL_DIR}/.cybermonitor-agent-token"
  rm -f "${INSTALL_DIR}/.cybermonitor-node-id"
  rmdir "${CONF_DIR}" 2>/dev/null || true
  rmdir "${INSTALL_DIR}" 2>/dev/null || true
}

uninstall_server() {
  local keep=""
  read -r -p "是否保留主控配置与数据目录? [y/N]: " keep
  local data_dir
  data_dir="$(read_server_data_dir)"
  uninstall_service "server"
  if [[ ! "${keep}" =~ ^[Yy]$ ]]; then
    cleanup_server_config "${data_dir}"
  fi
}

uninstall_agent() {
  uninstall_service "agent"
  cleanup_agent_config
}

run_install_menu() {
  while true; do
    print_install_menu
    read -r -p "请选择: " choice
    case "${choice}" in
      1)
        read -r -p "监听地址(默认 25012): " listen
        read -r -p "数据目录(默认 /opt/CyberMonitor/data): " data_dir
        read -r -p "版本号(默认 latest): " version
        listen="${listen:-25012}"
        data_dir="${data_dir:-/opt/CyberMonitor/data}"
        install_server "${listen}" "${data_dir}" "${version}"
        ;;
      2)
        read -r -p "Server 地址(统一接入地址，例如 http://1.2.3.4:25012；运行态会优先尝试 gRPC): " server_url
        read -r -p "Agent Token: " token
        read -r -p "Node ID（可空，留空则复用本机已保存 ID 或自动生成）: " node_id
        read -r -p "指定网卡(可空): " net_iface
        read -r -p "是否禁用服务端远程更新? [y/N]: " disable_update_answer
        read -r -p "版本号(默认 latest): " version
        disable_update="0"
        if [[ "${disable_update_answer}" =~ ^[Yy]$ ]]; then
          disable_update="1"
        fi
        install_agent "${server_url}" "${token}" "${node_id}" "${net_iface}" "${disable_update}" "${version}"
        ;;
      0)
        exit 0
        ;;
      *)
        echo "无效选项，请重试。"
        ;;
    esac
    echo ""
  done
}

run_remove_menu() {
  while true; do
    print_remove_menu
    read -r -p "请选择: " choice
    case "${choice}" in
      1) uninstall_server ;;
      2) uninstall_agent ;;
      0) exit 0 ;;
      *) echo "无效选项" ;;
    esac
    echo ""
  done
}

main() {
  require_root
  require_systemd
  require_curl
  case "${1:-}" in
    install)
      run_install_menu
      ;;
    remove)
      run_remove_menu
      ;;
    *)
      run_install_menu
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
