#!/usr/bin/env bash
set -euo pipefail

REPO="crazy0x70/CyberMonitor"
INSTALL_DIR="/opt/CyberMonitor"
CONF_DIR="/etc/cybermonitor"

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
  local type="$1"
  local version="$2"
  local arch="$3"
  local os="linux"
  local asset="cyber-monitor-${type}-${os}-${arch}"
  local url="https://github.com/${REPO}/releases/download/${version}/${asset}"
  local target="${INSTALL_DIR}/cyber-monitor-${type}"
  mkdir -p "${INSTALL_DIR}"
  curl -fL "${url}" -o "${target}"
  chmod +x "${target}"
  echo "${target}"
}

write_server_conf() {
  mkdir -p "${CONF_DIR}"
  cat > "${CONF_DIR}/server.conf" <<EOF
CM_LISTEN=${1}
CM_DATA_DIR=${2}
EOF
}

write_agent_conf() {
  mkdir -p "${CONF_DIR}"
  cat > "${CONF_DIR}/agent.conf" <<EOF
CM_SERVER_URL=${1}
CM_AGENT_TOKEN=${2}
CM_NET_IFACE=${3}
EOF
}

read_admin_settings() {
  local data_dir="$1"
  local state_file="${data_dir}/state.json"
  local admin_path=""
  local admin_user=""
  local admin_pass=""

  for _ in {1..20}; do
    if [[ -f "${state_file}" ]]; then
      admin_path="$(sed -n 's/.*"admin_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${state_file}" | head -n 1)"
      admin_user="$(sed -n 's/.*"admin_user"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${state_file}" | head -n 1)"
      admin_pass="$(sed -n 's/.*"admin_pass"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${state_file}" | head -n 1)"
      if [[ -n "${admin_path}" && -n "${admin_user}" && -n "${admin_pass}" ]]; then
        break
      fi
    fi
    sleep 1
  done
  if [[ -z "${admin_path}" || -z "${admin_user}" || -z "${admin_pass}" ]]; then
    return 1
  fi
  echo -e "${admin_path}\t${admin_user}\t${admin_pass}"
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
    local public_ip=""
    public_ip="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
    if is_valid_ipv4 "${public_ip}"; then
      host="${public_ip}"
    else
      host="$(hostname -I 2>/dev/null | awk '{print $1}')"
      if [[ -z "${host}" ]]; then
        host="127.0.0.1"
      fi
    fi
  fi
  echo "${host} ${port}"
}

print_admin_info() {
  local listen="$1"
  local data_dir="$2"
  local admin_path admin_user admin_pass
  if ! read -r admin_path admin_user admin_pass < <(read_admin_settings "${data_dir}"); then
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
  echo "初始管理员密码: ${admin_pass}"
}

install_server() {
  local listen="$1"
  local data_dir="$2"
  local version="$3"
  local arch
  arch="$(detect_arch)"
  version="$(resolve_version "${version}")"
  mkdir -p "${data_dir}"

  local bin
  bin="$(download_binary "server" "${version}" "${arch}")"
  write_server_conf "${listen}" "${data_dir}"

  local service="cyber-monitor-server"
  local service_file="/etc/systemd/system/${service}.service"
  cat > "${service_file}" <<EOF
[Unit]
Description=CyberMonitor Server
After=network.target

[Service]
Type=simple
EnvironmentFile=${CONF_DIR}/server.conf
ExecStart=${bin} -listen \${CM_LISTEN} -data-dir \${CM_DATA_DIR}
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${service}"
  echo "已安装并启动 ${service}"
  print_admin_info "${listen}" "${data_dir}"
}

install_agent() {
  local server_url="$1"
  local token="$2"
  local net_iface="$3"
  local version="$4"
  [[ -z "${server_url}" ]] && die "被控需要填写 Server 地址"
  [[ -z "${token}" ]] && die "被控需要填写 Token"

  local arch
  arch="$(detect_arch)"
  version="$(resolve_version "${version}")"

  local bin
  bin="$(download_binary "agent" "${version}" "${arch}")"
  write_agent_conf "${server_url}" "${token}" "${net_iface}"

  local service="cyber-monitor-agent"
  local service_file="/etc/systemd/system/${service}.service"
  local extra_args=""
  if [[ -n "${net_iface}" ]]; then
    extra_args="-net-iface ${net_iface}"
  fi

  cat > "${service_file}" <<EOF
[Unit]
Description=CyberMonitor Agent
After=network.target

[Service]
Type=simple
EnvironmentFile=${CONF_DIR}/agent.conf
ExecStart=${bin} -server-url \${CM_SERVER_URL} -agent-token \${CM_AGENT_TOKEN} ${extra_args}
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${service}"
  echo "已安装并启动 ${service}"
}

uninstall_service() {
  local type="$1"
  local service="cyber-monitor-${type}"
  local service_file="/etc/systemd/system/${service}.service"
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
  fi
  if [[ -z "${data_dir}" ]]; then
    data_dir="/opt/CyberMonitor/data"
  fi
  echo "${data_dir}"
}

cleanup_server_config() {
  local data_dir="$1"
  rm -f "${CONF_DIR}/server.conf"
  if [[ -n "${data_dir}" && "${data_dir}" != "/" ]]; then
    rm -rf "${data_dir}"
  fi
  if [[ -n "${INSTALL_DIR}" && "${INSTALL_DIR}" != "/" ]]; then
    rm -rf "${INSTALL_DIR}"
  fi
  rmdir "${CONF_DIR}" 2>/dev/null || true
}

cleanup_agent_config() {
  rm -f "${CONF_DIR}/agent.conf"
  rmdir "${CONF_DIR}" 2>/dev/null || true
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
        read -r -p "Server 地址(例如 http://1.2.3.4:25012): " server_url
        read -r -p "Agent Token: " token
        read -r -p "指定网卡(可空): " net_iface
        read -r -p "版本号(默认 latest): " version
        install_agent "${server_url}" "${token}" "${net_iface}" "${version}"
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

main "$@"
