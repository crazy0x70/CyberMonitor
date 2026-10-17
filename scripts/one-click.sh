#!/usr/bin/env bash
# CyberMonitor 一键脚本（Linux systemd / macOS launchd）。
#
#   bash one-click.sh                                  交互菜单
#   bash one-click.sh install-server   [--listen :25012] [--data-dir DIR] [--version V]
#   bash one-click.sh install-agent    --server-url URL --agent-token TOKEN
#                                      [--node-id ID] [--net-iface IFACE] [--disable-update] [--version V]
#   bash one-click.sh upgrade-server   [--version V]
#   bash one-click.sh upgrade-agent    [--version V]
#   bash one-click.sh uninstall-server [--keep-data]
#   bash one-click.sh uninstall-agent
#
# Linux 需要 root。macOS 用 sudo 运行安装系统级服务（开机自启），
# 不用 sudo 安装到当前用户（登录自启）。
set -euo pipefail

REPO="crazy0x70/CyberMonitor"
INSTALL_DIR="${INSTALL_DIR:-/opt/CyberMonitor}"
CONF_DIR="${CONF_DIR:-/etc/cybermonitor}"
SYSTEMD_DIR="${SYSTEMD_SERVICE_DIR:-/etc/systemd/system}"
LAUNCHD_DIR="/Library/LaunchDaemons"
LAUNCHD_DOMAIN="system"
LOG_DIR="/var/log"
LABEL_PREFIX="io.github.crazy0x70.cyber-monitor"
DEFAULT_LISTEN=":25012"
OS=""
ARCH=""

die() {
  echo "错误: $*" >&2
  exit 1
}

usage() {
  sed -n '3,14p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true
}

init_platform() {
  case "$(uname -s)" in
    Linux) OS="linux" ;;
    Darwin) OS="darwin" ;;
    *) die "不支持的系统: $(uname -s)" ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) ARCH="amd64" ;;
    aarch64 | arm64) ARCH="arm64" ;;
    armv7l | armv7) ARCH="armv7" ;;
    *) die "不支持的架构: $(uname -m)" ;;
  esac
  command -v curl >/dev/null 2>&1 || die "请先安装 curl"
  if [[ "${OS}" == "linux" ]]; then
    [[ "$(id -u)" -eq 0 ]] || die "请使用 root 运行"
    command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd"
  elif [[ "$(id -u)" -ne 0 ]]; then
    INSTALL_DIR="${HOME}/CyberMonitor"
    CONF_DIR="${HOME}/CyberMonitor/etc"
    LAUNCHD_DIR="${HOME}/Library/LaunchAgents"
    LAUNCHD_DOMAIN="gui/$(id -u)"
    LOG_DIR="${HOME}/Library/Logs"
  fi
}

default_data_dir() {
  echo "${INSTALL_DIR}/data"
}

# ---------- 版本与下载 ----------

resolve_version() {
  local version="${1:-}"
  if [[ -z "${version}" || "${version}" == "latest" ]]; then
    version="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")" ||
      die "无法获取最新版本，请用 --version 指定"
    version="${version##*/}"
    [[ "${version}" != "latest" ]] || die "仓库还没有发布版本"
  fi
  [[ "${version}" == v* ]] || version="v${version}"
  echo "${version}"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# download_binary server|agent VERSION：下载、校验后原子替换 INSTALL_DIR 下的程序。
download_binary() {
  local type="$1" version="$2"
  local asset="cyber-monitor-${type}-${OS}-${ARCH}"
  local base="https://github.com/${REPO}/releases/download/${version}"
  local target="${INSTALL_DIR}/cyber-monitor-${type}"
  local tmp expected
  mkdir -p "${INSTALL_DIR}"
  tmp="$(mktemp "${INSTALL_DIR}/.download.XXXXXX")"
  echo "下载 ${asset} ${version} ..."
  if ! curl -fL --progress-bar "${base}/${asset}" -o "${tmp}"; then
    rm -f "${tmp}"
    die "下载失败: ${base}/${asset}"
  fi
  expected="$(curl -fsSL "${base}/SHA256SUMS" | awk -v a="${asset}" '{n=$2; sub(/^\*/, "", n); if (n == a) {print $1; exit}}')" || true
  if [[ -z "${expected}" || "$(sha256_of "${tmp}")" != "${expected}" ]]; then
    rm -f "${tmp}"
    die "校验失败: ${asset}"
  fi
  chmod 755 "${tmp}"
  mv -f "${tmp}" "${target}"
}

# ---------- 配置文件（KEY=VALUE，每行一项） ----------

# write_conf FILE KEY=VALUE...：Linux 写 systemd EnvironmentFile 的引号格式，macOS 写原值。
write_conf() {
  local file="$1"
  shift
  mkdir -p "$(dirname "${file}")"
  (
    umask 077
    : >"${file}"
    local pair key value
    for pair in "$@"; do
      key="${pair%%=*}"
      value="${pair#*=}"
      if [[ "${OS}" == "linux" ]]; then
        value="${value//\\/\\\\}"
        value="${value//\"/\\\"}"
        value="${value//\$/\\\$}"
        printf '%s="%s"\n' "${key}" "${value}" >>"${file}"
      else
        printf '%s=%s\n' "${key}" "${value}" >>"${file}"
      fi
    done
  )
}

read_conf() {
  local file="$1" key="$2" value
  [[ -f "${file}" ]] || return 0
  value="$(sed -n "s/^${key}=//p" "${file}" | head -n 1)"
  if [[ "${value}" == \"*\" ]]; then
    value="${value:1:${#value}-2}"
    value="${value//\\\$/\$}"
    value="${value//\\\"/\"}"
    value="${value//\\\\/\\}"
  fi
  echo "${value}"
}

# ---------- 服务管理 ----------

xml_escape() {
  local v="$1"
  v="${v//&/&amp;}"
  v="${v//</&lt;}"
  v="${v//>/&gt;}"
  printf '%s' "${v}"
}

# write_service server|agent KEY=VALUE...：写入配置文件与服务定义，然后（重新）启动服务。
write_service() {
  local type="$1"
  shift
  local bin="${INSTALL_DIR}/cyber-monitor-${type}"
  local conf="${CONF_DIR}/${type}.conf"
  write_conf "${conf}" "$@"
  if [[ "${OS}" == "linux" ]]; then
    cat >"${SYSTEMD_DIR}/cyber-monitor-${type}.service" <<EOF
[Unit]
Description=CyberMonitor ${type}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${conf}
ExecStart=${bin}
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "cyber-monitor-${type}" >/dev/null 2>&1
    systemctl restart "cyber-monitor-${type}"
    return
  fi
  local label="${LABEL_PREFIX}-${type}"
  local plist="${LAUNCHD_DIR}/${label}.plist"
  local log="${LOG_DIR}/cybermonitor-${type}.log"
  local env="" pair
  for pair in "$@"; do
    env+="    <key>$(xml_escape "${pair%%=*}")</key><string>$(xml_escape "${pair#*=}")</string>"$'\n'
  done
  mkdir -p "${LAUNCHD_DIR}" "${LOG_DIR}"
  cat >"${plist}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array><string>$(xml_escape "${bin}")</string></array>
  <key>EnvironmentVariables</key>
  <dict>
${env}  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$(xml_escape "${log}")</string>
  <key>StandardErrorPath</key><string>$(xml_escape "${log}")</string>
</dict>
</plist>
EOF
  launchctl bootout "${LAUNCHD_DOMAIN}" "${plist}" >/dev/null 2>&1 || true
  # bootout 是异步的，旧实例未卸载完时 bootstrap 会失败，稍等重试。
  local i
  for i in 1 2 3 4 5; do
    launchctl bootstrap "${LAUNCHD_DOMAIN}" "${plist}" 2>/dev/null && return
    sleep 1
  done
  launchctl bootstrap "${LAUNCHD_DOMAIN}" "${plist}"
}

restart_service() {
  local type="$1"
  if [[ "${OS}" == "linux" ]]; then
    systemctl restart "cyber-monitor-${type}"
  else
    launchctl kickstart -k "${LAUNCHD_DOMAIN}/${LABEL_PREFIX}-${type}"
  fi
}

remove_service() {
  local type="$1"
  if [[ "${OS}" == "linux" ]]; then
    systemctl disable --now "cyber-monitor-${type}" >/dev/null 2>&1 || true
    rm -f "${SYSTEMD_DIR}/cyber-monitor-${type}.service"
    systemctl daemon-reload
  else
    local plist="${LAUNCHD_DIR}/${LABEL_PREFIX}-${type}.plist"
    launchctl bootout "${LAUNCHD_DOMAIN}" "${plist}" >/dev/null 2>&1 || true
    rm -f "${plist}" "${LOG_DIR}/cybermonitor-${type}.log"
  fi
}

# ---------- Server ----------

install_server() {
  local listen="$1" data_dir="$2" version i
  local conf="${CONF_DIR}/server.conf"
  # 重装时沿用已有配置，避免端口和数据目录被默认值覆盖。
  [[ -n "${listen}" ]] || listen="$(read_conf "${conf}" CM_LISTEN)"
  [[ -n "${data_dir}" ]] || data_dir="$(read_conf "${conf}" CM_DATA_DIR)"
  listen="${listen:-${DEFAULT_LISTEN}}"
  data_dir="${data_dir:-$(default_data_dir)}"
  version="$(resolve_version "$3")"

  local admin_pass=""
  if [[ ! -f "${data_dir}/state.json" ]]; then
    admin_pass="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
  fi
  mkdir -p "${data_dir}"
  download_binary server "${version}"
  if [[ -z "${admin_pass}" ]]; then
    write_service server "CM_LISTEN=${listen}" "CM_DATA_DIR=${data_dir}"
  else
    write_service server "CM_LISTEN=${listen}" "CM_DATA_DIR=${data_dir}" "CM_ADMIN_PASS=${admin_pass}"
    # 首次启动写出 state.json 后，去掉配置里的明文密码再重启。
    for i in $(seq 1 30); do
      [[ -f "${data_dir}/state.json" ]] && break
      sleep 1
    done
    write_service server "CM_LISTEN=${listen}" "CM_DATA_DIR=${data_dir}"
  fi
  for i in $(seq 1 10); do
    curl -fs -o /dev/null "http://127.0.0.1:${listen##*:}/api/v1/health" && break
    sleep 1
  done

  local admin_path="" admin_user=""
  if [[ -f "${data_dir}/state.json" ]]; then
    admin_path="$(sed -n 's/.*"admin_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${data_dir}/state.json" | head -n 1)"
    admin_user="$(sed -n 's/.*"admin_user"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${data_dir}/state.json" | head -n 1)"
  fi
  echo
  echo "CyberMonitor Server ${version} 已安装并启动"
  echo "  状态页:   http://<服务器IP>:${listen##*:}/"
  [[ -z "${admin_path}" ]] || echo "  管理后台: http://<服务器IP>:${listen##*:}/${admin_path#/}"
  [[ -z "${admin_user}" ]] || echo "  用户名:   ${admin_user}"
  if [[ -n "${admin_pass}" ]]; then
    echo "  密码:     ${admin_pass}（只显示这一次，请登录后修改）"
  fi
  echo "  数据目录: ${data_dir}"
}

uninstall_server() {
  local keep_data="$1"
  local data_dir
  data_dir="$(read_conf "${CONF_DIR}/server.conf" CM_DATA_DIR)"
  data_dir="${data_dir:-$(default_data_dir)}"
  remove_service server
  rm -f "${INSTALL_DIR}/cyber-monitor-server" "${CONF_DIR}/server.conf"
  if [[ "${keep_data}" == "1" ]]; then
    echo "已保留数据目录: ${data_dir}"
  elif [[ "${data_dir}" == "$(default_data_dir)" ]]; then
    rm -rf "${data_dir}"
  else
    echo "自定义数据目录未删除，如不再需要请手动删除: ${data_dir}"
  fi
  rmdir "${CONF_DIR}" "${INSTALL_DIR}" 2>/dev/null || true
  echo "已卸载 CyberMonitor Server"
}

# ---------- Agent ----------

install_agent() {
  local server_url="${1%/}" token="$2" node_id="$3" net_iface="$4" disable_update="$5" version
  [[ -n "${server_url}" ]] || die "缺少 --server-url"
  [[ -n "${token}" ]] || die "缺少 --agent-token"
  local id_file="${INSTALL_DIR}/.cybermonitor-node-id"
  local token_file="${INSTALL_DIR}/.cybermonitor-agent-token"
  if [[ -z "${node_id}" && -f "${id_file}" ]]; then
    node_id="$(head -n 1 "${id_file}" | tr -d '\r\n')"
  fi
  if [[ -z "${node_id}" ]]; then
    node_id="node-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  fi
  version="$(resolve_version "$6")"

  # 用接入 Token 换取本节点专属凭据。
  local response node_token
  response="$(curl -fsS -X POST -H "X-AGENT-TOKEN: ${token}" \
    "${server_url}/api/v1/agent/register?node_id=${node_id}")" ||
    die "注册失败，请检查 Server 地址与 Agent Token"
  node_token="$(printf '%s' "${response}" | sed -n 's/.*"agent_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  [[ -n "${node_token}" ]] || die "注册失败：服务端未返回节点凭据"

  download_binary agent "${version}"
  (
    umask 077
    printf '%s\n' "${node_id}" >"${id_file}"
    printf '%s\n' "${node_token}" >"${token_file}"
  )
  local env=("CM_SERVER_URL=${server_url}" "CM_NODE_ID_FILE=${id_file}" "CM_AGENT_TOKEN_FILE=${token_file}")
  [[ -z "${net_iface}" ]] || env+=("CM_NET_IFACE=${net_iface}")
  [[ "${disable_update}" != "1" ]] || env+=("CM_DISABLE_UPDATE=1")
  write_service agent "${env[@]}"
  echo
  echo "CyberMonitor Agent ${version} 已安装并启动"
  echo "  Node ID: ${node_id}"
}

uninstall_agent() {
  remove_service agent
  rm -f "${INSTALL_DIR}/cyber-monitor-agent" "${CONF_DIR}/agent.conf" \
    "${INSTALL_DIR}/.cybermonitor-node-id" "${INSTALL_DIR}/.cybermonitor-agent-token"
  rmdir "${CONF_DIR}" "${INSTALL_DIR}" 2>/dev/null || true
  echo "已卸载 CyberMonitor Agent"
}

# ---------- 升级 ----------

upgrade() {
  local type="$1" version
  [[ -x "${INSTALL_DIR}/cyber-monitor-${type}" ]] || die "未找到已安装的 ${type}: ${INSTALL_DIR}/cyber-monitor-${type}"
  version="$(resolve_version "$2")"
  download_binary "${type}" "${version}"
  restart_service "${type}"
  echo "CyberMonitor ${type} 已升级到 ${version}"
}

# ---------- 入口 ----------

ask() {
  local prompt="$1" default="${2:-}" answer
  read -r -p "${prompt}" answer
  echo "${answer:-${default}}"
}

menu() {
  echo "CyberMonitor 一键脚本"
  echo "  1) 安装 Server        2) 安装 Agent"
  echo "  3) 升级 Server        4) 升级 Agent"
  echo "  5) 卸载 Server        6) 卸载 Agent"
  echo "  0) 退出"
  case "$(ask '请选择: ')" in
    1)
      install_server "$(ask "监听地址 [${DEFAULT_LISTEN}]: ")" "$(ask "数据目录 [$(default_data_dir)]: ")" ""
      ;;
    2)
      local url token
      url="$(ask 'Server 地址（例如 http://1.2.3.4:25012）: ')"
      token="$(ask 'Agent Token: ')"
      install_agent "${url}" "${token}" "" "" "0" ""
      ;;
    3) upgrade server "" ;;
    4) upgrade agent "" ;;
    5)
      local keep="0"
      [[ "$(ask '保留数据目录? [y/N]: ')" =~ ^[Yy] ]] && keep="1"
      uninstall_server "${keep}"
      ;;
    6) uninstall_agent ;;
    0) exit 0 ;;
    *) die "无效选项" ;;
  esac
}

need_value() {
  [[ -n "${2:-}" && "${2}" != --* ]] || die "$1 需要参数"
}

main() {
  local cmd="${1:-}"
  [[ $# -eq 0 ]] || shift
  case "${cmd}" in
    -h | --help | help)
      usage
      return
      ;;
  esac
  init_platform

  local listen="" data_dir="" version="" server_url="" token="" node_id="" net_iface="" disable_update="0" keep_data="0"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --listen) need_value "$@"; listen="$2"; shift 2 ;;
      --data-dir) need_value "$@"; data_dir="$2"; shift 2 ;;
      --version) need_value "$@"; version="$2"; shift 2 ;;
      --server-url) need_value "$@"; server_url="$2"; shift 2 ;;
      --agent-token) need_value "$@"; token="$2"; shift 2 ;;
      --node-id) need_value "$@"; node_id="$2"; shift 2 ;;
      --net-iface) need_value "$@"; net_iface="$2"; shift 2 ;;
      --disable-update) disable_update="1"; shift ;;
      --keep-data) keep_data="1"; shift ;;
      *) die "未知参数: $1" ;;
    esac
  done

  case "${cmd}" in
    "" | install | remove | uninstall) menu ;;
    install-server) install_server "${listen}" "${data_dir}" "${version}" ;;
    install-agent) install_agent "${server_url}" "${token}" "${node_id}" "${net_iface}" "${disable_update}" "${version}" ;;
    upgrade-server) upgrade server "${version}" ;;
    upgrade-agent) upgrade agent "${version}" ;;
    uninstall-server) uninstall_server "${keep_data}" ;;
    uninstall-agent) uninstall_agent ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
