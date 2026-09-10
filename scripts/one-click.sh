#!/usr/bin/env bash
# CyberMonitor 一键安装/卸载脚本（Linux systemd + macOS launchd，单文件自包含）。
# 用法：
#   bash one-click.sh                                # 交互菜单
#   bash one-click.sh install-server  [--listen 25012] [--data-dir DIR] [--version V]
#   bash one-click.sh install-agent   --server-url URL --agent-token T
#                                     [--node-id N] [--net-iface I] [--disable-update] [--version V]
#   bash one-click.sh uninstall-server [--keep-data]
#   bash one-click.sh uninstall-agent
# 说明：
#   Linux 需要 root（systemd）。macOS 以 sudo 运行安装系统级服务（LaunchDaemons，
#   开机自启）；普通用户运行安装用户级服务（LaunchAgents，登录自启）。
set -euo pipefail

# ============================================================
# 通用库：路径防呆 / 版本解析 / 下载校验 / 备份回滚（原 install-common.sh）
# ============================================================


REPO="crazy0x70/CyberMonitor"
INSTALL_DIR="${INSTALL_DIR:-/opt/CyberMonitor}"
CONF_DIR="${CONF_DIR:-/etc/cybermonitor}"
SYSTEMD_SERVICE_DIR="${SYSTEMD_SERVICE_DIR:-/etc/systemd/system}"
MACOS_LAUNCHD_DIR="${MACOS_LAUNCHD_DIR:-/Library/LaunchDaemons}"
LAST_BINARY_BACKUP=""
LAST_BINARY_TARGET=""
LAST_BINARY_INSTALLED="0"

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

detect_os() {
  case "$(uname -s)" in
    Linux) echo "linux" ;;
    Darwin) echo "macos" ;;
    *) die "不支持的操作系统: $(uname -s)" ;;
  esac
}

# macOS 普通用户安装时重定向到用户目录（系统目录不可写）：
# 程序 ~/CyberMonitor、plist ~/Library/LaunchAgents（登录自启）。
# root 安装保持 /opt/CyberMonitor + /Library/LaunchDaemons（开机自启）。
normalize_macos_user_paths() {
  [[ "$(uname -s)" == "Darwin" && "$(id -u)" -ne 0 ]] || return 0
  INSTALL_DIR="${HOME}/CyberMonitor"
  CONF_DIR="${HOME}/CyberMonitor/etc"
  MACOS_LAUNCHD_DIR="${HOME}/Library/LaunchAgents"
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
  local version
  version="$(normalize_release_version "$1")"
  if [[ -n "${version}" ]]; then
    echo "${version}"
    return
  fi
  local latest_url=""
  if latest_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" 2>/dev/null)"; then
    version="${latest_url##*/}"
    if [[ "${version}" == "latest" ]]; then
      version=""
    fi
  fi
  if [[ -z "${version}" ]]; then
    if ! version="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"; then
      version=""
    fi
  fi
  if [[ -z "${version}" ]]; then
    die "无法获取最新版本，请使用版本号手动指定"
  fi
  normalize_release_version "${version}"
}

normalize_release_version() {
  local version="$1"
  version="${version#"${version%%[![:space:]]*}"}"
  version="${version%"${version##*[![:space:]]}"}"
  if [[ -z "${version}" ]]; then
    echo ""
    return 0
  fi
  # macOS 自带 bash 3.2 无 ${var,,} 展开，用 tr 兼容。
  local version_lower
  version_lower="$(printf '%s' "${version}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${version_lower}" == "latest" || "${version_lower}" == "vlatest" ]]; then
    echo ""
    return 0
  fi
  if [[ "${version}" =~ ^v?[0-9]+(\.[0-9]+){2}([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
    if [[ "${version}" != v* ]]; then
      version="v${version}"
    fi
    echo "${version}"
    return 0
  fi
  echo "版本号必须形如 v0.1.0 或 v0.1.0-rc.1" >&2
  return 1
}

urlencode() {
  local raw="$1"
  local out=""
  local char
  local encoded
  local i
  for ((i = 0; i < ${#raw}; i++)); do
    char="${raw:i:1}"
    case "${char}" in
      [a-zA-Z0-9.~_-])
        out+="${char}"
        ;;
      *)
        printf -v encoded '%%%02X' "'${char}"
        out+="${encoded}"
        ;;
    esac
  done
  printf '%s' "${out}"
}

systemd_env_escape() {
  local value="$1"
  if [[ "${value}" == *$'\n'* || "${value}" == *$'\r'* ]]; then
    echo "EnvironmentFile value must not contain newlines" >&2
    return 1
  fi
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//\$/\\\$}"
  value="${value//\`/\\\`}"
  printf '"%s"' "${value}"
}

write_systemd_env() {
  local key="$1"
  local value="$2"
  local escaped
  escaped="$(systemd_env_escape "${value}")" || return 1
  printf '%s=%s\n' "${key}" "${escaped}"
}

validate_systemd_env_value() {
  systemd_env_escape "$1" >/dev/null
}

validate_systemd_unit_path_value() {
  local name="$1"
  local value="$2"
  if [[ -z "${value}" ]]; then
    echo "${name} must not be empty" >&2
    return 1
  fi
  if [[ "${value}" == *[[:space:]]* || "${value}" == *[[:cntrl:]]* ]]; then
    echo "${name} must not contain whitespace or control characters: ${value}" >&2
    return 1
  fi
  if [[ "${value}" == *%* ]]; then
    echo "${name} must not contain systemd specifier characters: ${value}" >&2
    return 1
  fi
}

validate_systemd_unit_paths() {
  validate_systemd_unit_path_value "INSTALL_DIR" "${INSTALL_DIR}" &&
    validate_systemd_unit_path_value "CONF_DIR" "${CONF_DIR}" &&
    validate_systemd_unit_path_value "SYSTEMD_SERVICE_DIR" "${SYSTEMD_SERVICE_DIR}"
}

validate_private_state_value() {
  local value="$1"
  [[ -n "${value}" ]] || {
    echo "file value required" >&2
    return 1
  }
}

validate_agent_local_config() {
  local server_url="$1"
  local node_id="$2"
  local net_iface="$3"
  local disable_update="$4"
  local node_token="${5:-placeholder-token}"
  validate_private_state_value "${node_id}" &&
    validate_private_state_value "${node_token}" &&
    validate_systemd_env_value "${server_url}" &&
    validate_systemd_env_value "${INSTALL_DIR}/.cybermonitor-node-id" &&
    validate_systemd_env_value "${INSTALL_DIR}/.cybermonitor-agent-token" &&
    validate_systemd_env_value "${net_iface}" &&
    validate_systemd_env_value "${disable_update}"
}

strip_systemd_env_quotes() {
  local value="$1"
  if [[ "${value}" == \"*\" && "${value}" == *\" ]]; then
    value="${value:1:${#value}-2}"
    value="${value//\\\"/\"}"
    value="${value//\\\\/\\}"
    value="${value//\\\$/\$}"
    value="${value//\\\`/\`}"
  fi
  printf '%s' "${value}"
}

function reject_unsafe_path() {
  local path="$1"
  local allow_leaf="${2:-}"
  local current=""
  local part
  local remaining
  if [[ -z "${path}" ]]; then
    return 0
  fi
  case "/${path}/" in
    *"/../"*)
      echo "refuses unsafe path traversal: ${path}" >&2
      return 1
      ;;
  esac
  case "${path}" in
    /*) ;;
    *) path="$(pwd)/${path}" ;;
  esac
  remaining="${path#/}"
  while [[ -n "${remaining}" ]]; do
    part="${remaining%%/*}"
    if [[ "${part}" == "${remaining}" ]]; then
      remaining=""
    else
      remaining="${remaining#*/}"
    fi
    [[ -n "${part}" ]] || continue
    if [[ -z "${current}" ]]; then
      current="/${part}"
    else
      current="${current}/${part}"
    fi
    if [[ -L "${current}" ]]; then
      # macOS 系统标准链接（/etc /opt /tmp /var -> /private/<同名>）放行：
      # 解析为物理路径继续验证剩余分量；其余 symlink 一律拒绝（防写入重定向）。
      local link_target
      link_target="$(readlink "${current}" 2>/dev/null || true)"
      if [[ -n "${link_target}" && ( "${link_target}" == "/private/${part}" || "${link_target}" == "private/${part}" ) ]]; then
        current="${link_target}"
      else
        if [[ "${allow_leaf}" == "allow-leaf" && -z "${remaining}" ]]; then
          return 0
        fi
        echo "refuses symbolic link path: ${current}" >&2
        return 1
      fi
    fi
    if [[ ! -e "${current}" ]]; then
      return 0
    fi
  done
}

verify_asset_checksum() {
  local version="$1"
  local asset="$2"
  local target="$3"
  local sums_url="https://github.com/${REPO}/releases/download/${version}/SHA256SUMS"
  local sums_file
  local expected=""
  local actual=""
  sums_file="$(mktemp)" || return 1
  if ! curl -fL "${sums_url}" -o "${sums_file}"; then
    rm -f "${sums_file}"
    echo "无法下载 SHA256SUMS；该版本可能不包含校验文件，请改用包含 SHA256SUMS 的新版本或对应旧安装脚本" >&2
    return 1
  fi
  expected="$(awk -v asset="${asset}" '{ name = $2; sub(/^\*/, "", name); if (name == asset) { print $1; exit } }' "${sums_file}")"
  if [[ -z "${expected}" ]]; then
    rm -f "${sums_file}"
    echo "SHA256SUMS 中未找到 ${asset}；请确认版本与安装脚本匹配" >&2
    return 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${target}" | awk '{ print $1 }')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "${target}" | awk '{ print $1 }')"
  else
    rm -f "${sums_file}"
    echo "请先安装 sha256sum 或 shasum 以校验下载文件" >&2
    return 1
  fi
  rm -f "${sums_file}"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "下载文件校验失败: ${asset}" >&2
    return 1
  fi
}

download_binary() {
  local type="$1"
  local version="$2"
  local arch="$3"
  local output_var="$4"
  local os
  os="$(detect_os)"
  local asset_os="${os}"
  # release 资产命名沿用 GOOS（darwin），detect_os 的 macos 需要映射。
  if [[ "${os}" == "macos" ]]; then
    asset_os="darwin"
  fi
  local asset="cyber-monitor-${type}-${asset_os}-${arch}"
  local url="https://github.com/${REPO}/releases/download/${version}/${asset}"
  local target="${INSTALL_DIR}/cyber-monitor-${type}"
  local backup=""
  local tmp_target
  LAST_BINARY_BACKUP=""
  LAST_BINARY_TARGET=""
  LAST_BINARY_INSTALLED="0"
  reject_unsafe_path "${INSTALL_DIR}" || return 1
  mkdir -p "${INSTALL_DIR}"
  if [[ -L "${target}" ]]; then
    echo "refuses symbolic link binary target: ${target}" >&2
    return 1
  fi
  reject_unsafe_path "${target}" || return 1
  tmp_target="$(mktemp "${INSTALL_DIR}/.cyber-monitor-${type}.XXXXXX")" || {
    echo "无法创建临时下载文件" >&2
    return 1
  }
  if ! curl -fL "${url}" -o "${tmp_target}"; then
    rm -f "${tmp_target}"
    echo "下载 ${asset} 失败" >&2
    return 1
  fi
  if ! verify_asset_checksum "${version}" "${asset}" "${tmp_target}"; then
    rm -f "${tmp_target}"
    echo "下载文件校验失败: ${asset}" >&2
    return 1
  fi
  if ! chmod 755 "${tmp_target}"; then
    rm -f "${tmp_target}"
    echo "无法设置 ${asset} 可执行权限" >&2
    return 1
  fi
  if [[ -e "${target}" ]]; then
    backup="$(mktemp "${INSTALL_DIR}/.cyber-monitor-${type}.backup.XXXXXX")" || {
      rm -f "${tmp_target}"
      echo "无法创建 ${asset} 回滚备份" >&2
      return 1
    }
    if ! cp -p "${target}" "${backup}"; then
      rm -f "${tmp_target}" "${backup}"
      echo "无法备份现有 ${asset}" >&2
      return 1
    fi
    LAST_BINARY_BACKUP="${backup}"
    LAST_BINARY_TARGET="${target}"
  fi
  if ! mv -f "${tmp_target}" "${target}"; then
    rm -f "${LAST_BINARY_BACKUP}"
    LAST_BINARY_BACKUP=""
    LAST_BINARY_TARGET=""
    LAST_BINARY_INSTALLED="0"
    rm -f "${tmp_target}"
    echo "无法安装 ${asset}" >&2
    return 1
  fi
  LAST_BINARY_INSTALLED="1"
  printf -v "${output_var}" '%s' "${target}"
}

function backup_file_if_exists() {
  local path="$1"
  local output_var="$2"
  local backup=""
  if [[ -L "${path}" ]]; then
    echo "refuses symbolic link backup target: ${path}" >&2
    return 1
  fi
  reject_unsafe_path "${path}" || return 1
  if [[ -f "${path}" ]]; then
    backup="$(mktemp "${path}.backup.XXXXXX")" || {
      echo "无法创建 ${path} 回滚备份" >&2
      return 1
    }
    if ! cp -p "${path}" "${backup}"; then
      rm -f "${backup}"
      echo "无法备份 ${path}" >&2
      return 1
    fi
  fi
  printf -v "${output_var}" '%s' "${backup}"
}

function restore_file_backup() {
  local path="$1"
  local backup="$2"
  reject_unsafe_path "${path}" allow-leaf || return 1
  if [[ -n "${backup}" && -f "${backup}" ]]; then
    reject_unsafe_path "${backup}" || return 1
    rm -f "${path}" || return 1
    if ! mv -f "${backup}" "${path}"; then
      echo "无法恢复 ${path}" >&2
      return 1
    fi
    return 0
  fi
  rm -f "${path}"
}

function cleanup_file_backup() {
  local backup="$1"
  if [[ -n "${backup}" ]]; then
    rm -f "${backup}"
  fi
}

function rollback_install_failure() {
  local type="$1"
  local service="$2"
  local token_file="$3"
  local token_backup="$4"
  local conf_file="$5"
  local conf_backup="$6"
  local service_file="$7"
  local service_backup="$8"
  local service_existed="$9"
  local service_enabled="${10}"
  local service_active="${11}"
  if [[ -n "${token_file}" ]]; then
    restore_file_backup "${token_file}" "${token_backup}" || true
  fi
  restore_file_backup "${conf_file}" "${conf_backup}" || true
  restore_file_backup "${service_file}" "${service_backup}" || true
  restore_binary_backup "${type}" &&
    restore_service_state "${service}" "${service_existed}" "${service_enabled}" "${service_active}"
}

function restore_binary_backup() {
  local type="$1"
  local target="${LAST_BINARY_TARGET:-${INSTALL_DIR}/cyber-monitor-${type}}"
  if [[ "${LAST_BINARY_INSTALLED}" != "1" ]]; then
    return 0
  fi
  if [[ -n "${LAST_BINARY_BACKUP}" && -f "${LAST_BINARY_BACKUP}" ]]; then
    if ! mv -f "${LAST_BINARY_BACKUP}" "${target}"; then
      echo "无法恢复旧二进制: ${target}" >&2
      return 1
    fi
  else
    rm -f "${target}"
  fi
  LAST_BINARY_BACKUP=""
  LAST_BINARY_TARGET=""
  LAST_BINARY_INSTALLED="0"
}

function cleanup_binary_backup() {
  if [[ -n "${LAST_BINARY_BACKUP}" ]]; then
    rm -f "${LAST_BINARY_BACKUP}"
  fi
  LAST_BINARY_BACKUP=""
  LAST_BINARY_TARGET=""
  LAST_BINARY_INSTALLED="0"
}

function capture_service_state() {
  local service="$1"
  local existed_var="$2"
  local enabled_var="$3"
  local active_var="$4"
  local existed="0"
  local enabled="0"
  local active="0"
  if systemctl status "${service}" >/dev/null 2>&1 || systemctl cat "${service}" >/dev/null 2>&1; then
    existed="1"
  fi
  if systemctl is-enabled --quiet "${service}" >/dev/null 2>&1; then
    enabled="1"
  fi
  if systemctl is-active --quiet "${service}" >/dev/null 2>&1; then
    active="1"
  fi
  printf -v "${existed_var}" '%s' "${existed}"
  printf -v "${enabled_var}" '%s' "${enabled}"
  printf -v "${active_var}" '%s' "${active}"
}

function restore_service_state() {
  local service="$1"
  local existed="$2"
  local enabled="$3"
  local active="$4"
  systemctl daemon-reload || return 1
  if [[ "${existed}" != "1" ]]; then
    systemctl disable --now "${service}" >/dev/null 2>&1 || true
    return 0
  fi
  if [[ "${enabled}" == "1" ]]; then
    systemctl enable "${service}" || return 1
  else
    systemctl disable "${service}" >/dev/null 2>&1 || true
  fi
  if [[ "${active}" == "1" ]]; then
    if ! systemctl restart "${service}"; then
      echo "已恢复旧文件，但无法重新启动 ${service}" >&2
      return 1
    fi
    if ! systemctl is-active --quiet "${service}"; then
      echo "已恢复旧文件，但 ${service} 未处于运行状态" >&2
      return 1
    fi
  else
    systemctl stop "${service}" >/dev/null 2>&1 || true
  fi
}

write_private_state_file() {
  local path="$1"
  local value="$2"
  local dir
  local tmp_target
  if [[ -L "${path}" ]]; then
    echo "refuses symbolic link state target: ${path}" >&2
    return 1
  fi
  reject_unsafe_path "${path}" || return 1
  dir="$(dirname "${path}")"
  mkdir -p "${dir}" || return 1
  tmp_target="$(mktemp "${dir}/.$(basename "${path}").XXXXXX")" || return 1
  if ! printf '%s\n' "${value}" > "${tmp_target}"; then
    rm -f "${tmp_target}"
    return 1
  fi
  if ! chmod 600 "${tmp_target}"; then
    rm -f "${tmp_target}"
    return 1
  fi
  if [[ -L "${path}" ]]; then
    rm -f "${tmp_target}"
    echo "refuses symbolic link state target: ${path}" >&2
    return 1
  fi
  reject_unsafe_path "${path}" || {
    rm -f "${tmp_target}"
    return 1
  }
  if ! mv -f "${tmp_target}" "${path}"; then
    rm -f "${tmp_target}"
    return 1
  fi
}

write_agent_token_file() {
  local token="$1"
  write_private_state_file "${INSTALL_DIR}/.cybermonitor-agent-token" "${token}"
}

write_node_id_file() {
  local node_id="$1"
  write_private_state_file "${INSTALL_DIR}/.cybermonitor-node-id" "${node_id}"
}

resolve_node_id() {
  local explicit="$1"
  local node_id_file="${INSTALL_DIR}/.cybermonitor-node-id"
  local existing=""
  if [[ -n "${explicit}" ]]; then
    echo "${explicit}"
    return
  fi
  if [[ -f "${node_id_file}" ]]; then
    existing="$(head -n 1 "${node_id_file}" | tr -d '\r\n')"
  fi
  if [[ -n "${existing}" ]]; then
    echo "${existing}"
    return
  fi
  generate_node_id
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
  # 安装阶段首次注册仍走 HTTP；安装完成后的 Agent 运行态会对同一 server-url 优先尝试 gRPC。
  local endpoint="${server_url%/}/api/v1/agent/register?node_id=$(urlencode "${node_id}")"
  local response
  response="$(curl -fsSL -X POST -H "X-AGENT-TOKEN: ${bootstrap_token}" "${endpoint}")" || \
    {
      echo "Agent 注册失败，请检查 Server 地址与 Agent Token" >&2
      return 1
    }
  local node_token
  node_token="$(printf '%s' "${response}" | sed -n 's/.*"agent_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  if [[ -z "${node_token}" ]]; then
    echo "Agent 注册成功但未返回专属凭据" >&2
    return 1
  fi
  echo "${node_token}"
}


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

default_server_data_dir() {
  if [[ "$(detect_os)" == "macos" && "$(id -u)" -ne 0 ]]; then
    printf '%s/CyberMonitor/data' "${HOME}"
  else
    printf '%s' "/opt/CyberMonitor/data"
  fi
}

SERVER_DATA_OWNED_MARKER=".cybermonitor-server-data"

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

# 等待首次启动完成（state.json 持久化），最多 30 秒。
wait_for_state_file() {
  local data_dir="$1"
  local state_file="${data_dir}/state.json"
  for _ in {1..30}; do
    if [[ -f "${state_file}" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "警告：等待 ${state_file} 生成超时，继续执行后续步骤。" >&2
  return 0
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
  if [[ -n "${admin_pass}" ]]; then
    # 等首次启动把 state.json 落盘后再剥离密码重启；否则第二次启动可能在
    # 初始化完成前进行，服务端会重新生成随机密码，而脚本打印的将是已失效的旧密码。
    wait_for_state_file "${data_dir}"
    if ! write_server_conf "${listen}" "${data_dir}" || ! systemctl restart "${service}"; then
      if ! rollback_install_failure "server" "${service}" "" "" "${CONF_DIR}/server.conf" "${conf_backup}" "${service_file}" "${service_backup}" "${service_existed}" "${service_enabled}" "${service_active}"; then
        cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
        die "清理 ${service} 初始管理员密码失败；回滚后服务仍未运行"
      fi
      cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
      die "安装 ${service} 失败，已执行回滚流程"
    fi
  fi
  cleanup_file_backup "${conf_backup}"
  cleanup_file_backup "${service_backup}"
  cleanup_binary_backup
  echo "已安装并启动 ${service}"
  print_admin_info "${listen}" "${data_dir}" "${admin_pass}"
}

install_agent_linux() {
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
  uninstall_service_dispatch "server"
  if [[ ! "${keep}" =~ ^[Yy]$ ]]; then
    cleanup_server_config "${data_dir}"
  fi
}

uninstall_agent() {
  uninstall_service_dispatch "agent"
  cleanup_agent_config
}

run_install_menu() {
  while true; do
    print_install_menu
    read -r -p "请选择: " choice
    case "${choice}" in
      1)
        read -r -p "监听地址(默认 25012): " listen
        read -r -p "数据目录(默认 $(default_server_data_dir)): " data_dir
        read -r -p "版本号(默认 latest): " version
        listen="${listen:-25012}"
        data_dir="${data_dir:-$(default_server_data_dir)}"
        install_server_dispatch "${listen}" "${data_dir}" "${version}"
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
        install_agent_dispatch "${server_url}" "${token}" "${node_id}" "${net_iface}" "${disable_update}" "${version}"
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

# ============================================================
# macOS launchd 支持：Agent 与 Server 共用的服务管理
# ============================================================

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

MACOS_SERVER_LABEL="io.github.crazy0x70.cyber-monitor-server"

write_server_conf_macos() {
  local listen="$1"
  local data_dir="$2"
  local admin_pass="${3:-}"
  mkdir -p "${CONF_DIR}"
  {
    echo "CM_LISTEN=${listen}"
    echo "CM_DATA_DIR=${data_dir}"
    [[ -z "${admin_pass}" ]] || echo "CM_ADMIN_PASS=${admin_pass}"
  } > "${CONF_DIR}/server.conf"
  chmod 600 "${CONF_DIR}/server.conf" 2>/dev/null || true
}

write_server_launchd_plist() {
  local plist_path="$1"
  local bin="$2"
  local listen="$3"
  local data_dir="$4"
  local admin_pass="${5:-}"
  local extra_env=""
  if [[ -n "${admin_pass}" ]]; then
    extra_env="        <key>CM_ADMIN_PASS</key>
        <string>$(plist_escape "${admin_pass}")</string>"
  fi
  local log_path
  log_path="$(macos_agent_log_path | sed 's/agent\.log/server.log/')"
  cat > "${plist_path}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${MACOS_SERVER_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${bin}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>CM_LISTEN</key>
        <string>$(plist_escape "${listen}")</string>
        <key>CM_DATA_DIR</key>
        <string>$(plist_escape "${data_dir}")</string>${extra_env}
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

macos_launchd_service_running() {
  local label="$1"
  sleep 1
  launchctl print "$(macos_launchd_domain)/${label}" 2>/dev/null | grep -q 'state = running'
}

macos_bootout_plist() {
  local plist_path="$1"
  launchctl bootout "$(macos_launchd_domain)" "${plist_path}" >/dev/null 2>&1 || true
}

install_server_macos() {
  local listen="$1"
  local data_dir="$2"
  local version="$3"
  normalize_macos_user_paths
  reject_unsafe_path "${data_dir}" || die "数据目录包含不安全路径"
  local arch
  arch="$(detect_arch)"
  version="$(resolve_version "${version}")"
  local admin_pass=""
  if [[ ! -f "${data_dir}/state.json" ]]; then
    admin_pass="$(generate_admin_password)" || die "生成管理员初始密码失败"
  fi
  local data_dir_created=""
  [[ -e "${data_dir}" ]] || data_dir_created="1"
  mkdir -p "${data_dir}"
  if [[ "${data_dir_created}" == "1" ]] && ! mark_server_data_dir_owned "${data_dir}"; then
    cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
    die "安装 cyber-monitor-server 失败，无法标记数据目录归属"
  fi

  local plist_dir
  plist_dir="$(macos_launchd_dir)"
  mkdir -p "${plist_dir}"
  local plist_path="${plist_dir}/${MACOS_SERVER_LABEL}.plist"
  local conf_backup=""
  local plist_backup=""
  if ! backup_file_if_exists "${CONF_DIR}/server.conf" conf_backup ||
    ! backup_file_if_exists "${plist_path}" plist_backup; then
    cleanup_file_backup "${conf_backup}"
    cleanup_file_backup "${plist_backup}"
    cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
    die "安装 cyber-monitor-server 失败，无法创建回滚备份"
  fi

  local bin
  if ! download_binary "server" "${version}" "${arch}" bin ||
    ! write_server_conf_macos "${listen}" "${data_dir}" "${admin_pass}" ||
    ! write_server_launchd_plist "${plist_path}" "${bin}" "${listen}" "${data_dir}" "${admin_pass}" ||
    ! enable_launchd_service "${plist_path}" ||
    ! macos_launchd_service_running "${MACOS_SERVER_LABEL}"; then
    macos_bootout_plist "${plist_path}"
    restore_file_backup "${CONF_DIR}/server.conf" "${conf_backup}" || true
    restore_file_backup "${plist_path}" "${plist_backup}" || true
    restore_binary_backup "server" || true
    if [[ -n "${plist_backup}" ]]; then
      launchctl bootstrap "$(macos_launchd_domain)" "${plist_path}" >/dev/null 2>&1 || true
    fi
    cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
    die "安装 cyber-monitor-server 失败，已执行回滚流程"
  fi
  if [[ -n "${admin_pass}" ]]; then
    wait_for_state_file "${data_dir}"
    if ! write_server_conf_macos "${listen}" "${data_dir}" ||
      ! write_server_launchd_plist "${plist_path}" "${bin}" "${listen}" "${data_dir}" ||
      ! enable_launchd_service "${plist_path}"; then
      macos_bootout_plist "${plist_path}"
      restore_file_backup "${CONF_DIR}/server.conf" "${conf_backup}" || true
      restore_file_backup "${plist_path}" "${plist_backup}" || true
      restore_binary_backup "server" || true
      cleanup_created_data_dir "${data_dir}" "${data_dir_created}"
      die "清理 cyber-monitor-server 初始管理员密码失败；已执行回滚流程"
    fi
  fi
  cleanup_file_backup "${conf_backup}"
  cleanup_file_backup "${plist_backup}"
  cleanup_binary_backup
  echo "已安装并启动 ${MACOS_SERVER_LABEL}（macOS / launchd）"
  print_admin_info "${listen}" "${data_dir}" "${admin_pass}"
}


install_server_dispatch() {
  case "$(detect_os)" in
    linux) install_server "$@" ;;
    macos) install_server_macos "$@" ;;
  esac
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

install_agent_dispatch() {
  case "$(detect_os)" in
    linux) install_agent_linux "$@" ;;
    macos) install_agent_macos "$@" ;;
  esac
}


uninstall_service_macos() {
  local type="$1"
  local label="${MACOS_AGENT_LABEL}"
  [[ "${type}" == "server" ]] && label="${MACOS_SERVER_LABEL}"
  local plist_dir
  plist_dir="$(macos_launchd_dir)"
  local plist_path="${plist_dir}/${label}.plist"
  reject_unsafe_path "${plist_path}" || die "拒绝清理包含不安全路径的 launchd plist"
  reject_unsafe_path "${INSTALL_DIR}/cyber-monitor-${type}" || die "拒绝清理包含不安全路径的安装文件"
  macos_bootout_plist "${plist_path}"
  rm -f "${plist_path}"
  rm -f "${INSTALL_DIR}/cyber-monitor-${type}"
  if [[ "${type}" == "agent" ]]; then
    rm -f /var/log/cybermonitor-agent.log 2>/dev/null || true
    if [[ -n "${HOME:-}" && "${HOME}" != "/" ]]; then
      rm -f "${HOME}/Library/Logs/cybermonitor-agent.log" 2>/dev/null || true
    fi
  fi
  echo "已卸载 cyber-monitor-${type}（macOS / launchd）"
}

uninstall_service_dispatch() {
  case "$(detect_os)" in
    linux) uninstall_service "$@" ;;
    macos) uninstall_service_macos "$@" ;;
  esac
}

uninstall_agent_dispatch() {
  case "$(detect_os)" in
    linux) uninstall_agent "$@" ;;
    macos)
      normalize_macos_user_paths
      uninstall_agent_macos_inlined
      ;;
  esac
}

# macOS agent 卸载：复用统一文件清理（与 linux cleanup_agent_config 同构）。
uninstall_agent_macos_inlined() {
  uninstall_service_macos "agent"
  cleanup_agent_config
}

uninstall_server_dispatch() {
  case "$(detect_os)" in
    linux) uninstall_server "$@" ;;
    macos) uninstall_server_macos "$@" ;;
  esac
}

uninstall_server_macos() {
  normalize_macos_user_paths
  local keep="${1:-}"
  if [[ -z "${keep}" ]]; then
    read -r -p "是否保留主控配置与数据目录? [y/N]: " keep || keep=""
  fi
  local data_dir
  data_dir="$(read_server_data_dir)"
  uninstall_service_macos "server"
  if [[ ! "${keep}" =~ ^[Yy]$ ]]; then
    cleanup_server_config "${data_dir}"
  fi
}

# macOS 的 server.conf 是 KEY=value 裸格式，读取时不需要去引号。
read_server_data_dir() {
  local data_dir=""
  if [[ -f "${CONF_DIR}/server.conf" ]]; then
    data_dir="$(sed -n 's/^CM_DATA_DIR=//p' "${CONF_DIR}/server.conf" | head -n 1)"
    data_dir="$(strip_systemd_env_quotes "${data_dir}")"
  fi
  if [[ -z "${data_dir}" ]]; then
    data_dir="$(default_server_data_dir)"
  fi
  echo "${data_dir}"
}


# 解析 install-server 非交互参数：--listen/--data-dir/--version。
parse_server_args() {
  local listen="25012"
  local data_dir=""
  local version=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --listen) listen="${2:-}"; shift 2 ;;
      --data-dir) data_dir="${2:-}"; shift 2 ;;
      --version) version="${2:-}"; shift 2 ;;
      *) die "未知参数: $1（install-server 支持 --listen/--data-dir/--version）" ;;
    esac
  done
  [[ -n "${listen}" ]] || die "--listen 需要参数"
  [[ -n "${data_dir}" ]] || data_dir="$(default_server_data_dir)"
  echo "${listen}"
  echo "${data_dir}"
  echo "${version}"
}

run_install_server_args() {
  local args
  args="$(parse_server_args "$@")"
  local listen data_dir version
  IFS=$'\n' read -r -d '' listen data_dir version < <(printf '%s\0' "${args}") || true
  install_server_dispatch "${listen}" "${data_dir}" "${version}"
}

# 解析 install-agent 非交互参数。
run_install_agent_args() {
  local server_url=""
  local token=""
  local node_id=""
  local net_iface=""
  local disable_update="0"
  local version=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server-url) server_url="$(require_value "$1" "${2:-}")"; shift 2 ;;
      --agent-token) token="$(require_value "$1" "${2:-}")"; shift 2 ;;
      --node-id) node_id="$(require_value "$1" "${2:-}")"; shift 2 ;;
      --net-iface) net_iface="$(require_value "$1" "${2:-}")"; shift 2 ;;
      --disable-update) disable_update="1"; shift ;;
      --version) version="$(require_value "$1" "${2:-}")"; shift 2 ;;
      *) die "未知参数: $1" ;;
    esac
  done
  install_agent_dispatch "${server_url}" "${token}" "${node_id}" "${net_iface}" "${disable_update}" "${version}"
}

run_uninstall_server_args() {
  local keep=""
  if [[ "${1:-}" == "--keep-data" ]]; then
    keep="y"
  elif [[ -n "${1:-}" ]]; then
    die "未知参数: $1（uninstall-server 支持 --keep-data）"
  fi
  uninstall_server_dispatch "${keep}"
}

require_value() {
  local option="$1"
  local value="${2:-}"
  if [[ -z "${value}" || "${value}" == --* ]]; then
    die "${option} 需要参数"
  fi
  printf '%s\n' "${value}"
}


usage_main() {
  sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
}


main() {
  case "$(detect_os)" in
    linux)
      require_root
      require_systemd
      ;;
    macos)
      # root=系统级 LaunchDaemon；普通用户=用户级 LaunchAgent。
      ;;
  esac
  require_curl

  local cmd="${1:-}"
  case "${cmd}" in
    ""|install)
      run_install_menu
      ;;
    remove|uninstall)
      run_remove_menu
      ;;
    install-server)
      shift
      run_install_server_args "$@"
      ;;
    install-agent)
      shift
      run_install_agent_args "$@"
      ;;
    uninstall-server)
      shift
      run_uninstall_server_args "$@"
      ;;
    uninstall-agent)
      uninstall_agent_dispatch
      ;;
    -h|--help)
      usage_main
      ;;
    *)
      usage_main
      exit 1
      ;;
  esac
}


if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
