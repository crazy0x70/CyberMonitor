#!/usr/bin/env bash

REPO="crazy0x70/CyberMonitor"
INSTALL_DIR="${INSTALL_DIR:-/opt/CyberMonitor}"
CONF_DIR="${CONF_DIR:-/etc/cybermonitor}"
SYSTEMD_SERVICE_DIR="${SYSTEMD_SERVICE_DIR:-/etc/systemd/system}"
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
  if [[ "${version,,}" == "latest" || "${version,,}" == "vlatest" ]]; then
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
      if [[ "${allow_leaf}" == "allow-leaf" && -z "${remaining}" ]]; then
        return 0
      fi
      echo "refuses symbolic link path: ${current}" >&2
      return 1
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
  local asset="cyber-monitor-${type}-linux-${arch}"
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
