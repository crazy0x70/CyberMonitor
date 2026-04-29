#!/usr/bin/env bash

REPO="crazy0x70/CyberMonitor"
INSTALL_DIR="/opt/CyberMonitor"
CONF_DIR="/etc/cybermonitor"

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
      sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
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
  local asset="cyber-monitor-${type}-linux-${arch}"
  local url="https://github.com/${REPO}/releases/download/${version}/${asset}"
  local target="${INSTALL_DIR}/cyber-monitor-${type}"
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
  # 安装阶段首次注册仍走 HTTP；安装完成后的 Agent 运行态会对同一 server-url 优先尝试 gRPC。
  local endpoint="${server_url%/}/api/v1/agent/register?node_id=${node_id}"
  local response
  response="$(curl -fsSL -X POST -H "X-AGENT-TOKEN: ${bootstrap_token}" "${endpoint}")" || \
    die "Agent 注册失败，请检查 Server 地址与 Agent Token"
  local node_token
  node_token="$(printf '%s' "${response}" | sed -n 's/.*"agent_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  [[ -n "${node_token}" ]] || die "Agent 注册成功但未返回专属凭据"
  echo "${node_token}"
}
