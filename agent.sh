#!/usr/bin/env bash
set -euo pipefail

REPO="crazy0x70/CyberMonitor"
INSTALL_DIR="/opt/CyberMonitor"
CONF_DIR="/etc/cybermonitor"
SCRIPT_PATH="${BASH_SOURCE[0]}"
cleanup() {
  if [[ -f "${SCRIPT_PATH}" ]]; then
    rm -f "${SCRIPT_PATH}"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
用法：
  bash agent.sh --server-url http://<ip>:25012 --agent-token <token> [--net-iface eth0] [--version v0.1.0]
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

write_conf() {
  mkdir -p "${CONF_DIR}"
  cat > "${CONF_DIR}/agent.conf" <<EOF
CM_SERVER_URL=${1}
CM_AGENT_TOKEN=${2}
CM_NET_IFACE=${3}
EOF
}

install_agent() {
  local server_url="$1"
  local token="$2"
  local net_iface="$3"
  local version="$4"
  [[ -z "${server_url}" ]] && die "必须提供 --server-url"
  [[ -z "${token}" ]] && die "必须提供 --agent-token"

  local arch
  arch="$(detect_arch)"
  version="$(resolve_version "${version}")"

  local bin
  bin="$(download_binary "${version}" "${arch}")"
  write_conf "${server_url}" "${token}" "${net_iface}"

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

main() {
  require_root
  require_systemd
  require_curl

  local server_url=""
  local token=""
  local net_iface=""
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
      --net-iface)
        net_iface="$2"
        shift 2
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

  install_agent "${server_url}" "${token}" "${net_iface}" "${version}"
}

main "$@"
