#!/usr/bin/env bash
set -euo pipefail

: "${INSTALL_DIR:=/opt/CyberMonitor}"
: "${CONF_DIR:=/etc/cybermonitor}"
: "${SYSTEMD_SERVICE_DIR:=/etc/systemd/system}"
: "${MACOS_LAUNCHD_DIR:=/Library/LaunchDaemons}"
: "${CYBERMONITOR_SELF_DELETE:=1}"

SERVICE_NAME="cyber-monitor-agent"
SCRIPT_PATH="${BASH_SOURCE[0]}"

usage() {
  cat <<'EOF'
用法：
  bash agent-uninstall.sh

说明：
  自动卸载 CyberMonitor Agent 的服务、二进制与 agent.conf。
EOF
}

die() {
  echo "错误：$*" >&2
  exit 1
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "请使用 root 运行"
  fi
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

detect_os() {
  case "$(uname -s)" in
    Linux) echo "linux" ;;
    Darwin) echo "macos" ;;
    *) die "暂不支持当前系统：$(uname -s)" ;;
  esac
}

should_cleanup_script() {
  [[ "${CYBERMONITOR_SELF_DELETE}" == "1" ]] || return 1
  case "${SCRIPT_PATH}" in
    /tmp/*) return 0 ;;
    /var/folders/*) return 0 ;;
    "${TMPDIR:-/tmp}"/*) return 0 ;;
    *) return 1 ;;
  esac
}

cleanup_script() {
  if should_cleanup_script && [[ -f "${SCRIPT_PATH}" ]]; then
    reject_unsafe_path "${SCRIPT_PATH}" || return 1
    rm -f "${SCRIPT_PATH}"
  fi
}

cleanup_common_files() {
  reject_unsafe_path "${INSTALL_DIR}/cyber-monitor-agent" || die "拒绝清理包含不安全路径的 Agent 二进制"
  reject_unsafe_path "${INSTALL_DIR}/.cybermonitor-agent-token" || die "拒绝清理包含不安全路径的 Agent token"
  reject_unsafe_path "${INSTALL_DIR}/.cybermonitor-node-id" || die "拒绝清理包含不安全路径的节点 ID"
  reject_unsafe_path "${CONF_DIR}/agent.conf" || die "拒绝清理包含不安全路径的 Agent 配置"
  reject_unsafe_path "${CONF_DIR}" || die "拒绝清理包含不安全路径的配置目录"
  reject_unsafe_path "${INSTALL_DIR}" || die "拒绝清理包含不安全路径的安装目录"
  rm -f "${INSTALL_DIR}/cyber-monitor-agent"
  rm -f "${INSTALL_DIR}/.cybermonitor-agent-token"
  rm -f "${INSTALL_DIR}/.cybermonitor-node-id"
  rm -f "${CONF_DIR}/agent.conf"
  rmdir "${CONF_DIR}" 2>/dev/null || true
  rmdir "${INSTALL_DIR}" 2>/dev/null || true
}

linux_uninstall() {
  local service_file="${SYSTEMD_SERVICE_DIR}/${SERVICE_NAME}.service"
  reject_unsafe_path "${service_file}" || die "拒绝清理包含不安全路径的 systemd service"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "${SERVICE_NAME}" >/dev/null 2>&1 || true
  fi

  rm -f "${service_file}"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  cleanup_common_files
  echo "已卸载 ${SERVICE_NAME}（Linux / systemd）"
}

macos_plist_candidates() {
  cat <<EOF
${MACOS_LAUNCHD_DIR}/io.github.crazy0x70.cyber-monitor-agent.plist
${MACOS_LAUNCHD_DIR}/com.cybermonitor.agent.plist
${MACOS_LAUNCHD_DIR}/cyber-monitor-agent.plist
EOF
}

macos_uninstall() {
  local plist_path

  while IFS= read -r plist_path; do
    [[ -n "${plist_path}" ]] || continue
    if [[ -f "${plist_path}" ]]; then
      reject_unsafe_path "${plist_path}" || die "拒绝清理包含不安全路径的 launchd plist"
      if command -v launchctl >/dev/null 2>&1; then
        launchctl bootout system "${plist_path}" >/dev/null 2>&1 || \
          launchctl unload -w "${plist_path}" >/dev/null 2>&1 || true
      fi
      rm -f "${plist_path}"
    fi
  done < <(macos_plist_candidates)

  cleanup_common_files
  echo "已卸载 ${SERVICE_NAME}（macOS / launchd）"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ $# -gt 0 ]]; then
    die "未知参数：$*"
  fi

  require_root

  case "$(detect_os)" in
    linux) linux_uninstall ;;
    macos) macos_uninstall ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  trap 'cleanup_script || true' EXIT
  main "$@"
fi
