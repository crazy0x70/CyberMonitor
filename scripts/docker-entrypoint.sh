#!/bin/sh
set -eu

BINARY_PATH="/app/cyber-monitor"
RUNTIME_USER="${CM_RUNTIME_USER:-cm}"
DOCKER_SOCKET_PATH="${CM_DOCKER_SOCKET:-/var/run/docker.sock}"
DATA_DIR="${CM_DATA_DIR:-}"

apply_timezone() {
  if [ -z "${TZ:-}" ]; then
    return
  fi

  zoneinfo="/usr/share/zoneinfo/${TZ}"
  if [ ! -f "${zoneinfo}" ]; then
    echo "Invalid TZ value: ${TZ}" >&2
    return
  fi

  ln -snf "${zoneinfo}" /etc/localtime
  printf '%s\n' "${TZ}" > /etc/timezone
}

prepare_data_dir() {
  if [ -z "${DATA_DIR}" ]; then
    return
  fi

  mkdir -p "${DATA_DIR}"
  if ! chown "${RUNTIME_USER}:${RUNTIME_USER}" "${DATA_DIR}"; then
    echo "Failed to prepare data directory permissions for ${DATA_DIR}" >&2
    exit 1
  fi
}

attach_docker_socket_group() {
  [ -S "${DOCKER_SOCKET_PATH}" ] || return

  socket_gid="$(stat -c '%g' "${DOCKER_SOCKET_PATH}" 2>/dev/null || true)"
  [ -n "${socket_gid}" ] || return

  socket_group="$(awk -F: -v gid="${socket_gid}" '$3 == gid { print $1; exit }' /etc/group)"
  if [ -z "${socket_group}" ]; then
    socket_group="dockerhost"
    addgroup -g "${socket_gid}" -S "${socket_group}" >/dev/null 2>&1 || true
  fi
  addgroup "${RUNTIME_USER}" "${socket_group}" >/dev/null 2>&1 || true
}

run_as_root() {
  apply_timezone
  prepare_data_dir
  attach_docker_socket_group
  exec su-exec "${RUNTIME_USER}" "${BINARY_PATH}" "$@"
}

if [ "${1:-}" = "docker-recreate-helper" ]; then
  exec "${BINARY_PATH}" "$@"
fi

if [ "$(id -u)" -eq 0 ]; then
  run_as_root "$@"
fi

exec "${BINARY_PATH}" "$@"
