#!/bin/sh
set -eu

BINARY_PATH="/app/cyber-monitor"
RUNTIME_USER="${CM_RUNTIME_USER:-cm}"
DOCKER_SOCKET_PATH="${CM_DOCKER_SOCKET:-/var/run/docker.sock}"
DATA_DIR="${CM_DATA_DIR:-}"

prepare_data_dir() {
  if [ -z "${DATA_DIR}" ]; then
    return
  fi

  mkdir -p "${DATA_DIR}"
  if ! chmod u+rwx "${DATA_DIR}"; then
    echo "Failed to make data directory writable: ${DATA_DIR}" >&2
    exit 1
  fi
  if ! chown -R "${RUNTIME_USER}:${RUNTIME_USER}" "${DATA_DIR}"; then
    echo "Failed to prepare data directory permissions for ${DATA_DIR}" >&2
    exit 1
  fi
}

if [ "${1:-}" = "docker-recreate-helper" ]; then
  exec "${BINARY_PATH}" "$@"
fi

if [ "$(id -u)" -eq 0 ]; then
  prepare_data_dir

  if [ -S "${DOCKER_SOCKET_PATH}" ]; then
    SOCKET_GID="$(stat -c '%g' "${DOCKER_SOCKET_PATH}" 2>/dev/null || true)"
    if [ -n "${SOCKET_GID}" ]; then
      SOCKET_GROUP="$(awk -F: -v gid="${SOCKET_GID}" '$3 == gid { print $1; exit }' /etc/group)"
      if [ -z "${SOCKET_GROUP}" ]; then
        SOCKET_GROUP="dockerhost"
        addgroup -g "${SOCKET_GID}" -S "${SOCKET_GROUP}" >/dev/null 2>&1 || true
      fi
      addgroup "${RUNTIME_USER}" "${SOCKET_GROUP}" >/dev/null 2>&1 || true
    fi
  fi

  exec su-exec "${RUNTIME_USER}" "${BINARY_PATH}" "$@"
fi

exec "${BINARY_PATH}" "$@"
