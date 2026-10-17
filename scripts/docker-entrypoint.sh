#!/bin/sh
# 容器入口：以 root 启动时准备时区、数据目录权限与 docker.sock 组，然后降权到 cm 用户运行。
set -eu

BINARY_PATH="/app/cyber-monitor"
RUNTIME_USER="${CM_RUNTIME_USER:-cm}"

if [ "$(id -u)" -ne 0 ]; then
	exec "${BINARY_PATH}" "$@"
fi

if [ -n "${TZ:-}" ] && [ -f "/usr/share/zoneinfo/${TZ}" ]; then
	ln -snf "/usr/share/zoneinfo/${TZ}" /etc/localtime
	printf '%s\n' "${TZ}" >/etc/timezone
fi

# 让运行用户拥有目录：只改属主不对的条目，避免每次启动重写整个历史数据目录。
own_dir() {
	dir="$1"
	if [ -z "${dir}" ] || [ "${dir}" = "/" ] || [ "${dir}" = "." ]; then
		return
	fi
	mkdir -p "${dir}"
	find "${dir}" ! -user "${RUNTIME_USER}" -exec chown -h "${RUNTIME_USER}:${RUNTIME_USER}" {} +
}

own_dir "${CM_DATA_DIR:-}"
if [ -n "${CM_NODE_ID_FILE:-}" ]; then own_dir "$(dirname "${CM_NODE_ID_FILE}")"; fi
if [ -n "${CM_AGENT_TOKEN_FILE:-}" ]; then own_dir "$(dirname "${CM_AGENT_TOKEN_FILE}")"; fi

# Docker 托管更新：把运行用户加入 docker.sock 的属组。
socket="${CM_DOCKER_SOCKET:-/var/run/docker.sock}"
if [ "${CM_ENABLE_DOCKER_UPDATE:-0}" = "1" ] && [ -S "${socket}" ]; then
	gid="$(stat -c '%g' "${socket}")"
	group="$(awk -F: -v gid="${gid}" '$3 == gid { print $1; exit }' /etc/group)"
	if [ -z "${group}" ]; then
		group="dockerhost"
		addgroup -g "${gid}" -S "${group}"
	fi
	addgroup "${RUNTIME_USER}" "${group}" 2>/dev/null || true
fi

exec su-exec "${RUNTIME_USER}" "${BINARY_PATH}" "$@"
