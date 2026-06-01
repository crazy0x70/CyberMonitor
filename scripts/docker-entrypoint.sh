#!/bin/sh
set -eu

BINARY_PATH="/app/cyber-monitor"
RUNTIME_USER="${CM_RUNTIME_USER:-cm}"
DOCKER_SOCKET_PATH="${CM_DOCKER_SOCKET:-/var/run/docker.sock}"
DATA_DIR="${CM_DATA_DIR:-}"

runtime_file_allowed() {
	target_path="$1"
	if [ -z "${target_path}" ]; then
		return 1
	fi
	case "${target_path}" in
		/*) ;;
		*) return 1 ;;
	esac
	case "${target_path}" in
		*/../* | */.. | /..) return 1 ;;
	esac
	case "${target_path}" in
		/state | /state/* | /data | /data/* | /home/cm | /home/cm/*) return 0 ;;
		*) return 1 ;;
	esac
}

reject_symlink_runtime_path() {
	target_path="$1"
	current=""
	remaining="${target_path#/}"

	while [ -n "${remaining}" ]; do
		part="${remaining%%/*}"
		if [ "${part}" = "${remaining}" ]; then
			remaining=""
		else
			remaining="${remaining#*/}"
		fi
		[ -n "${part}" ] || continue
		case "${part}" in
			. | ..)
				echo "Refusing runtime path outside allowed state roots: ${target_path}" >&2
				exit 1
				;;
		esac
		if [ -z "${current}" ]; then
			current="/${part}"
		else
			current="${current}/${part}"
		fi
		if [ -L "${current}" ]; then
			echo "Refusing symlink runtime path: ${current}" >&2
			exit 1
		fi
	done
}

chown_runtime_path() {
	target_path="$1"
	if ! runtime_file_allowed "${target_path}"; then
		echo "Refusing runtime path outside allowed state roots: ${target_path}" >&2
		exit 1
	fi
	reject_symlink_runtime_path "${target_path}"
	if [ ! -e "${target_path}" ]; then
		return
	fi
	if [ -d "${target_path}" ]; then
		if find "${target_path}" -type l -print -quit | grep -q .; then
			echo "Refusing symlink runtime path: ${target_path}" >&2
			exit 1
		fi
		if ! find "${target_path}" -exec sh -c '
			expected="$1"
			shift
			for path do
				if [ -L "$path" ]; then
					echo "Refusing symlink runtime path: $path" >&2
					exit 1
				fi
				if [ "$(stat -c "%U:%G" "$path" 2>/dev/null || true)" = "$expected" ]; then
					continue
				fi
				chown -h "$expected" "$path" || exit 1
			done
		' sh "${RUNTIME_USER}:${RUNTIME_USER}" {} +; then
			echo "Failed to prepare runtime path permissions for ${target_path}" >&2
			exit 1
		fi
		return
	fi
	if [ "$(stat -c '%U:%G' "${target_path}" 2>/dev/null || true)" = "${RUNTIME_USER}:${RUNTIME_USER}" ]; then
		return
	fi
	if ! chown -h "${RUNTIME_USER}:${RUNTIME_USER}" "${target_path}"; then
		echo "Failed to prepare runtime path permissions for ${target_path}" >&2
		exit 1
	fi
}

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
	if ! runtime_file_allowed "${DATA_DIR}"; then
		echo "Refusing runtime directory outside allowed state roots: ${DATA_DIR}" >&2
		exit 1
	fi
	reject_symlink_runtime_path "${DATA_DIR}"

	mkdir -p "${DATA_DIR}"
	chown_runtime_path "${DATA_DIR}"
}

prepare_parent_dir() {
	target_path="$1"
	if [ -z "${target_path}" ]; then
		return
	fi

	target_dir="$(dirname "${target_path}")"
	if [ "${target_dir}" = "." ] || [ "${target_dir}" = "/" ] || ! runtime_file_allowed "${target_path}"; then
		echo "Refusing runtime file outside allowed state roots: ${target_path}" >&2
		exit 1
	fi
	if [ -L "${target_path}" ]; then
		echo "Refusing symlink runtime file: ${target_path}" >&2
		exit 1
	fi
	reject_symlink_runtime_path "${target_dir}"
	mkdir -p "${target_dir}"
	chown_runtime_path "${target_dir}"
	chown_runtime_path "${target_path}"
}

prepare_agent_identity_dirs() {
	prepare_parent_dir "${CM_NODE_ID_FILE:-}"
	prepare_parent_dir "${CM_AGENT_TOKEN_FILE:-}"
}

attach_docker_socket_group() {
	if [ "${CM_ENABLE_DOCKER_UPDATE:-0}" != "1" ]; then
		return 0
	fi

	if [ ! -S "${DOCKER_SOCKET_PATH}" ]; then
		return 0
	fi

	socket_gid="$(stat -c '%g' "${DOCKER_SOCKET_PATH}" 2>/dev/null || true)"
	if [ -z "${socket_gid}" ]; then
		return 0
	fi

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
	prepare_agent_identity_dirs
	attach_docker_socket_group
	exec su-exec "${RUNTIME_USER}" "${BINARY_PATH}" "$@"
}

if [ "$(id -u)" -eq 0 ]; then
  run_as_root "$@"
fi

exec "${BINARY_PATH}" "$@"
