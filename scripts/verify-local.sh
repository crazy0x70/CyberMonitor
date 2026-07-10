#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADMIN_DIR="${ROOT_DIR}/internal/server/web/admin"

export GOPATH="${GOPATH:-${ROOT_DIR}/.cache/go}"
export GOMODCACHE="${GOMODCACHE:-${ROOT_DIR}/.cache/go-mod}"
export GOCACHE="${GOCACHE:-${ROOT_DIR}/.cache/go-build}"
export TMPDIR="${TMPDIR:-${ROOT_DIR}/.tmp}"

mkdir -p "${GOPATH}" "${GOMODCACHE}" "${GOCACHE}" "${TMPDIR}"

cd "${ROOT_DIR}"

bash -n \
  scripts/verify-local.sh \
  scripts/build-local.sh \
  scripts/install-common.sh \
  scripts/agent.sh \
  scripts/one-click.sh \
  scripts/agent-uninstall.sh
sh -n scripts/docker-entrypoint.sh

npm --prefix "${ADMIN_DIR}" ci --cache "${ROOT_DIR}/.cache/npm"
npm --prefix "${ADMIN_DIR}" run lint
npm --prefix "${ADMIN_DIR}" run build:admin

go vet ./...
go test ./...
