#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
VERSION="${VERSION:-0.0.0-local}"
COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo local)}"

"${ROOT_DIR}/scripts/verify-local.sh"

export GOPATH="${GOPATH:-${ROOT_DIR}/.cache/go}"
export GOMODCACHE="${GOMODCACHE:-${ROOT_DIR}/.cache/go-mod}"
export GOCACHE="${GOCACHE:-${ROOT_DIR}/.cache/go-build}"
export TMPDIR="${TMPDIR:-${ROOT_DIR}/.tmp}"
export CGO_ENABLED="${CGO_ENABLED:-0}"

mkdir -p "${ROOT_DIR}/dist" "${GOPATH}" "${GOMODCACHE}" "${GOCACHE}" "${TMPDIR}"

cd "${ROOT_DIR}"

go build \
  -trimpath \
  -ldflags "-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" \
  -o "${ROOT_DIR}/dist/cyber-monitor-server-local" \
  ./cmd/server

go build \
  -trimpath \
  -ldflags "-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" \
  -o "${ROOT_DIR}/dist/cyber-monitor-agent-local" \
  ./cmd/agent
