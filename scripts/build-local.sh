#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADMIN_DIR="${ROOT_DIR}/internal/server/web/admin"
BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
VERSION="${VERSION:-0.0.0-local}"
COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo local)}"

export GOPATH="${GOPATH:-${ROOT_DIR}/.cache/go}"
export GOMODCACHE="${GOMODCACHE:-${ROOT_DIR}/.cache/go-mod}"
export GOCACHE="${GOCACHE:-${ROOT_DIR}/.cache/go-build}"
export TMPDIR="${TMPDIR:-${ROOT_DIR}/.tmp}"

mkdir -p "${ROOT_DIR}/dist" "${GOPATH}" "${GOMODCACHE}" "${GOCACHE}" "${TMPDIR}"

npm --prefix "${ADMIN_DIR}" ci --cache "${ROOT_DIR}/.cache/npm"
npm --prefix "${ADMIN_DIR}" run lint
npm --prefix "${ADMIN_DIR}" run test:unit
npm --prefix "${ADMIN_DIR}" run build:admin

cd "${ROOT_DIR}"
go vet ./...
go test ./...

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
