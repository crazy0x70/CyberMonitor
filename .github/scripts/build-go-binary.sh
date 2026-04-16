#!/usr/bin/env bash
set -euo pipefail

target_os="${1:-}"
target_arch="${2:-}"
target_goarm="${3:-}"
output_path="${4:-}"
cmd_path="${5:-}"
version="${6:-}"
commit="${7:-}"
build_time="${8:-}"

if [[ -z "${target_os}" || -z "${target_arch}" || -z "${output_path}" || -z "${cmd_path}" ]]; then
  echo "usage: build-go-binary.sh <os> <arch> <goarm> <output> <cmd> <version> <commit> <build_time>" >&2
  exit 1
fi

mkdir -p "$(dirname "${output_path}")"

export CGO_ENABLED=0
export GOOS="${target_os}"
export GOARCH="${target_arch}"
if [[ -n "${target_goarm}" ]]; then
  export GOARM="${target_goarm}"
fi

go build \
  -trimpath \
  -ldflags "-s -w -X main.Version=${version} -X main.Commit=${commit} -X main.BuildTime=${build_time}" \
  -o "${output_path}" \
  "${cmd_path}"
