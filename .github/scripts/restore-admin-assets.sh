#!/usr/bin/env bash
set -euo pipefail

archive_path="${1:-}"
target_root="${2:-internal/server/web}"

if [[ -z "${archive_path}" ]]; then
  echo "usage: restore-admin-assets.sh <archive-path> [target-root]" >&2
  exit 1
fi

mkdir -p "${target_root}"
tar -xzf "${archive_path}" -C "${target_root}"
