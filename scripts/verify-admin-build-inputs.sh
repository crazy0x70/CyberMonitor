#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"

cd "$ROOT_DIR"

require_tracked=0
if [ "${1:-}" = "--require-tracked" ]; then
  require_tracked=1
fi

require_path() {
  path="$1"
  if [ ! -e "$path" ]; then
    echo "Missing required admin build input: $path" >&2
    exit 1
  fi
}

require_tracked_path() {
  path="$1"
  if ! git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
    echo "Required admin build input is not tracked by the top-level Git repository: $path" >&2
    echo "同步到 GitHub 前，请先把 admin-ui/ 与 scripts/ 纳入顶层仓库，或改成显式 submodule。" >&2
    exit 1
  fi
}

require_path "admin-ui/package.json"
require_path "admin-ui/package-lock.json"
require_path "admin-ui/src/App.tsx"
require_path "admin-ui/lib/admin-ui.ts"
require_path "admin-ui/scripts/sync-admin.mjs"
require_path "scripts/build-admin.sh"
require_path "internal/server/web/index.html"

if [ "$require_tracked" -eq 1 ]; then
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Top-level Git repository is required when --require-tracked is enabled." >&2
    exit 1
  fi

  require_tracked_path "admin-ui/package.json"
  require_tracked_path "admin-ui/package-lock.json"
  require_tracked_path "admin-ui/src/App.tsx"
  require_tracked_path "admin-ui/lib/admin-ui.ts"
  require_tracked_path "admin-ui/scripts/sync-admin.mjs"
  require_tracked_path "scripts/build-admin.sh"
  require_tracked_path "internal/server/web/index.html"
fi
