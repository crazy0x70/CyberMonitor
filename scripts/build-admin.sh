#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"

cd "$ROOT_DIR"
"$ROOT_DIR/scripts/verify-admin-build-inputs.sh"
npm --prefix admin-ui run build:admin
