#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW_FILE="$ROOT_DIR/.github/workflows/build-release.yml"

grep -Fq 'image_repo: ${{ steps.version.outputs.image_repo }}' "$WORKFLOW_FILE"
grep -Fq 'REPO_OWNER="$(printf '\''%s'\'' "${GITHUB_REPOSITORY%/*}" | tr '\''[:upper:]'\'' '\''[:lower:]'\'')"' "$WORKFLOW_FILE"
grep -Fq 'REPO_NAME_KEBAB="$(printf '\''%s'\'' "${GITHUB_REPOSITORY#*/}" | sed -E '\''s/([[:lower:][:digit:]])([[:upper:]])/\1-\2/g; s/[[:space:]_]+/-/g'\'' | tr '\''[:upper:]'\'' '\''[:lower:]'\'')"' "$WORKFLOW_FILE"
grep -Fq 'IMAGE_REPO="${REPO_OWNER}/${REPO_NAME_KEBAB}"' "$WORKFLOW_FILE"
grep -Fq 'IMAGE_PREFIX: ghcr.io/${{ needs.version.outputs.image_repo }}' "$WORKFLOW_FILE"
grep -Fq '${{ env.IMAGE_PREFIX }}-server:${{ needs.version.outputs.version }}' "$WORKFLOW_FILE"
grep -Fq '${{ env.IMAGE_PREFIX }}-agent:${{ needs.version.outputs.version }}' "$WORKFLOW_FILE"

if grep -Fq 'IMAGE_PREFIX: ghcr.io/${{ github.repository_owner }}/${{ github.event.repository.name }}' "$WORKFLOW_FILE"; then
  echo "workflow still uses repository name with original casing" >&2
  exit 1
fi

if grep -Fq 'IMAGE_REPO="$(printf '\''%s'\'' "${GITHUB_REPOSITORY}" | tr '\''[:upper:]'\'' '\''[:lower:]'\'')"' "$WORKFLOW_FILE"; then
  echo "workflow still lowercases the repository name without converting CamelCase to kebab-case" >&2
  exit 1
fi
