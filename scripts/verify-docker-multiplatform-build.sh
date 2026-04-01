#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="$ROOT_DIR/Dockerfile"

grep -Fq 'FROM --platform=$BUILDPLATFORM node:22-alpine AS admin-build' "$DOCKERFILE"
grep -Fq 'FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build-base' "$DOCKERFILE"
grep -Fq 'ARG TARGETOS' "$DOCKERFILE"
grep -Fq 'ARG TARGETARCH' "$DOCKERFILE"
grep -Fq 'export GOOS=${TARGETOS}' "$DOCKERFILE"
grep -Fq 'export GOARCH=${TARGETARCH}' "$DOCKERFILE"
