# syntax=docker/dockerfile:1.7
ARG GO_IMAGE=golang:latest
ARG RUNTIME_IMAGE=debian:stable-slim

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build-base

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

WORKDIR /src
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal

FROM build-base AS build-server
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN set -eu; \
    test -f internal/server/web/dist/admin/index.html || { \
      echo "Missing admin assets: run npm --prefix internal/server/web/admin run build:admin before local Docker builds." >&2; \
      exit 1; \
    }; \
    missing=0; \
    for ref in $(grep -o 'assets/[A-Za-z0-9._-]*' internal/server/web/dist/admin/index.html | sort -u); do \
      if [ ! -f "internal/server/web/dist/admin/$ref" ]; then \
        echo "Missing admin asset: internal/server/web/dist/admin/$ref (dist build incomplete, re-run build:admin)" >&2; \
        missing=1; \
      fi; \
    done; \
    test "$missing" -eq 0
RUN set -eux; \
  export GOOS=${TARGETOS}; \
  export GOARCH=${TARGETARCH}; \
  if [ "${TARGETARCH}" = "arm" ] && [ -n "${TARGETVARIANT:-}" ]; then export GOARM="${TARGETVARIANT#v}"; fi; \
  CGO_ENABLED=0 go build -o /out/cyber-monitor \
    -trimpath \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" \
    ./cmd/server

FROM build-base AS build-agent
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN set -eux; \
  export GOOS=${TARGETOS}; \
  export GOARCH=${TARGETARCH}; \
  if [ "${TARGETARCH}" = "arm" ] && [ -n "${TARGETVARIANT:-}" ]; then export GOARM="${TARGETVARIANT#v}"; fi; \
  CGO_ENABLED=0 go build -o /out/cyber-monitor \
    -trimpath \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" \
    ./cmd/agent

FROM ${RUNTIME_IMAGE} AS runtime-base
WORKDIR /app
# GOMEMLIMIT 是 Go GC 软上限：实测 30 agent 满负载工作集 <60MiB，
# 300MiB 留足余量，同时阻止堆水位在分配波动下无限抬升容器 RSS。
ENV GOMEMLIMIT=300MiB \
    DEBIAN_FRONTEND=noninteractive
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates gosu tzdata && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system cm && \
    useradd --system --gid cm --home-dir /app --shell /usr/sbin/nologin cm && \
    chmod +x /usr/local/bin/docker-entrypoint.sh && \
    chown -R cm:cm /app

FROM runtime-base AS release-server
ARG VERSION=dev
ARG COMMIT=none
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /data && chown -R cm:cm /data
ENV CM_DATA_DIR=/data \
    CM_DEPLOY_MODE=docker \
    CM_VERSION=${VERSION} \
    CM_COMMIT=${COMMIT}
COPY --from=build-server /out/cyber-monitor /app/cyber-monitor
EXPOSE 25012
EXPOSE 25013
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:25012/api/v1/health >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

FROM runtime-base AS release-agent
ARG VERSION=dev
ARG COMMIT=none
COPY --from=build-agent /out/cyber-monitor /app/cyber-monitor
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping libcap2-bin && \
    rm -rf /var/lib/apt/lists/* && \
    ping_path="$(readlink -f "$(command -v ping)")" && \
    setcap cap_net_raw+ep "$ping_path"
ENV CM_DEPLOY_MODE=docker \
    CM_VERSION=${VERSION} \
    CM_COMMIT=${COMMIT}
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

FROM runtime-base AS release-server-prebuilt
ARG VERSION=dev
ARG COMMIT=none
ARG TARGETARCH
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /data && chown -R cm:cm /data
RUN --mount=type=bind,source=docker-release,target=/release,readonly \
    set -eu; \
    case "${TARGETARCH}" in \
      amd64) binary="/release/cyber-monitor-server-linux-amd64" ;; \
      arm64) binary="/release/cyber-monitor-server-linux-arm64" ;; \
      *) echo "Unsupported server Docker target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    test -f "$binary"; \
    cp "$binary" /app/cyber-monitor; \
    chmod 0755 /app/cyber-monitor; \
    chown cm:cm /app/cyber-monitor
ENV CM_DATA_DIR=/data \
    CM_DEPLOY_MODE=docker \
    CM_VERSION=${VERSION} \
    CM_COMMIT=${COMMIT}
EXPOSE 25012
EXPOSE 25013
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:25012/api/v1/health >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

FROM runtime-base AS release-agent-prebuilt
ARG VERSION=dev
ARG COMMIT=none
ARG TARGETARCH
RUN --mount=type=bind,source=docker-release,target=/release,readonly \
    set -eu; \
    case "${TARGETARCH}" in \
      amd64) binary="/release/cyber-monitor-agent-linux-amd64" ;; \
      arm64) binary="/release/cyber-monitor-agent-linux-arm64" ;; \
      *) echo "Unsupported agent Docker target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    test -f "$binary"; \
    cp "$binary" /app/cyber-monitor; \
    chmod 0755 /app/cyber-monitor; \
    chown cm:cm /app/cyber-monitor
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping libcap2-bin && \
    rm -rf /var/lib/apt/lists/* && \
    ping_path="$(readlink -f "$(command -v ping)")" && \
    setcap cap_net_raw+ep "$ping_path"
ENV CM_DEPLOY_MODE=docker \
    CM_VERSION=${VERSION} \
    CM_COMMIT=${COMMIT}
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
