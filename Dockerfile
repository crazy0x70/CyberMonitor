ARG GO_IMAGE_VERSION=1.26.2

FROM --platform=$BUILDPLATFORM node:24-alpine AS admin-build

WORKDIR /src
COPY internal/server/web ./internal/server/web
RUN test -f internal/server/web/admin/package.json && \
    test -f internal/server/web/admin/package-lock.json && \
    test -f internal/server/web/admin/src/App.tsx && \
    test -f internal/server/web/admin/lib/admin-ui.ts && \
    test -f internal/server/web/public/index.html
RUN --mount=type=cache,target=/root/.npm \
    npm --prefix internal/server/web/admin ci && \
    npm --prefix internal/server/web/admin run lint && \
    npm --prefix internal/server/web/admin run build:admin

FROM --platform=$BUILDPLATFORM golang:${GO_IMAGE_VERSION}-alpine AS build-base

ARG GO_IMAGE_VERSION
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

WORKDIR /src
COPY go.mod ./
COPY go.sum ./
RUN set -eu; \
    go_version="$(awk '/^go / { print $2; exit }' go.mod)"; \
    if [ -z "${go_version}" ]; then \
      echo "Unable to resolve Go version from go.mod" >&2; \
      exit 1; \
    fi; \
    if [ "${go_version}" != "${GO_IMAGE_VERSION}" ]; then \
      echo "Go version drift detected: go.mod=${go_version}, Dockerfile GO_IMAGE_VERSION=${GO_IMAGE_VERSION}" >&2; \
      exit 1; \
    fi; \
    go mod download
COPY cmd ./cmd
COPY internal ./internal

FROM build-base AS build-server
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
COPY --from=admin-build /src/internal/server/web/dist/admin ./internal/server/web/dist/admin
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

FROM alpine:3.23 AS runtime-base
WORKDIR /app
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN apk add --no-cache su-exec tzdata && \
    addgroup -S cm && \
    adduser -S -G cm cm && \
    chmod +x /usr/local/bin/docker-entrypoint.sh && \
    chown -R cm:cm /app

FROM runtime-base AS release-server
ARG VERSION=dev
ARG COMMIT=none
RUN mkdir -p /data && chown -R cm:cm /data
ENV CM_DATA_DIR=/data \
    CM_DEPLOY_MODE=docker \
    CM_VERSION=${VERSION} \
    CM_COMMIT=${COMMIT}
COPY --from=build-server /out/cyber-monitor /app/cyber-monitor
EXPOSE 25012
EXPOSE 25013
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:25012/api/v1/health || exit 1
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

FROM runtime-base AS release-agent
ARG VERSION=dev
ARG COMMIT=none
COPY --from=build-agent /out/cyber-monitor /app/cyber-monitor
RUN apk add --no-cache iputils libcap-utils && \
    setcap cap_net_raw+ep /bin/ping && \
    ping6_path="$(command -v ping6 || true)" && \
    if [ -n "$ping6_path" ] && [ ! -L "$ping6_path" ] && [ "$ping6_path" != "/bin/ping" ]; then \
      setcap cap_net_raw+ep "$ping6_path"; \
    fi
ENV CM_DEPLOY_MODE=docker \
    CM_VERSION=${VERSION} \
    CM_COMMIT=${COMMIT}
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
