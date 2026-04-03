# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM node:22-alpine AS admin-build

WORKDIR /src
COPY admin-ui ./admin-ui
COPY internal/server/web ./internal/server/web
COPY scripts ./scripts
RUN --mount=type=cache,target=/root/.npm npm --prefix admin-ui ci
RUN npm --prefix admin-ui run lint
RUN ./scripts/build-admin.sh

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build-base

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
COPY --from=admin-build /src/internal/server/web/admin-app ./internal/server/web/admin-app
COPY --from=admin-build /src/internal/server/web/admin-assets ./internal/server/web/admin-assets
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

FROM alpine:3.20 AS runtime-base
WORKDIR /app
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN apk add --no-cache su-exec && \
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
