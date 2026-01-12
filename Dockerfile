FROM golang:1.24-alpine AS build

WORKDIR /src
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown
ARG TARGET=server
COPY go.mod ./
COPY go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN go mod download
RUN CGO_ENABLED=0 go build -o /out/cyber-monitor \
  -trimpath \
  -ldflags "-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" \
  ./cmd/${TARGET}

FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/cyber-monitor /app/cyber-monitor
RUN addgroup -S cm && adduser -S -G cm cm && chown -R cm:cm /app
EXPOSE 25012
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:25012/api/v1/health || exit 1
USER cm
ENTRYPOINT ["/app/cyber-monitor"]
