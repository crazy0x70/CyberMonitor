FROM golang:1.22-alpine AS build

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
EXPOSE 25012
ENTRYPOINT ["/app/cyber-monitor"]
