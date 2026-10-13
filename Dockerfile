# syntax=docker/dockerfile:1
FROM golang:1.26.9-bookworm AS build
ARG GOPROXY=https://proxy.golang.org,direct
ENV CGO_ENABLED=0 GOMAXPROCS=2 GOMEMLIMIT=256MiB
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test -trimpath ./... && go build -trimpath -ldflags="-s -w" -o /out/linknest ./cmd/linknest
RUN mkdir -p /out/licenses && cp /usr/local/go/LICENSE /out/licenses/GO-LICENSE \
    && cp /go/pkg/mod/golang.org/x/crypto@v0.48.0/LICENSE /out/licenses/XCRYPTO-LICENSE \
    && cp /go/pkg/mod/golang.org/x/sys@v0.41.0/LICENSE /out/licenses/XSYS-LICENSE \
    && cp /go/pkg/mod/github.com/gorilla/websocket@v1.5.3/LICENSE /out/licenses/WEBSOCKET-LICENSE \
    && cp web/vendor/LICENSE /out/licenses/XTERM-LICENSE \
    && cp /go/pkg/mod/github.com/skip2/go-qrcode@v0.0.0-20200617195104-da1b6568686e/LICENSE /out/licenses/QRCODE-LICENSE

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iptables tzdata \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/linknest /usr/local/bin/linknest
COPY --from=build /out/licenses /usr/share/doc/linknest
ENV LINKNEST_DATA_DIR=/data LINKNEST_ADMIN_ADDR=127.0.0.1:17880 LINKNEST_FIREWALL=disabled \
    GOMEMLIMIT=128MiB GOMAXPROCS=2 TZ=Asia/Shanghai
VOLUME ["/data"]
EXPOSE 17880/tcp
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["linknest", "healthcheck"]
LABEL org.opencontainers.image.version="1.0.3" \
      org.opencontainers.image.source="https://github.com/daixu0502/linknest"
ENTRYPOINT ["/usr/local/bin/linknest"]
