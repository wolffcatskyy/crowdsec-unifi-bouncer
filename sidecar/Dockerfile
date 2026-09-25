# syntax=docker/dockerfile:1
#
# CrowdSec LAPI Sidecar Proxy
#
# Targets:
#   runtime (default) - distroless static, no shell, runs as UID 1000
#   debug             - same binary on distroless :debug-nonroot (busybox shell)
#
#   docker build -t crowdsec-sidecar .                     # runtime
#   docker build --target debug -t crowdsec-sidecar:debug . # debug

# Build stage. --platform=$BUILDPLATFORM keeps the compiler native on the CI
# host; Go cross-compiles for the target arch (no QEMU emulation needed).
FROM --platform=$BUILDPLATFORM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS builder

WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
ARG BUILD_TIME=unknown
RUN GOARM=${TARGETVARIANT#v} CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" \
    -o /out/crowdsec-sidecar ./cmd/sidecar

# Debug stage: busybox shell for troubleshooting. Published as :debug / :<version>-debug.
FROM gcr.io/distroless/static-debian12:debug-nonroot@sha256:d5563cc7f2f44313f332e91138cc8c6a158899afeeeab2fce3b0f9ccdb3cf9ee AS debug

ARG VERSION=dev
LABEL org.opencontainers.image.title="crowdsec-sidecar (debug)" \
      org.opencontainers.image.source="https://github.com/wolffcatskyy/crowdsec-unifi-bouncer" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /out/crowdsec-sidecar /usr/local/bin/crowdsec-sidecar
COPY config.yaml.example /etc/crowdsec-sidecar/config.yaml.example

USER 1000:1000
EXPOSE 8084

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/crowdsec-sidecar", "-healthcheck", "-config", "/etc/crowdsec-sidecar/config.yaml"]

ENTRYPOINT ["/usr/local/bin/crowdsec-sidecar"]
CMD ["-config", "/etc/crowdsec-sidecar/config.yaml"]

# Runtime stage (default, last): distroless static - no shell, no package
# manager. Includes CA certificates and tzdata, so TZ= still works.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime

ARG VERSION=dev
LABEL org.opencontainers.image.title="crowdsec-sidecar" \
      org.opencontainers.image.description="CrowdSec LAPI sidecar proxy that keeps decisions within ipset capacity" \
      org.opencontainers.image.source="https://github.com/wolffcatskyy/crowdsec-unifi-bouncer" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /out/crowdsec-sidecar /usr/local/bin/crowdsec-sidecar
COPY config.yaml.example /etc/crowdsec-sidecar/config.yaml.example

USER 1000:1000
EXPOSE 8084

# No wget in distroless: the binary probes its own /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/crowdsec-sidecar", "-healthcheck", "-config", "/etc/crowdsec-sidecar/config.yaml"]

ENTRYPOINT ["/usr/local/bin/crowdsec-sidecar"]
CMD ["-config", "/etc/crowdsec-sidecar/config.yaml"]
