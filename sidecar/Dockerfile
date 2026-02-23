# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Build
ARG VERSION=dev
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 go build \
    -ldflags "-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" \
    -o crowdsec-sidecar ./cmd/sidecar

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/crowdsec-sidecar /usr/local/bin/
COPY config.yaml.example /etc/crowdsec-sidecar/config.yaml.example

# Create non-root user
RUN adduser -D -u 1000 sidecar
USER sidecar

EXPOSE 8084

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8084/health || exit 1

ENTRYPOINT ["crowdsec-sidecar"]
CMD ["-config", "/etc/crowdsec-sidecar/config.yaml"]
