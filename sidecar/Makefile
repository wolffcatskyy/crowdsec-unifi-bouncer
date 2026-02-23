# CrowdSec LAPI Sidecar Proxy Makefile

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

.PHONY: all build build-local build-linux-arm64 build-linux-amd64 clean test lint run

all: build

# Build for the current platform
build-local:
	go build $(LDFLAGS) -o bin/crowdsec-sidecar ./cmd/sidecar

# Build for Synology NAS (ARM64)
build: build-linux-arm64

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/crowdsec-sidecar-linux-arm64 ./cmd/sidecar

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/crowdsec-sidecar-linux-amd64 ./cmd/sidecar

# Build all targets
build-all: build-local build-linux-arm64 build-linux-amd64

# Clean build artifacts
clean:
	rm -rf bin/

# Run tests
test:
	go test -v -race ./...

# Run tests with coverage
test-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Lint code
lint:
	golangci-lint run

# Run locally for development
run: build-local
	./bin/crowdsec-sidecar -config config.yaml

# Format code
fmt:
	go fmt ./...

# Download dependencies
deps:
	go mod download
	go mod tidy

# Install to /usr/local/bin (requires sudo)
install: build-local
	sudo install -m 755 bin/crowdsec-sidecar /usr/local/bin/crowdsec-sidecar

# Create release tarball
release: build-all
	mkdir -p dist
	tar -czvf dist/crowdsec-sidecar-$(VERSION)-linux-arm64.tar.gz -C bin crowdsec-sidecar-linux-arm64 -C .. config.yaml.example README.md
	tar -czvf dist/crowdsec-sidecar-$(VERSION)-linux-amd64.tar.gz -C bin crowdsec-sidecar-linux-amd64 -C .. config.yaml.example README.md
