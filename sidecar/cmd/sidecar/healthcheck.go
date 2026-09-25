package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/wolffcatskyy/crowdsec-unifi-bouncer/sidecar/internal/config"
)

// Healthcheck mode lets the distroless image (no shell, no wget) run a Docker
// HEALTHCHECK against its own /health endpoint.
var (
	healthcheck    = flag.Bool("healthcheck", false, "probe the running sidecar's health endpoint and exit 0 (healthy) or 1 (unhealthy)")
	healthcheckURL = flag.String("healthcheck-url", "", "health URL to probe in -healthcheck mode (default: derived from -config, else http://127.0.0.1:8084/health)")
)

const defaultHealthURL = "http://127.0.0.1:8084/health"

// healthURLFromConfig builds the probe URL from listen_addr and health.path.
// Wildcard or empty hosts are probed on loopback.
func healthURLFromConfig(cfg *config.Config) string {
	host, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return defaultHealthURL
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	path := cfg.Health.Path
	if path == "" {
		path = "/health"
	}
	return "http://" + net.JoinHostPort(host, port) + path
}

// runHealthcheck returns the process exit code: 0 on HTTP 2xx, 1 otherwise.
func runHealthcheck(configPath string) int {
	url := *healthcheckURL
	if url == "" {
		url = defaultHealthURL
		if cfg, err := config.Load(configPath); err == nil {
			url = healthURLFromConfig(cfg)
		}
	}

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unhealthy: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		fmt.Fprintf(os.Stderr, "unhealthy: %s returned %d\n", url, resp.StatusCode)
		return 1
	}
	return 0
}
