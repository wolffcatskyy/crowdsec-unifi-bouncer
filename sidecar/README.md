# CrowdSec LAPI Sidecar Proxy

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

A lightweight Go proxy that sits between your CrowdSec firewall bouncer and the LAPI, scoring and filtering decisions to stay within device ipset/nftset capacity limits.

Production-proven: 2 instances, 20,000+ requests served, 0 failures.

---

## Problem

CrowdSec CAPI community blocklists can contain **120,000+ IP decisions**. Linux kernel ipset and nftset hash tables have practical capacity limits, typically 15,000-30,000 entries depending on device RAM and configuration. When the bouncer attempts to insert more entries than the set's `maxelem` allows, decisions **silently overflow** -- the bouncer reports success but IPs beyond the limit are never blocked. There is no error, no warning, and no indication that your firewall is only enforcing a fraction of the blocklist.

This is especially common on:
- UniFi gateways (UDM, UDR, USG) with default `maxelem` of 16,384-65,536
- Embedded Linux devices with constrained memory
- Any system where CrowdSec CAPI blocklist growth outpaces device capacity

## Solution

```
CrowdSec LAPI (120,000+ decisions)
        |
        v
+------------------------+
|    Sidecar Proxy       |
|    (score + filter)    |
|    Port 8084           |
+------------------------+
        |
        v  (top 18,000 by score)
Firewall Bouncer --> ipset
```

The sidecar intercepts decision requests from your bouncer, fetches the full decision set from LAPI, scores each decision by threat severity, and returns only the top N highest-priority decisions. Lower-risk entries (stale community blocklist IPs, low-severity probes) are dropped first, ensuring your limited ipset capacity is spent on the most dangerous threats.

1. Intercepts `/v1/decisions` and `/v1/decisions/stream` requests from your bouncer
2. Fetches all decisions from the real CrowdSec LAPI upstream
3. Scores each decision across 7 weighted factors
4. Sorts by score descending, truncates to `max_decisions`
5. Caches results to reduce upstream LAPI load
6. Proxies all other paths directly to upstream (transparent to the bouncer)

---

## Scoring System

Each decision receives a composite score. Higher scores survive truncation. The total score is:

```
total = (scenario_base * scenario_multiplier)
      + origin_score
      + ttl_bonus
      + decision_type_score
      + freshness_bonus
      + cidr_bonus
      + recidivism_bonus
```

### All 7 Scoring Factors

| # | Factor | Points | Description |
|---|--------|--------|-------------|
| 1 | **Scenario score** | 0-120 pts (base * 2.0 multiplier) | Pattern-matched against scenario name. SSH brute force (50 base = 100 pts) scores higher than HTTP probing (30 base = 60 pts). Regex patterns supported (e.g., `http-cve-.*`). Unmatched scenarios fall back to `default` (10 base = 20 pts). |
| 2 | **Origin score** | 0-25 pts | `crowdsec`: 25 (local detection -- YOUR network saw this attack). `cscli`: 20 (explicit admin ban). `CAPI`: 10 (community blocklist, crowd-sourced). |
| 3 | **TTL bonus** | 0-10 pts | Linear scaling based on remaining ban duration. 7-day ban = 10 pts (max). 3.5-day ban = 5 pts. Longer bans indicate more serious, persistent threats. |
| 4 | **Decision type** | 0-5 pts | `ban`: 5 pts (full block, highest priority). `captcha`: 0 pts (challenge only). |
| 5 | **Freshness bonus** | 0-15 pts | Created < 1 hour ago: 15 pts. Created < 24 hours ago: 10 pts. Created < 7 days ago: 5 pts. Older than 7 days: 0 pts. Prioritizes active, ongoing attacks. |
| 6 | **CIDR bonus** | 0-20 pts | /0-/16 (large ranges): 20 pts. /17-/24 (medium ranges): 10 pts. /25-/32 (single IPs): 0 pts. Broader ranges block more addresses per ipset entry. |
| 7 | **Recidivism bonus** | 15 pts per extra decision | If an IP has N decisions, each gets +15*(N-1). An IP with 3 decisions gets +30 per decision. Repeat offenders are promoted to survive truncation. |

### What Survives, What Gets Dropped

In production with 125,000 LAPI decisions filtered to 38,000 (UDR cap):

| Origin | LAPI Total | Kept | Kept % | Verdict |
|--------|-----------|------|--------|---------|
| `crowdsec` (local detections) | 268 | 268 | **100%** | All preserved — YOUR network detected these |
| `cscli` (manual bans) | 1 | 1 | **100%** | All preserved — explicit admin action |
| `lists` (curated community) | 14,603 | 14,603 | **100%** | All preserved — community-curated, high signal |
| `CAPI` (community blocklist) | 10,239 | 10,239 | **100%** | All preserved — scored above bulk imports |
| `blocklist-import` (bulk feeds) | 100,210 | 12,889 | **13%** | Bulk feeds absorb all drops |

**The scoring guarantee:** local detections, manual bans, and community intel are always prioritized. Only low-signal bulk blocklist imports are shed — and even within those, IPs that overlap with other sources (recidivism bonus) survive.

### Scoring Examples

| Scenario | Origin | TTL | Type | Age | Scope | Recidivism | Total |
|----------|--------|-----|------|-----|-------|------------|-------|
| ssh-bf (50*2=100) | crowdsec (25) | 7d (10) | ban (5) | <1h (15) | /32 (0) | 1st offense (0) | **155** |
| http-cve-2024-6387 (60*2=120) | CAPI (10) | 4d (5) | ban (5) | <24h (10) | /32 (0) | 1st offense (0) | **150** |
| http-probing (30*2=60) | CAPI (10) | 1d (1) | ban (5) | >7d (0) | /32 (0) | 1st offense (0) | **76** |
| default (10*2=20) | CAPI (10) | 12h (0) | ban (5) | >7d (0) | /32 (0) | 1st offense (0) | **35** |

---

## Configuration Reference

Configuration is a single YAML file. Copy `config.yaml.example` and customize:

```bash
cp config.yaml.example config.yaml
```

### Top-Level Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_addr` | string | `127.0.0.1:8081` | Address and port the sidecar listens on. Use `0.0.0.0:8084` for Docker. |
| `upstream_lapi_url` | string | *required* | URL of your CrowdSec LAPI (e.g., `http://crowdsec:8080`). |
| `upstream_lapi_key` | string | *required* | Bouncer API key. Use the same key your bouncer was registered with. |
| `max_decisions` | int | `15000` | Maximum decisions returned to the bouncer. Set below your ipset `maxelem` -- leave ~2,000 headroom for manual entries and churn. Example: device maxelem=20,000, set max_decisions=18,000. |
| `cache_ttl` | duration | `60s` | How long to cache upstream LAPI responses. Reduces load on LAPI while keeping data fresh enough. |
| `upstream_timeout` | duration | `120s` | Timeout for upstream LAPI requests. Large decision sets (120K+) can take time, especially on `startup=true` stream queries. |
| `log_level` | string | `info` | Log verbosity: `debug`, `info`, `warn`, `error`. JSON-structured output to stdout. |

### Scoring Section

```yaml
scoring:
  scenario_multiplier: 2.0
  scenarios:
    ssh-bf: 50
    ssh-slow-bf: 50
    ssh-cve-2024-6387: 60
    http-cve-.*: 55
    http-sqli: 50
    http-xss: 45
    http-path-traversal: 45
    http-probing: 30
    http-crawl-non_statics: 25
    http-bad-user-agent: 20
    http-sensitive-files: 35
    default: 10
  origins:
    crowdsec: 25
    cscli: 20
    CAPI: 10
  decision_types:
    ban: 5
    captcha: 0
  ttl_scoring:
    enabled: true
    max_bonus: 10
    max_ttl: "168h"
  freshness_bonuses:
    - max_age: "1h"
      bonus: 15
    - max_age: "24h"
      bonus: 10
    - max_age: "168h"
      bonus: 5
  cidr_bonuses:
    - min_prefix: 0
      max_prefix: 16
      bonus: 20
    - min_prefix: 17
      max_prefix: 24
      bonus: 10
    - min_prefix: 25
      max_prefix: 32
      bonus: 0
  recidivism_bonus: 15
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `scenario_multiplier` | float | `2.0` | Multiplier applied to all scenario base scores. Makes scenario the dominant scoring factor. |
| `scenarios` | map[string]int | (see above) | Base score by scenario name. Supports regex patterns (e.g., `http-cve-.*`). The `default` key is the fallback for unmatched scenarios. |
| `origins` | map[string]int | (see above) | Score by decision origin. Local detections (`crowdsec`) are weighted higher than community data (`CAPI`). |
| `decision_types` | map[string]int | ban:5, captcha:0 | Score by decision type. |
| `ttl_scoring.enabled` | bool | `true` | Enable TTL-based bonus scoring. |
| `ttl_scoring.max_bonus` | int | `10` | Maximum bonus points awarded for TTL. |
| `ttl_scoring.max_ttl` | duration | `168h` (7 days) | TTL threshold for maximum bonus. Bans at or above this duration receive full `max_bonus`. |
| `freshness_bonuses` | list | (see above) | Ordered list of age thresholds. First matching threshold wins. |
| `freshness_bonuses[].max_age` | duration | -- | Maximum age for this bonus tier (e.g., `1h`, `24h`). |
| `freshness_bonuses[].bonus` | int | -- | Bonus points awarded if decision age is within `max_age`. |
| `cidr_bonuses` | list | (see above) | Bonus by CIDR prefix length range. Broader ranges (smaller prefix) score higher. |
| `cidr_bonuses[].min_prefix` | int | -- | Minimum prefix length (inclusive). |
| `cidr_bonuses[].max_prefix` | int | -- | Maximum prefix length (inclusive). |
| `cidr_bonuses[].bonus` | int | -- | Bonus points for decisions in this prefix range. |
| `recidivism_bonus` | int | `15` | Extra points per additional decision for the same IP. If an IP has 3 decisions, each gets +15*(3-1) = +30. |

### Health Section

```yaml
health:
  enabled: true
  path: "/health"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `health.enabled` | bool | `true` | Enable the health check endpoint. |
| `health.path` | string | `/health` | Path for the health check endpoint. |

### Metrics Section

```yaml
metrics:
  enabled: true
  path: "/metrics"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `metrics.enabled` | bool | `true` | Enable the Prometheus metrics endpoint. |
| `metrics.path` | string | `/metrics` | Path for the metrics endpoint. |

### Effectiveness Section (v2.2.0)

```yaml
effectiveness:
  top_scenarios: 20
  false_negative_check:
    enabled: true
    interval: 5m
    lookback: 15m
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `effectiveness.top_scenarios` | int | `20` | Number of top scenarios shown individually in metrics. Rest aggregated as "other". |
| `effectiveness.false_negative_check.enabled` | bool | `true` | Enable background false-negative detection. |
| `effectiveness.false_negative_check.interval` | duration | `5m` | How often to check for false negatives. |
| `effectiveness.false_negative_check.lookback` | duration | `15m` | How far back to look for local alerts that match dropped IPs. |

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/decisions` | Returns scored, filtered, and cached decisions. The bouncer's primary polling endpoint. Returns `null` for empty results (matching LAPI behavior). |
| GET | `/v1/decisions/stream` | Scored and filtered decision stream. Supports `?startup=true` for initial full sync. New decisions are scored and truncated; deleted decisions are passed through unmodified. |
| GET | `/health` | Health check. Returns JSON with `status`, `uptime`, and `upstream_healthy` fields. Returns HTTP 503 if upstream LAPI is unreachable (status: `degraded`). |
| GET | `/metrics` | Prometheus-format metrics (see metrics reference below). |
| * | `/*` | All other paths are proxied directly to the upstream LAPI, with the API key injected. Transparent to the bouncer. |

---

## Docker Deployment (Recommended)

Add the sidecar service to your existing CrowdSec compose file. The bouncer connects to the sidecar instead of LAPI directly.

### docker-compose.yaml

```yaml
services:
  crowdsec-sidecar:
    build:
      context: ./sidecar
      args:
        VERSION: ${VERSION:-dev}
        BUILD_TIME: ${BUILD_TIME:-unknown}
    image: crowdsec-sidecar:latest
    container_name: crowdsec-sidecar
    restart: unless-stopped
    networks:
      - crowdsec_network
    ports:
      - "8084:8084"
    volumes:
      - ./sidecar/config.yaml:/etc/crowdsec-sidecar/config.yaml:ro
    environment:
      - TZ=America/Los_Angeles
    depends_on:
      - crowdsec
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8084/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 5s

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    restart: unless-stopped
    networks:
      - crowdsec_network
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/crowdsec
      - ./data:/var/lib/crowdsec/data

networks:
  crowdsec_network:
    external: true
```

### Update Bouncer Configuration

Point your firewall bouncer at the sidecar instead of LAPI:

```yaml
# Before: bouncer connects directly to LAPI
api_url: http://crowdsec:8080

# After: bouncer connects through sidecar
api_url: http://crowdsec-sidecar:8084
```

The sidecar uses the same API key your bouncer was registered with. No changes needed on the CrowdSec or bouncer side beyond the URL.

### Dockerfile

The included multi-stage Dockerfile builds a minimal Alpine-based image:

- Build stage: `golang:1.21-alpine`
- Runtime stage: `alpine:3.19` with `ca-certificates` and `tzdata`
- Runs as non-root user (`sidecar`, UID 1000)
- Built-in healthcheck via `wget`
- Exposes port 8084

---

## Native Binary Deployment

### Build

```bash
# Build for your current platform
make build-local

# Cross-compile for Linux ARM64 (e.g., UniFi gateways, Synology NAS)
make build-linux-arm64

# Cross-compile for Linux AMD64
make build-linux-amd64

# Build all targets
make build-all
```

Binaries are output to `bin/`.

### Run

```bash
./bin/crowdsec-sidecar -config /path/to/config.yaml
```

Flags:
- `-config <path>` -- Path to configuration file (default: `config.yaml`)
- `-version` -- Print version and build time, then exit

### Systemd Service

```ini
[Unit]
Description=CrowdSec LAPI Sidecar Proxy
After=crowdsec.service
Wants=crowdsec.service

[Service]
Type=simple
ExecStart=/usr/local/bin/crowdsec-sidecar -config /etc/crowdsec-sidecar/config.yaml
Restart=always
RestartSec=5
User=sidecar
Group=sidecar

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/crowdsec-sidecar

[Install]
WantedBy=multi-user.target
```

Install the binary:

```bash
make install  # copies to /usr/local/bin (requires sudo)
```

---

## Prometheus Metrics Reference

All metrics are exposed at the `/metrics` endpoint in Prometheus text format.

### Operational Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `crowdsec_sidecar_requests_total` | counter | Total number of requests received by the sidecar (all endpoints). |
| `crowdsec_sidecar_requests_failed_total` | counter | Total number of requests that failed (upstream errors, timeouts). |
| `crowdsec_sidecar_cache_hits_total` | counter | Total number of requests served from cache. |
| `crowdsec_sidecar_cache_misses_total` | counter | Total number of requests that required an upstream LAPI fetch. |
| `crowdsec_sidecar_cached_decisions` | gauge | Current number of decisions held in the response cache. |
| `crowdsec_sidecar_upstream_latency_seconds` | gauge | Latency of the most recent upstream LAPI request, in seconds. |
| `crowdsec_sidecar_max_decisions` | gauge | Configured `max_decisions` limit (static, from config). |
| `crowdsec_sidecar_decisions_total` | gauge | Total number of decisions received from upstream LAPI (before filtering). |
| `crowdsec_sidecar_decisions_dropped` | gauge | Number of decisions dropped due to the `max_decisions` limit. |
| `crowdsec_sidecar_uptime_seconds` | gauge | Time in seconds since the sidecar process started. |

### Effectiveness Metrics (v2.2.0)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crowdsec_sidecar_decisions_kept` | gauge | `origin` | Decisions kept per origin (e.g., `crowdsec`, `CAPI`, `blocklist-import`). |
| `crowdsec_sidecar_decisions_dropped_by_origin` | gauge | `origin` | Decisions dropped per origin. |
| `crowdsec_sidecar_scenario_kept` | gauge | `scenario` | Decisions kept per scenario (top N, rest as "other"). |
| `crowdsec_sidecar_scenario_dropped` | gauge | `scenario` | Decisions dropped per scenario (top N, rest as "other"). |
| `crowdsec_sidecar_score_cutoff` | gauge | | Lowest score that survived truncation. |
| `crowdsec_sidecar_score_max` | gauge | | Highest decision score. |
| `crowdsec_sidecar_score_median` | gauge | | Median decision score across all decisions. |
| `crowdsec_sidecar_score_bucket` | gauge | `le` | Cumulative score distribution. Thresholds: 25, 50, 75, 100, 150, 200. |
| `crowdsec_sidecar_recidivism_ips` | gauge | | Unique IPs that received a recidivism bonus. |
| `crowdsec_sidecar_recidivism_boosts` | gauge | | Total recidivism bonus points applied across all decisions. |
| `crowdsec_sidecar_false_negatives_total` | counter | | IPs that were dropped by scoring but later attacked locally. Should always be 0. |
| `crowdsec_sidecar_false_negative_check_time` | gauge | | Unix timestamp of the last false-negative check. |

### Example Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: crowdsec-sidecar
    static_configs:
      - targets: ['crowdsec-sidecar:8084']
    metrics_path: /metrics
    scrape_interval: 30s
```

---

## Building from Source

### Prerequisites

- Go 1.21 or later
- GNU Make (optional, for convenience targets)

### Build and Test

```bash
# Download dependencies
make deps

# Build for current platform
make build-local

# Run all tests with race detector
go test -race ./...

# Run tests with coverage report
make test-coverage
# Opens coverage.html

# Lint (requires golangci-lint)
make lint

# Format code
make fmt
```

### Make Targets

| Target | Description |
|--------|-------------|
| `build-local` | Build for the current platform |
| `build-linux-arm64` | Cross-compile for Linux ARM64 |
| `build-linux-amd64` | Cross-compile for Linux AMD64 |
| `build-all` | Build all three targets |
| `build` | Alias for `build-linux-arm64` |
| `clean` | Remove `bin/` directory |
| `test` | Run tests with `-race` |
| `test-coverage` | Run tests with coverage, generate HTML report |
| `lint` | Run `golangci-lint` |
| `fmt` | Run `go fmt` |
| `deps` | Download and tidy modules |
| `install` | Install binary to `/usr/local/bin` |
| `run` | Build and run locally with `config.yaml` |
| `release` | Build all targets and create release tarballs in `dist/` |

### Project Structure

```
sidecar/
  cmd/sidecar/main.go          # Entry point, server setup, graceful shutdown
  internal/
    config/config.go            # YAML config loading, validation, defaults
    config/config_test.go       # Config loading and scoring config tests
    lapi/client.go              # HTTP client for CrowdSec LAPI (decisions + alerts)
    lapi/client_test.go         # LAPI client tests (alert fetching)
    proxy/handler.go            # HTTP handler, routing, caching, metrics, false-negative detection
    proxy/handler_test.go       # Handler tests (metrics output, false-negative detection)
    scorer/scorer.go            # Decision scoring, sorting, and effectiveness stats
    scorer/scorer_test.go       # Scoring algorithm and effectiveness metrics tests
  config.yaml.example           # Annotated example configuration
  docker-compose.yaml           # Reference compose file
  Dockerfile                    # Multi-stage Docker build
  Makefile                      # Build, test, and release targets
  go.mod                        # Go module definition
  go.sum                        # Dependency checksums
```

---

## License

[MIT](../LICENSE)
