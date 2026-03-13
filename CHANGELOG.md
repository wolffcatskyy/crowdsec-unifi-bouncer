# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - v2.4.0

### Added
- **AbuseIPDB reporting** — automatically report locally-banned IPs to [AbuseIPDB](https://www.abuseipdb.com/) via the sidecar proxy
  - Async fire-and-forget reporting — never blocks or affects decision processing
  - CrowdSec scenario-to-AbuseIPDB category mapping (SSH → 22/18, HTTP → 21, etc.)
  - Daily rate limiting (default: 100/day free tier, configurable for premium)
  - Smart origin filtering — only reports local CrowdSec and cscli bans; skips CAPI and blocklist-import decisions to prevent circular reporting
  - Prometheus metrics: `abuseipdb_reports_total`, `abuseipdb_reports_queued`
  - Configurable via environment variables (`ABUSEIPDB_API_KEY`, `ABUSEIPDB_REPORT_ENABLED`) or `config.yaml`
- 19 new tests for AbuseIPDB reporter, config, and handler integration

## [2.3.0] - 2026-03-08

### Added
- **Stream-aware decision capping** — prevents ipset overflow on high-churn CAPI streams
- `MAX_DECISIONS` and `EVICTION_MODE` environment variables for controlling CAPI decision limits
- StreamTracker for cumulative CAPI tracking across incremental updates
- Local decisions (origin: crowdsec, cscli) always pass through regardless of cap
- 7 new Prometheus metrics for stream tracking
- 32 tests for stream capping logic

## [2.2.0] - 2026-03-05

### Added
- **Effectiveness metrics** for the sidecar proxy — per-origin kept/dropped counters, score distribution, recidivism stats, false-negative detection
- Multi-arch Docker images published to GHCR (amd64/arm64)
- GitHub Actions workflow for automated Docker publishing

## [2.1.0]

### Added
- **Intelligent sidecar proxy** with 7-factor scoring system
- Decision prioritization: scores 120K+ decisions across scenario, origin, TTL, decision type, freshness, CIDR, and recidivism factors
- Configurable scoring weights and scenario patterns
- Prometheus metrics endpoint
- Health check endpoint
- Response caching to reduce LAPI load

## [2.0.0]

### Changed
- **Complete rewrite** — replaced Python/Docker bouncer (UniFi controller API) with the official Go binary using ipset/iptables directly
- No MongoDB thrashing, no UniFi credentials needed
- 15 MB RAM footprint (down from ~200 MB)
- 10s polling interval (down from 60s)

### Added
- Auto-detection of UniFi device model with safe ipset limit defaults
- Firmware-proof persistence (survives UniFi OS updates, reboots, controller reprovisioning)
- One-line bootstrap installer
- Cron-based iptables rule recovery
- ipset capacity monitoring with Prometheus metrics

[Unreleased]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.3.0...HEAD
[2.3.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/releases/tag/v2.0.0
