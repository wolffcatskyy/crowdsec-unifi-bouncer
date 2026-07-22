# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **LOG rule persistence on UCG Fiber / UniFi OS 4.x** — `log-rules.sh` now re-applied via 5-min cron (fixes parser issue #7). Previously, LOG rules were only deployed once at install/boot and vanished after a bouncer restart or iptables flush, while DROP rules already self-healed via `ensure-rules.sh`.

### Added
- **iptables LOG rules** — `log-rules.sh` inserts LOG rules before every DROP rule in UniFi WAN firewall chains, giving CrowdSec visibility into blocked traffic
  - Enables detection of port scans and brute force from already-blocked IPs
  - Structured log prefixes (`[UNIFI-WAN_LOCAL-D-ALL]`, `[UNIFI-WAN_LAN-D-INVALID]`) parseable by crowdsec-unifi-parser
  - Rate-limited (10/min burst 20) to prevent log flooding
  - Idempotent — safe to run repeatedly; cleans up old rules before re-inserting
  - Automatically maintained by `ensure-rules.sh` (survives reboots and firmware updates)
  - Supports all WAN chains: LOCAL, LAN, IN, DMZ, GUEST, VPN, WAN
  - Standalone usage: `--status`, `--remove`, `--quiet` flags

## [2.5.0] - 2026-07-21

### Fixed
- **Stream tracker cap mode silently drops incrementals after full sync** — when a full sync returned more CAPI decisions than `maxDecisions` (e.g., UDM Pro with 20k active vs 15k max), the incremental counter started already over the cap, silently dropping all subsequent incremental decisions. The cap now only applies to INCREMENTAL CAPI additions after the full sync baseline; baseline decisions are tracked separately in `fullSyncSet` and always passed through authoritatively. (Closes #58)
- **Stream tracker evict mode causes mass eviction on restart** — after sidecar restart, `SetCapFromFullSync` repopulated the eviction-ordered `tracked` slice with all baseline CAPI decisions, making evictions potentially replace baseline (full-sync) decisions. The `tracked` slice now only holds incremental decisions; eviction can never touch the authoritative baseline. (Closes #57)

### Added
- `BaseCount` metric to expose the full-sync baseline CAPI decision count separately from incremental `CAPICount`
- 4 new regression tests for #57 and #58 behaviors

## [2.4.0] - 2026-03-13

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

[2.5.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/releases/tag/v2.0.0
