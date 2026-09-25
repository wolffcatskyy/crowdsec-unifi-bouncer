# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Feed confidence scoring (8th scoring factor)** - The sidecar now ranks crowdsec-blocklist-import decisions by source-feed quality instead of treating all bulk imports the same. Feed and confidence are parsed from the scenario name (`external/blocklist-import/<feed>/c<0-100>`, written by blocklist-import with `SCENARIO_FORMAT=structured`). Legacy names (`external/blocklist (Feed Name)`) are recognized too and can get confidence from the new `scoring.feed_scoring.feeds` overrides. Penalty-only (default up to -30 pts), so imports never climb above CAPI, local or manual decisions; decisions with unknown confidence score exactly as before.
- `crowdsec_sidecar_feed_kept{feed}` and `crowdsec_sidecar_feed_dropped{feed}` metrics.
- **Live LAPI CI test** (`.github/workflows/live-lapi.yml`) - Runs crowdsec-blocklist-import with `SCENARIO_FORMAT=structured` against a real CrowdSec container, points the sidecar at that LAPI, and asserts scenarios round-trip byte-for-byte and that truncation drops the lowest-confidence import first while a manual ban survives. Also asserts the LAPI has no online API credentials or console enrollment, so imported alerts cannot leak upstream as community signals.

### Release plan
- Feed confidence scoring ships as opt-in in **v2.6** (importer v3.9, `SCENARIO_FORMAT=structured`).
- Structured becomes the importer default in **v4.0**, staged through its `PRESET` mechanism.
- No public claims about the combined feature until it has run on real UniFi hardware (the CI live-LAPI run covers the software side).

## [2.5.4] - 2026-09-24

### Fixed
- **Bouncer stayed stopped after a UniFi OS firmware update** - Updates keep `/data/` but reset `/etc/` and root's crontab, removing the systemd unit link, the enable link, and the cron jobs. `setup.sh` only runs when the service starts and `ensure-rules.sh` only acts while the bouncer is running, so nothing brought it back and nothing warned. `install.sh` also never ran `systemctl enable`. Reported with a clear write-up by @RichBrew (discussion #46).

### Added
- `boot-restore.sh` - idempotent: re-links and enables the service, restores the cron jobs, and with `--boot` starts the bouncer.
- `install.sh` now enables the service and, when unifios-utilities on-boot-script-2.x is present (`/data/on_boot.d`), installs `/data/on_boot.d/99-crowdsec-bouncer.sh` so this runs on every boot. Without it, the installer warns and prints the manual command.

### Changed
- README and docs no longer claim "firmware-proof" persistence without on-boot-script; new Firmware updates section.

## [2.5.3] - 2026-09-24

### Fixed
- **Capacity monitor always reported 0% fill on ipset 7.x (UniFi OS)** - `ipset-capacity-monitor.sh` parsed maxelem only from a standalone `Maxelem:` line, which ipset 7.x never prints (capacity is inline in the `Header:` line). Result: `Entries: N / 0`, `Fill Ratio: 0%`, and the 90%/95% warnings never fired even near full. Now parses `maxelem` from the `Header:` line with a fallback to the legacy `Maxelem:` line. Reported and root-caused by @ahmaddxb with a tested fix. (Closes #63)

## [2.5.2] - 2026-09-22

### Fixed
- **Bootstrap version selection** — Stop forcing the obsolete upstream firewall-bouncer v0.0.34. The default one-line install now lets `install.sh` resolve the latest upstream release, while an explicit `BOUNCER_VERSION` still pins reproducibly.

## [2.5.1] - 2026-07-21

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

[2.5.4]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.5.3...v2.5.4
[2.5.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/releases/tag/v2.0.0
