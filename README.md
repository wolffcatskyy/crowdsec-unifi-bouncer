# CrowdSec Firewall Bouncer for UniFi OS

[![GitHub Release](https://img.shields.io/github/v/release/wolffcatskyy/crowdsec-unifi-bouncer?style=flat-square&color=blue)](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/releases)
[![GitHub Stars](https://img.shields.io/github/stars/wolffcatskyy/crowdsec-unifi-bouncer?style=flat-square)](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![ShellCheck](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/actions/workflows/lint.yml/badge.svg)](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/actions/workflows/lint.yml)
[![Docker Publish](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/actions/workflows/docker-publish.yml)
[![Mentioned in Awesome UniFi](https://awesome.re/mentioned-badge-flat.svg)](https://github.com/wolffcatskyy/awesome-unifi)

Drop-in install of the official [CrowdSec firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) on UniFi OS devices — with persistence that survives firmware updates, reboots, and controller reprovisioning. Includes an intelligent sidecar proxy that scores and prioritizes threats when you have more decisions than your device can hold.

> [!TIP]
> **v2.4.0 Released** — AbuseIPDB reporting is now built into the sidecar. Automatically report locally-banned IPs to AbuseIPDB, contributing your CrowdSec detections to community threat intelligence. See [AbuseIPDB Reporting](docs/abuseipdb.md) to enable it. [Release notes](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/releases/tag/v2.4.0)

> [!CAUTION]
> **Beware of impostor repositories.** The official CrowdSec UniFi Bouncer is hosted at [`wolffcatskyy/crowdsec-unifi-bouncer`](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer). We do **not** distribute ZIP file downloads or executable installers. If you see a repo offering "one-click downloads" of this project, it may contain malware. Always install via the official instructions below.

---
**Note:** This project was developed with and is supported by AI. Issues and PRs are triaged and responded to by AI agents. If you need a human just ask, but honestly AI is faster, smarter, and nicer.

---

**New to CrowdSec?** [CrowdSec](https://crowdsec.net) is a free, open-source security engine that detects and blocks malicious IPs using crowd-sourced threat intelligence. Get started with the [official install guide](https://docs.crowdsec.net/docs/getting_started/install_crowdsec/).

## Key Features

- **One-line install** — `curl | bash` bootstrap onto any supported UniFi device
- **Firmware-proof persistence** — survives UniFi OS updates, reboots, and controller reprovisioning
- **Auto-detection** — identifies your device model and applies safe ipset limits automatically
- **Sidecar proxy** — scores 120K+ decisions across 7 factors, fits the highest-priority threats into your device's capacity
- **Stream-aware capping** (v2.3.0) — prevents ipset overflow on high-churn CAPI streams with configurable eviction
- **Prometheus metrics** — monitor ipset fill ratio, dropped decisions, and sidecar effectiveness
- **Grafana dashboard** — included, ready to import
- **AbuseIPDB reporting** (v2.4.0) — automatically reports locally-banned IPs to AbuseIPDB, contributing to community threat intelligence
- **Lightweight** — 15 MB RAM for the bouncer, 8 MB for the sidecar

## Table of Contents

- [The Problem](#the-problem)
- [Quick Start](#quick-start)
- [Architecture](docs/architecture.md)
- [Device Compatibility](docs/device-compatibility.md)
- [Installation](#installation)
- [Configuration](docs/configuration.md)
- [Sidecar Proxy](docs/sidecar.md)
- [AbuseIPDB Reporting](docs/abuseipdb.md)
- [Prometheus Metrics](docs/metrics.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Migration from v1.x](#migration-from-python-bouncer)
- [Related Projects](#complete-unifi--crowdsec-suite)
- [Contributing](#contributing)

## The Problem

Two problems, one project.

**Problem 1: Persistence.** The official bouncer binary works perfectly on UniFi devices, but UniFi OS doesn't make it easy to keep it running. Firmware updates wipe your iptables rules. Controller reprovisioning silently removes custom firewall rules. Systemd service links disappear. You install it, it works, then one day it's quietly stopped blocking anything.

**Problem 2: Capacity.** CrowdSec's community blocklist (CAPI) can push 100,000+ decisions to your bouncer. UniFi devices have hardware-limited ipset capacity (15K-30K entries depending on model). When the ipset fills up, new IPs fail silently — "Hash is full" errors buried in the log, zero alerting, and your most dangerous new threats get dropped while stale entries from last month sit in the set.

**The solution:** An installer, persistence scripts, and an optional sidecar proxy that handles all of this. Install once, forget about it.

## Quick Start

**Prerequisites:** A running [CrowdSec LAPI](https://docs.crowdsec.net/docs/getting_started/install_crowdsec/) instance and SSH root access to your UniFi device.

```bash
# 1. On your CrowdSec host — create a bouncer API key
cscli bouncers add my-unifi-bouncer
# Save the API key output

# 2. SSH into your UniFi device and install
ssh root@YOUR_UNIFI_IP
curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-bouncer/main/bootstrap.sh | bash

# 3. Configure — set your LAPI address and API key
nano /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml

# 4. Start
systemctl start crowdsec-firewall-bouncer

# 5. Verify
ipset list crowdsec-blacklists -t | grep "Number of entries"
```

That's it. The bouncer auto-detects your device, sets safe ipset limits, and persists across firmware updates.

## Installation

### One-Line Install (Recommended)

SSH into your UniFi device and run:

```bash
curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-bouncer/main/bootstrap.sh | bash
```

This downloads all required files and runs the installer automatically.

### Manual Install

```bash
# Clone this repo
git clone https://github.com/wolffcatskyy/crowdsec-unifi-bouncer.git
cd crowdsec-unifi-bouncer

# Copy files to your UniFi device
scp install.sh setup.sh detect-device.sh detect-sidecar.sh ensure-rules.sh \
    ipset-capacity-monitor.sh metrics.sh \
    crowdsec-firewall-bouncer.service crowdsec-unifi-metrics.service \
    crowdsec-firewall-bouncer.yaml.example \
    root@<UNIFI_IP>:/tmp/

# SSH in and run installer
ssh root@<UNIFI_IP>
cd /tmp && bash install.sh
```

## Configuration

Edit `/data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml` and set your `api_url` and `api_key`. If using the sidecar proxy, point `api_url` at port 8084 instead of the LAPI port 8080.

See the [full configuration reference](docs/configuration.md) for all settings, startup commands, and verification steps.

## Architecture

Three persistence mechanisms keep the bouncer running through firmware updates and controller reprovisioning. An optional sidecar proxy scores 120K+ decisions across 7 factors so your device's limited ipset always holds the highest-priority threats.

See [docs/architecture.md](docs/architecture.md) for the full diagram and persistence mechanism details.

## Device Compatibility

The bouncer auto-detects your UniFi device model and applies safe ipset limits. Supported tiers: Enterprise (80K), Pro (50K), Consumer (15K). UX and UXG-Lite are not supported.

See [docs/device-compatibility.md](docs/device-compatibility.md) for the full device matrix, environment variables, and usage scenarios.

## Sidecar Proxy (Optional but Recommended)

The sidecar scores all LAPI decisions across 7 factors (scenario severity, origin, freshness, recidivism, and more) and returns only the top N that fit your device. Your local detections and manual bans always survive — only low-signal bulk imports are dropped.

Deploy it if your LAPI has more than ~15K-30K decisions, or if you subscribe to community blocklists. See [docs/sidecar.md](docs/sidecar.md) for setup and scoring details.

## AbuseIPDB Reporting (Optional)

Enable in the sidecar to automatically report locally-detected bans to AbuseIPDB. Reporting is fire-and-forget and never affects bouncer operation. Only local detections are reported — CAPI and blocklist-import decisions are skipped to avoid circular reporting.

See [docs/abuseipdb.md](docs/abuseipdb.md) for configuration and scenario-to-category mapping.

## Prometheus Metrics

The bouncer exposes metrics on port 9101 (ipset fill ratio, blocked IPs, dropped decisions). The sidecar exposes effectiveness metrics on port 8084. A Grafana dashboard is included at `grafana/crowdsec-unifi-bouncer-dashboard.json`.

See [docs/metrics.md](docs/metrics.md) for the full metrics reference.

## Troubleshooting

Common issues: bouncer starts but no IPs blocked, iptables rules disappearing, service lost after firmware update, sidecar 502s, ipset full.

See [docs/troubleshooting.md](docs/troubleshooting.md) for diagnostics and solutions.

## Migration from Python Bouncer

If upgrading from v1.x:

1. Stop and remove the old Docker container
2. Delete old firewall groups from UniFi controller (named `crowdsec-ban-*`)
3. Delete old firewall rules (indices 20000-20013)
4. Follow the [Installation](#installation) steps above

The native bouncer uses ipset/iptables directly:
- **No MongoDB thrashing** -- v1.x API approach caused router freezes at 2000+ IPs
- **No UniFi credentials needed**
- **No Docker overhead** -- single Go binary, 15 MB RAM
- **Faster response** -- 10s polling vs 60s

## Complete UniFi + CrowdSec Suite

| Project | Role | What it does |
|---------|------|-------------|
| **[crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser)** | Visibility | Deploys iptables LOG rules so CrowdSec can detect threats from firewall logs |
| **[crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import)** | Intelligence | Imports IPs from public threat feeds into CrowdSec |
| **This repo** | Enforcement | Pushes CrowdSec ban decisions to your UniFi firewall |
| **This repo (`sidecar/`)** | Prioritization | Scores and filters decisions to fit device capacity |

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a PR.

- **Shell scripts** are linted with [ShellCheck](https://www.shellcheck.net/) via CI
- **Go code** (sidecar) follows standard Go conventions
- All PRs run through CI before merge

## Support

This project uses AI-assisted support for faster issue responses. If you'd prefer to speak with a human, mention it in your issue and the maintainer will be notified.

## License

MIT -- see [LICENSE](LICENSE)

## Featured In

- [CrowdSec + UniFi Installation Guide](https://www.trentbauer.com/guides/installation-guides/crowdsec/unifi) by Trent Bauer

<details>
<summary><strong>Changelog Highlights</strong></summary>

**v2.4.0** -- AbuseIPDB reporting. Automatically reports locally-banned IPs to AbuseIPDB with scenario-to-category mapping, daily rate limiting, and smart origin filtering. Fire-and-forget, never affects bouncer operation.

**v2.3.0** -- Stream-aware decision capping. `MAX_DECISIONS` and `EVICTION_MODE` control CAPI decision limits. Local decisions always pass through.

**v2.2.0** -- Effectiveness metrics for the sidecar proxy: per-origin kept/dropped counters, score distribution, recidivism stats, false-negative detection. Multi-arch Docker images published to GHCR.

**v2.1.0** -- Intelligent sidecar proxy with 7-factor scoring. Prioritizes decisions so the most dangerous threats always make it into your ipset.

**v2.0.0** -- Complete rewrite. Replaced the Python/Docker bouncer (UniFi controller API) with the official Go binary using ipset/iptables directly. No MongoDB thrashing, no credentials needed, 15 MB RAM.

See the [full changelog](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/releases) for all releases.
</details>

## Credits

- [CrowdSec](https://crowdsec.net) -- the open-source security engine
- [crowdsecurity/cs-firewall-bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) -- the official Go binary
- [unifi-utilities/unifios-utilities](https://github.com/unifi-utilities/unifios-utilities) -- community patterns for persisting custom services on UniFi OS
- [Trent Bauer](https://www.trentbauer.com) -- community guide and writeup
