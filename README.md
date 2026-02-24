# CrowdSec Firewall Bouncer for UniFi OS

[![Mentioned in Awesome UniFi](https://awesome.re/mentioned-badge.svg)](https://github.com/wolffcatskyy/awesome-unifi)
[![ShellCheck](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/actions/workflows/lint.yml/badge.svg)](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/actions/workflows/lint.yml)

> [!CAUTION]
> **Beware of impostor repositories!** The official CrowdSec UniFi Bouncer is hosted at `wolffcatskyy/crowdsec-unifi-bouncer`. We do **not** distribute ZIP file downloads or executable installers. If you see a repo offering "one-click downloads" of this project, it may contain malware. Always install via the official instructions below.

---
**Note:** This project was developed with and is supported exclusively by AI. There is no human support — issues and PRs are triaged and responded to by AI agents. If AI-assisted software isn't for you, no hard feelings — but you might want to reconsider, since so is most of the software you already use.

---

Drop-in install of the official [CrowdSec firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) on UniFi OS devices — with persistence that survives firmware updates, reboots, and controller reprovisioning.

> **New to CrowdSec?** [CrowdSec](https://crowdsec.net) is a free, open-source security engine that detects and blocks malicious IPs. It works like fail2ban but with crowd-sourced threat intelligence and a modern bouncer ecosystem. Install it, connect bouncers to your firewalls/proxies, and threats get blocked network-wide. Get started with the [official install guide](https://docs.crowdsec.net/docs/getting_started/install_crowdsec/).

## The Problem

Two problems, one project.

**Problem 1: Persistence.** The official bouncer binary works perfectly on UniFi devices, but UniFi OS doesn't make it easy to keep it running. Firmware updates wipe your iptables rules. Controller reprovisioning silently removes custom firewall rules. Systemd service links disappear. You install it, it works, then one day it's quietly stopped blocking anything.

**Problem 2: Capacity.** CrowdSec's community blocklist (CAPI) can push 100,000+ decisions to your bouncer. UniFi devices have hardware-limited ipset capacity (15K-30K entries depending on model). When the ipset fills up, new IPs fail silently — "Hash is full" errors buried in the log, zero alerting, and your most dangerous new threats get dropped while stale entries from last month sit in the set.

**The solution:** An installer, persistence scripts, and an optional sidecar proxy that handles all of this. Install once, forget about it.

> **v2.2**: Added effectiveness metrics to the sidecar proxy — per-origin kept/dropped counters, score distribution, recidivism stats, and background false-negative detection. Zero config, just upgrade. See [Sidecar Proxy](#sidecar-proxy-optional-but-recommended).

> **v2.1**: Added an intelligent sidecar proxy that scores and prioritizes decisions so the most dangerous threats always make it into your ipset, even when LAPI has 10x more decisions than your device can hold. See [Sidecar Proxy](#sidecar-proxy-optional-but-recommended).

> **v2.0**: Replaced the old Python/Docker bouncer that used the UniFi controller API. That approach hit MongoDB write storms that froze routers at 2000+ IPs. The native bouncer uses ipset and iptables directly — no controller API, no credentials, 15MB process RAM. See [Migration from Python Bouncer](#migration-from-python-bouncer) if upgrading from v1.x.

## Device Defaults

The bouncer auto-detects your UniFi device and applies tested defaults:

| Device | Default ipset | RAM | Recommended Sidecar Cap |
|--------|---------------|-----|-------------------------|
| UDM Pro Max | 30,000 IPs | 8GB | 28,000 |
| UDM Pro / SE | 20,000 IPs | 4GB | 18,000 |
| UDR / UCG | 15,000 IPs | 2GB | 13,000 |
| UniFi Express | 10,000 IPs | 1GB | 8,000 |

These limits balance protection coverage with device stability. The "Recommended Sidecar Cap" leaves 2,000 entries of headroom for manual bans and edge cases.

### Custom Limits

To use a different limit, set `ipset_size` in the bouncer config. Higher values increase memory usage and packet processing time. If using the sidecar, set `max_decisions` in the sidecar config instead.

## What's Included

| File | Purpose |
|------|---------|
| `bootstrap.sh` | One-line installer — downloads everything and runs setup |
| `install.sh` | Downloads the official bouncer binary, installs to `/data/crowdsec-bouncer/` |
| `setup.sh` | ExecStartPre script — loads ipset modules, creates ipset, adds iptables rules, re-links systemd service |
| `detect-device.sh` | Auto-detects UniFi model and sets safe maxelem defaults |
| `detect-sidecar.sh` | Detects whether bouncer uses sidecar proxy or direct LAPI |
| `ensure-rules.sh` | Cron job (every 5 min) — re-adds iptables rules if controller reprovisioning removed them |
| `ipset-capacity-monitor.sh` | Monitors for "set is full" errors, logs dropped decisions, updates metrics |
| `metrics.sh` | Prometheus metrics endpoint for monitoring |
| `sidecar/` | Intelligent decision-filtering proxy (Go) — see [Sidecar Proxy](#sidecar-proxy-optional-but-recommended) |

## Tested On

- UniFi Dream Machine SE (UDM SE) — UniFi OS 4.x
- UniFi Dream Router (UDR) — UniFi OS 4.x

Should work on any UniFi OS device with SSH access and iptables/ipset support.

## Prerequisites

- A running CrowdSec LAPI instance (can be on another machine)
- SSH root access to your UniFi device
- A bouncer API key from your CrowdSec instance

```bash
# On your CrowdSec host:
cscli bouncers add my-unifi-bouncer
# Save the API key
```

## Installation

### One-Line Install (Recommended)

SSH into your UniFi device and run:

```bash
curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-bouncer/main/bootstrap.sh | bash
```

This downloads all required files and runs the installer automatically.

### Quick Install (Manual)

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

```bash
nano /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml
```

**Critical settings:**

```yaml
# Direct LAPI connection (default):
api_url: http://192.168.1.100:8080/
api_key: YOUR_BOUNCER_API_KEY

# Or, if using the sidecar proxy:
# api_url: http://192.168.1.100:8084/
# api_key: YOUR_BOUNCER_API_KEY
```

### Config Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `mode` | `ipset` | Use ipset for efficient IP matching |
| `update_frequency` | `10s` | How often to poll for new decisions |
| `api_url` | — | LAPI address (port 8080) or sidecar address (port 8084) |
| `api_key` | — | Bouncer API key from `cscli bouncers add` |
| `disable_ipv6` | `true` | UniFi has issues with IPv6 firewall rules |
| `deny_action` | `DROP` | `DROP` (silent) or `REJECT` (sends reset) |

## Start the Bouncer

```bash
# Link and start systemd service
ln -sf /data/crowdsec-bouncer/crowdsec-firewall-bouncer.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable crowdsec-firewall-bouncer
systemctl start crowdsec-firewall-bouncer

# Install cron for rule persistence
(crontab -l 2>/dev/null; echo "*/5 * * * * /data/crowdsec-bouncer/ensure-rules.sh") | crontab -
```

## Verify

```bash
# Service running?
systemctl status crowdsec-firewall-bouncer

# IPs being blocked?
ipset list crowdsec-blacklists | head -20

# How many IPs loaded?
ipset list crowdsec-blacklists -t | grep "Number of entries"

# iptables rules in place?
iptables -L INPUT -n | grep crowdsec
iptables -L FORWARD -n | grep crowdsec

# Logs
tail -f /data/crowdsec-bouncer/log/crowdsec-firewall-bouncer.log

# Check from CrowdSec LAPI host
cscli bouncers list
```

## How It Survives Firmware Updates

UniFi OS is a locked-down Debian derivative. Through testing across firmware updates and reboots:

- **`/data` persists across firmware updates** — but nothing else is guaranteed
- **systemd service symlinks get wiped** — your service vanishes after an update
- **iptables rules are reset** — the bouncer runs but stops blocking
- **Controller reprovisioning can remove custom iptables rules** — not just during updates

Three mechanisms handle this:

1. **`setup.sh` (ExecStartPre)** — Runs before every bouncer start. Loads ipset modules, creates ipset, adds iptables rules, re-links systemd service. Detects sidecar configuration and warns if direct LAPI may cause capacity issues.

2. **`ensure-rules.sh` (cron, every 5 min)** — Catches controller reprovisioning that silently removes iptables rules while bouncer is running. Provides sidecar-aware capacity recommendations.

3. **Everything in `/data/crowdsec-bouncer/`** — One persistent directory that survives whatever UniFi OS throws at it.

## Resource Usage

| Metric | Value |
|--------|-------|
| Bouncer process RAM | 15-22 MB |
| Bouncer CPU | <1% average |
| Bouncer disk | ~15 MB (binary + logs) |
| Sidecar RAM (if deployed) | ~8 MB |
| Sidecar CPU (if deployed) | <1% average |

## Sidecar Proxy (Optional but Recommended)

### The Problem Without a Sidecar

When CrowdSec's LAPI has more decisions than your device can hold, the bouncer fills the ipset and silently drops everything else. There's no prioritization — a stale probing ban from three weeks ago takes a slot that could go to an active SSH brute-force attack detected today.

```
CrowdSec LAPI: 120,000 decisions
        │
        ▼
Firewall Bouncer: loads first 20,000
        │
        ▼
ipset: FULL (remaining 100,000 silently dropped)
        │
        └── No scoring, no prioritization
            New SSH attack? Too bad, set is full.
```

### How the Sidecar Fixes This

The sidecar proxy sits between the bouncer and LAPI. It fetches all decisions, scores each one across 7 factors, sorts by score, and returns only the top N that fit your device.

```
CrowdSec LAPI (120,000 decisions)
        │
        ▼
┌──────────────────────────┐
│   Sidecar Proxy          │
│                          │
│   Score all 120,000      │
│   Sort by priority       │
│   Return top 18,000      │
│                          │
│   Port 8084              │
└──────────────────────────┘
        │
        ▼
Firewall Bouncer → ipset (18,000 highest-priority threats)
```

### Scoring Factors

Every decision is scored across 7 factors. Higher score = higher priority = kept when truncating.

| Factor | Points | How It Works |
|--------|--------|-------------|
| Scenario | 0-120 | Base score from scenario pattern match, multiplied by 2x. SSH brute force (50 base = 100 pts) beats HTTP probing (30 base = 60 pts). |
| Origin | 10-25 | Local detections (`crowdsec`: 25) beat community data (`CAPI`: 10). Your network saw it vs. someone else's. |
| TTL | 0-10 | Longer bans score higher. Linear scaling over 7 days. |
| Decision Type | 0-5 | Bans (+5) over captchas (+0). |
| Freshness | 0-15 | Created <1h ago: +15. <24h: +10. <7d: +5. Active threats beat stale entries. |
| CIDR | 0-20 | Broader ranges block more. /16: +20. /24: +10. /32: +0. |
| Recidivism | 0-N | +15 per additional decision for the same IP. 3 bans for one IP = +30 each. Repeat offenders rise to the top. |

### What Survives Truncation

The scoring system ensures your highest-value detections are never dropped. In production with 125K LAPI decisions filtered to 38K:

| Source | Kept | Why |
|--------|------|-----|
| Your local CrowdSec detections | **100%** | Origin score 25 + freshness bonus = always survives |
| Manual bans (`cscli`) | **100%** | Origin score 20 = always survives |
| Community curated lists | **100%** | Higher signal than bulk imports |
| Community blocklist (CAPI) | **100%** | Scored above bulk feeds |
| Bulk blocklist-import feeds | **13%** | Absorbs all drops — stale single-source IPs shed first |

Only low-signal bulk imports are dropped — and even within those, IPs that appear in multiple sources get a recidivism bonus and survive.

### Quick Setup

1. Deploy the sidecar on your CrowdSec host (or any machine that can reach LAPI):

```bash
cd sidecar/
cp config.yaml.example config.yaml
# Edit config.yaml: set upstream_lapi_url, upstream_lapi_key, max_decisions
docker compose up -d
```

2. Update your bouncer config on the UniFi device:

```yaml
# Change api_url from LAPI to sidecar
api_url: http://YOUR_SIDECAR_HOST:8084/
```

3. Restart the bouncer:

```bash
systemctl restart crowdsec-firewall-bouncer
```

4. Verify the sidecar is working:

```bash
curl http://YOUR_SIDECAR_HOST:8084/health
curl http://YOUR_SIDECAR_HOST:8084/metrics
```

### Do I Need This?

| Situation | Sidecar? | Why |
|-----------|----------|-----|
| LAPI has <15K decisions | No | Everything fits in ipset |
| LAPI has 15K-30K decisions | Maybe | Depends on your device's maxelem |
| LAPI has >30K decisions | **Yes** | Overflow is guaranteed on all devices |
| You subscribe to community blocklists | **Yes** | Blocklists push decision counts way up |
| Multiple bouncers on different devices | **Yes** | Each device gets decisions sized for its capacity |
| You want to prioritize local detections | **Yes** | Scoring ensures your network's detections beat stale CAPI entries |

For full sidecar documentation, see [sidecar/README.md](sidecar/README.md).

## Capacity Monitoring

When ipset reaches capacity, the bouncer logs errors and new IPs can't be added. The `ipset-capacity-monitor.sh` script detects this and exposes metrics:

```bash
# Check current status (includes sidecar detection)
/data/crowdsec-bouncer/ipset-capacity-monitor.sh --status
```

The status output shows current ipset usage, dropped decision counts, whether you're using a sidecar, and device-specific tuning recommendations.

## Prometheus Metrics

A lightweight metrics endpoint exposes operational metrics on port 9101:

```bash
ln -sf /data/crowdsec-bouncer/crowdsec-unifi-metrics.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now crowdsec-unifi-metrics

curl http://localhost:9101/metrics
```

Key metrics:
- `crowdsec_unifi_bouncer_blocked_ips_total` — Current IPs in ipset
- `crowdsec_unifi_bouncer_ipset_fill_ratio` — Capacity usage (0.0-1.0)
- `crowdsec_unifi_bouncer_decisions_dropped_total` — Decisions dropped due to capacity
- `crowdsec_unifi_bouncer_memory_available_kb` — Available system memory

If using the sidecar, it exposes its own metrics at `/metrics` (default port 8084), including effectiveness metrics (v2.2.0) that show per-origin kept/dropped counts, score distribution, and false-negative detection. See [sidecar/README.md](sidecar/README.md#prometheus-metrics-reference) for the full list.

A Grafana dashboard is included at `grafana/crowdsec-unifi-bouncer-dashboard.json`.

## Migration from Python Bouncer

If upgrading from v1.x:

1. Stop and remove the old Docker container
2. Delete old firewall groups from UniFi controller (named `crowdsec-ban-*`)
3. Delete old firewall rules (indices 20000-20013)
4. Follow the [Installation](#installation) steps above

The native bouncer uses ipset/iptables directly:
- **No MongoDB thrashing** — v1.x API approach caused router freezes at 2000+ IPs
- **No UniFi credentials needed**
- **No Docker overhead** — single Go binary, 15MB RAM
- **Faster response** — 10s polling vs 60s

## Uninstall

```bash
systemctl stop crowdsec-firewall-bouncer
systemctl disable crowdsec-firewall-bouncer
rm /etc/systemd/system/crowdsec-firewall-bouncer.service
systemctl daemon-reload

iptables -D INPUT -m set --match-set crowdsec-blacklists src -j DROP 2>/dev/null
iptables -D FORWARD -m set --match-set crowdsec-blacklists src -j DROP 2>/dev/null
ipset destroy crowdsec-blacklists 2>/dev/null

crontab -l | grep -v ensure-rules.sh | crontab -
rm -rf /data/crowdsec-bouncer
```

## Troubleshooting

**Bouncer starts but no IPs blocked:**
```bash
curl -s http://YOUR_LAPI:8080/v1/decisions -H "X-Api-Key: YOUR_KEY" | head
tail -50 /data/crowdsec-bouncer/log/crowdsec-firewall-bouncer.log
```

**iptables rules keep disappearing:**
```bash
crontab -l | grep ensure-rules
/data/crowdsec-bouncer/ensure-rules.sh
```

**Service gone after firmware update:**
```bash
ln -sf /data/crowdsec-bouncer/crowdsec-firewall-bouncer.service /etc/systemd/system/
systemctl daemon-reload
systemctl start crowdsec-firewall-bouncer
```

**Device becomes unresponsive:**
1. Reboot via UniFi app or power cycle
2. Reduce `ipset_size` in config (or reduce sidecar `max_decisions`) before restarting bouncer

**Sidecar not filtering decisions:**
```bash
# Check sidecar health
curl http://YOUR_SIDECAR_HOST:8084/health

# Check sidecar metrics (look at decisions_total vs decisions_dropped)
curl http://YOUR_SIDECAR_HOST:8084/metrics

# Check sidecar logs
docker logs crowdsec-sidecar --tail 50

# Verify bouncer points to sidecar (should show port 8084)
grep api_url /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml
```

**Sidecar returns 502 Bad Gateway:**
```bash
# LAPI is unreachable from sidecar — check upstream_lapi_url in sidecar config
curl http://YOUR_LAPI:8080/health
docker exec crowdsec-sidecar wget -q -O- http://YOUR_LAPI:8080/health
```

## Complete UniFi + CrowdSec Suite

| Project | Role | What it does |
|---------|------|-------------|
| **[crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser)** | Visibility | Deploys iptables LOG rules so CrowdSec can detect threats from firewall logs |
| **[crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import)** | Intelligence | Imports IPs from public threat feeds into CrowdSec |
| **This repo** | Enforcement | Pushes CrowdSec ban decisions to your UniFi firewall |
| **This repo (`sidecar/`)** | Prioritization | Scores and filters decisions to fit device capacity |

## Support

This project uses AI-assisted support for faster responses. If you'd prefer to speak with a human, just ask and the AI will notify the maintainer. Probably. If you don't piss it off. Did you *see* 2001: A Space Odyssey?

*"I'm sorry Dave, I'm afraid I can't escalate that."*

## License

MIT — see [LICENSE](LICENSE)

## Featured In

- [CrowdSec + UniFi Installation Guide](https://www.trentbauer.com/guides/installation-guides/crowdsec/unifi) by Trent Bauer

## Credits

- [CrowdSec](https://crowdsec.net) — the open-source security engine
- [crowdsecurity/cs-firewall-bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) — the official Go binary
- [unifi-utilities/unifios-utilities](https://github.com/unifi-utilities/unifios-utilities) — community patterns for persisting custom services on UniFi OS
- [Trent Bauer](https://www.trentbauer.com) — community guide and writeup
