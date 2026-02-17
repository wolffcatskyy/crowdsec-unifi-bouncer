# CrowdSec Firewall Bouncer for UniFi OS

[![Mentioned in Awesome UniFi](https://awesome.re/mentioned-badge.svg)](https://github.com/wolffcatskyy/awesome-unifi)

---
**Note:** This project was developed with and is supported exclusively by AI. There is no human support — issues and PRs are triaged and responded to by AI agents. If AI-assisted software isn't for you, no hard feelings — but you might want to reconsider, since so is most of the software you already use.

---

Drop-in install of the official [CrowdSec firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) on UniFi OS devices — with persistence that survives firmware updates, reboots, and controller reprovisioning.

> **New to CrowdSec?** [CrowdSec](https://crowdsec.net) is a free, open-source security engine that detects and blocks malicious IPs. It works like fail2ban but with crowd-sourced threat intelligence and a modern bouncer ecosystem. Install it, connect bouncers to your firewalls/proxies, and threats get blocked network-wide. Get started with the [official install guide](https://docs.crowdsec.net/docs/getting_started/install_crowdsec/).

**The problem:** The official bouncer binary works perfectly on UniFi devices, but UniFi OS doesn't make it easy to keep it running. Firmware updates wipe your iptables rules. Controller reprovisioning silently removes custom firewall rules. There's no package manager. Systemd service links disappear. You install it, it works, then one day it's quietly stopped blocking anything.

**The solution:** An installer and three small scripts that handle all of this automatically. Install once, forget about it.

> **v2.0**: Replaced the old Python/Docker bouncer that used the UniFi controller API. That approach hit MongoDB write storms that froze routers at 2000+ IPs. The native bouncer uses ipset and iptables directly — no controller API, no credentials, 15MB process RAM. See [Migration from Python Bouncer](#migration-from-python-bouncer) if upgrading from v1.x.

## Device Defaults

The bouncer auto-detects your UniFi device and applies tested defaults:

| Device | Default | RAM |
|--------|---------|-----|
| UDM Pro Max | 30,000 IPs | 8GB |
| UDM Pro / SE | 20,000 IPs | 4GB |
| UDR / UCG | 15,000 IPs | 2GB |
| UniFi Express | 10,000 IPs | 1GB |

These limits balance protection coverage with device stability. Most CrowdSec deployments with standard community blocklists stay well under 20,000 active decisions.

### Advanced: Increasing Limits

If you need higher capacity, set `ipset_size` in the bouncer config:

```yaml
ipset_size: 40000
```

**Signs you've gone too high:**
- UniFi UI becomes sluggish
- Network latency increases
- Packet drops appear

Large ipsets consume memory and add latency to every packet lookup. If you see these symptoms, reduce `ipset_size` and restart.

## What's Included

| File | Purpose |
|------|---------|
| `bootstrap.sh` | One-line installer — downloads everything and runs setup |
| `install.sh` | Downloads the official bouncer binary, installs to `/data/crowdsec-bouncer/` |
| `setup.sh` | ExecStartPre script — loads ipset modules, creates ipset, adds iptables rules, re-links systemd service |
| `detect-device.sh` | Auto-detects UniFi model and sets safe maxelem defaults |
| `ensure-rules.sh` | Cron job (every 5 min) — re-adds iptables rules if controller reprovisioning removed them |
| `ipset-capacity-monitor.sh` | Monitors for "set is full" errors, logs dropped decisions, updates metrics |
| `metrics.sh` | Prometheus metrics endpoint for monitoring |

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
scp install.sh setup.sh ensure-rules.sh \
    crowdsec-firewall-bouncer.service \
    crowdsec-firewall-bouncer.yaml.example \
    root@<UNIFI_IP>:/tmp/

# SSH in and run installer
ssh root@<UNIFI_IP>
cd /tmp && bash install.sh
```

## Configuration

```bash
cp crowdsec-firewall-bouncer.yaml.example /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml
nano /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml
```

**Critical settings:**

```yaml
api_url: http://192.168.1.100:8081/    # Your CrowdSec LAPI address
api_key: YOUR_BOUNCER_API_KEY           # From 'cscli bouncers add'
ipset_size: 20000                        # Match your device's default or customize
```

### Config Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `mode` | `ipset` | Use ipset for efficient IP matching |
| `update_frequency` | `10s` | How often to poll LAPI for new decisions |
| `ipset_size` | `20000` | Max IPs to request from LAPI |
| `disable_ipv6` | `true` | UniFi has issues with IPv6 firewall rules |
| `deny_action` | `DROP` | `DROP` (silent) or `REJECT` (sends reset) |

## Start the Bouncer

```bash
# Copy persistence scripts to device
scp setup.sh ensure-rules.sh crowdsec-firewall-bouncer.service root@<UNIFI_IP>:/data/crowdsec-bouncer/
ssh root@<UNIFI_IP>

# Make scripts executable
chmod +x /data/crowdsec-bouncer/setup.sh /data/crowdsec-bouncer/ensure-rules.sh

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

1. **`setup.sh` (ExecStartPre)** — Runs before every bouncer start. Loads ipset modules, creates ipset, adds iptables rules, re-links systemd service.

2. **`ensure-rules.sh` (cron, every 5 min)** — Catches controller reprovisioning that silently removes iptables rules while bouncer is running.

3. **Everything in `/data/crowdsec-bouncer/`** — One persistent directory that survives whatever UniFi OS throws at it.

## Resource Usage

| Metric | Value |
|--------|-------|
| Process RAM | 15-22 MB |
| CPU | <1% average |
| Disk | ~15 MB (binary + logs) |

## Capacity Monitoring

When ipset reaches capacity, the bouncer logs errors and new IPs can't be added. The `ipset-capacity-monitor.sh` script detects this and exposes metrics:

```bash
# Check current status
/data/crowdsec-bouncer/ipset-capacity-monitor.sh --status
```

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
curl -s http://YOUR_LAPI:8081/v1/decisions -H "X-Api-Key: YOUR_KEY" | head
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
2. Reduce `ipset_size` in config before restarting bouncer

## Complete UniFi + CrowdSec Suite

| Project | Role | What it does |
|---------|------|-------------|
| **[crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser)** | Visibility | Deploys iptables LOG rules so CrowdSec can detect threats from firewall logs |
| **[crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import)** | Intelligence | Imports IPs from public threat feeds into CrowdSec |
| **This repo** | Enforcement | Pushes CrowdSec ban decisions to your UniFi firewall |

## License

MIT — see [LICENSE](LICENSE)

## Credits

- [CrowdSec](https://crowdsec.net) — the open-source security engine
- [crowdsecurity/cs-firewall-bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) — the official Go binary
- [unifi-utilities/unifios-utilities](https://github.com/unifi-utilities/unifios-utilities) — community patterns for persisting custom services on UniFi OS
