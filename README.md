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

## WARNING: ipset Limits Are UNTESTED ESTIMATES

**This is critical.** The ipset maxelem values in this bouncer are **CONSERVATIVE GUESSES**, not empirically verified limits. We have NOT systematically tested stability on each UniFi device model.

### What we know:
- UniFi devices have limited RAM and ipset capacity
- Large ipsets can crash devices or cause kernel instability
- Memory is not the only bottleneck — ipset operations themselves can cause issues

### What we DON'T know:
- Actual safe limits for each device model under real-world conditions
- How different UniFi applications (Protect, Talk, Access) affect available headroom
- Whether limits vary by firmware version

### Default: 20,000 IPs for ALL devices

We've intentionally set a very conservative default (20,000 entries) for all device models. This is almost certainly lower than what your device can handle, but we'd rather you start safe than crash your router.

### How to find YOUR device's actual limit:

1. **Start with the default** (20,000 entries)
2. **Monitor memory continuously:**
   ```bash
   cat /proc/meminfo | grep MemAvailable
   ```
3. **Run for 24-48 hours** under typical network load
4. **If stable with >500MB available**, increase by 5,000 entries
5. **Repeat** until you find instability, then back off 10,000
6. **Report your findings!** Open an issue with your device model, firmware version, running applications, and tested stable limit

### Help us build real data

If you successfully run this bouncer, please report your experience via [GitHub Issues](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/issues):

```
Device: [model]
Firmware: [version]
UniFi Apps Running: [Protect/Talk/Access/etc]
Stable maxelem: [number]
MemAvailable at that level: [KB]
Duration tested: [hours/days]
```

With community reports, we can build a real database of tested limits.

## Automatic Device Detection

The bouncer auto-detects your UniFi device model and sets conservative defaults.

**How it works:**
- `detect-device.sh` identifies your device using `ubnt-device-info model`
- Sets `SAFE_MAXELEM` to a conservative 20,000 (same for all devices)
- `setup.sh` uses this value unless you override with `MAXELEM` environment variable
- Prints warnings reminding you these are untested estimates

**Run detection manually:**
```bash
/data/crowdsec-bouncer/detect-device.sh
```

Output:
```
=== UniFi Device Detection ===
Detected model: UniFi Dream Machine SE
Total memory: 3946MB
Suggested maxelem: 20000 (CONSERVATIVE DEFAULT)

==========================================================================
WARNING: ipset LIMITS ARE UNTESTED ESTIMATES
==========================================================================
The suggested maxelem value (20000) is a CONSERVATIVE GUESS, not a
verified safe limit for your device. Real stability depends on:
  - Running UniFi applications (Protect, Talk, Access use RAM)
  - Current system load and memory pressure
  - Firmware version

RECOMMENDED:
  1. Start with this conservative default (20,000)
  2. Monitor memory: cat /proc/meminfo | grep MemAvailable
  3. Run for 24-48 hours under typical load
  4. If stable with >500MB free, increase by 5,000 and repeat
  5. Report your tested limits via GitHub issues!
==========================================================================
```

**Override detection:**
```bash
# Set custom maxelem in environment (e.g., in systemd service)
MAXELEM=30000 /data/crowdsec-bouncer/setup.sh
```

### Auto-Detection from RAM (NEW)

Instead of using the conservative 20,000 default, you can enable automatic maxelem calculation based on available RAM:

```bash
# Enable auto-detection (calculates from available RAM)
AUTO_MAXELEM=true /data/crowdsec-bouncer/setup.sh
```

**How it works:**
- Queries `/proc/meminfo` for `MemAvailable`
- Uses a conservative 10% of available RAM budget
- Assumes ~100 bytes overhead per ipset entry (includes kernel allocation overhead)
- Rounds down to nearest 5,000
- Applies minimum of 10,000 and maximum of 200,000

**Formula:** `maxelem = available_ram_kb` (approximately, with bounds applied)

This is intentionally conservative. Real-world testing shows UniFi devices can become unstable with large ipsets even when RAM appears available, due to kernel memory fragmentation and ipset operation latency.

**Example on a UDM-SE with 1.5GB available:**
```
Available: 1,536,000 KB
Calculation: 1,536,000 -> capped at 200,000
Result: 200,000 entries
```

**Example on a UDR with 500MB available:**
```
Available: 512,000 KB
Calculation: 512,000 -> rounded to 510,000, capped at 200,000
Result: 200,000 entries
```

**To enable permanently**, edit the systemd service:
```bash
nano /data/crowdsec-bouncer/crowdsec-firewall-bouncer.service
```

Add to `[Service]` section:
```ini
Environment=AUTO_MAXELEM=true
```

Then reload:
```bash
systemctl daemon-reload
systemctl restart crowdsec-firewall-bouncer
```

**Priority order:**
1. `MAXELEM` environment variable (explicit override, always wins)
2. `AUTO_MAXELEM=true` - calculate from available RAM
3. Conservative default (20,000)

**When to use AUTO_MAXELEM:**
- You want the bouncer to adapt to your device's current memory state
- You're running on a device with plenty of RAM (4GB+)
- You've tested and confirmed stability on your specific device

**When NOT to use AUTO_MAXELEM:**
- You need a predictable, fixed ipset size
- You're running memory-intensive UniFi apps (Protect with many cameras)
- You prefer the safer, tested-over-time conservative approach

## Memory and ipset Limits

### Conservative Defaults (UNTESTED)

| Device | Default maxelem | RAM | Status |
|--------|-----------------|-----|--------|
| UDM Pro Max | 20,000 IPs | 8GB | UNTESTED - likely can go higher |
| UDM Pro | 20,000 IPs | 4GB | UNTESTED - likely can go higher |
| UDM SE | 20,000 IPs | 4GB | UNTESTED - likely can go higher |
| UDR | 20,000 IPs | 2GB | UNTESTED |
| UDM (original) | 20,000 IPs | 2GB | UNTESTED |
| UCG Fiber | 20,000 IPs | 2GB | UNTESTED |
| UCG Ultra | 20,000 IPs | 2GB | UNTESTED |
| UniFi Express | 20,000 IPs | 1GB | UNTESTED - may need to go lower |
| Unknown device | 20,000 IPs | - | Conservative fallback |

### What happens if you exceed the limit:
- Device becomes unresponsive
- Bouncer fails to load decisions silently
- ipset operations timeout
- Potential device crash requiring reboot

### How to monitor memory:

```bash
# Check available memory (run this periodically)
cat /proc/meminfo | grep MemAvailable

# Watch memory in real-time
watch -n 5 'cat /proc/meminfo | grep MemAvailable'

# Check ipset entry count
ipset list crowdsec-blacklists | grep -c "^[0-9]"

# Check memory log from ensure-rules.sh
tail -f /data/crowdsec-bouncer/log/memory.log
```

**Target:** Keep MemAvailable above 300-500MB at all times.

### Setting the limit:

**Option 1: Manual override (explicit value):**
```bash
MAXELEM=30000 /data/crowdsec-bouncer/setup.sh
```

**Option 2: Auto-detect from RAM:**
```bash
AUTO_MAXELEM=true /data/crowdsec-bouncer/setup.sh
```

See [Auto-Detection from RAM](#auto-detection-from-ram-new) for details.

**Also set in bouncer config:**
```yaml
# /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml
ipset_size: 30000
```

Both values must match. The bouncer config `ipset_size` controls how many decisions the bouncer requests from LAPI, and `MAXELEM` controls the kernel ipset capacity.

**If you have more decisions than your limit allows:** The bouncer will load decisions up to your limit. When ipset reaches capacity, the kernel returns "set is full" errors. This repo includes a capacity monitor that detects these errors, logs them gracefully, and exposes metrics - so you know exactly when and how many decisions are being dropped. See [Capacity Monitoring](#capacity-monitoring) below.

## What's Included

| File | Purpose |
|------|---------|
| `bootstrap.sh` | One-line installer — downloads everything and runs setup |
| `install.sh` | Downloads the official bouncer binary, installs to `/data/crowdsec-bouncer/` |
| `setup.sh` | ExecStartPre script — loads ipset modules, creates ipset, adds iptables rules, re-links systemd service |
| `detect-device.sh` | Auto-detects UniFi model and sets conservative maxelem defaults |
| `ensure-rules.sh` | Cron job (every 5 min) — re-adds iptables rules if controller reprovisioning removed them |
| `ipset-capacity-monitor.sh` | Monitors for "set is full" errors, logs dropped decisions, updates metrics |
| `metrics.sh` | Prometheus metrics endpoint for monitoring |
| `crowdsec-firewall-bouncer.service` | systemd unit file for the bouncer |
| `crowdsec-unifi-metrics.service` | systemd unit file for the metrics endpoint |
| `crowdsec-firewall-bouncer.yaml.example` | Config template |

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

### Manual Install

```bash
ssh root@<UNIFI_IP>

# Create directory (persists across firmware updates)
mkdir -p /data/crowdsec-bouncer/log

# Download the official bouncer binary
# Check latest: https://github.com/crowdsecurity/cs-firewall-bouncer/releases
cd /tmp
wget https://github.com/crowdsecurity/cs-firewall-bouncer/releases/download/v0.0.34/crowdsec-firewall-bouncer-linux-amd64.tgz
tar xzf crowdsec-firewall-bouncer-linux-amd64.tgz
cp crowdsec-firewall-bouncer-*/crowdsec-firewall-bouncer /data/crowdsec-bouncer/
chmod +x /data/crowdsec-bouncer/crowdsec-firewall-bouncer
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
ipset_size: 20000                        # Start conservative, increase gradually
```

### Config Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `mode` | `ipset` | Use ipset for efficient IP matching |
| `update_frequency` | `10s` | How often to poll LAPI for new decisions |
| `ipset_size` | `20000` | Max IPs to request from LAPI — **start low!** |
| `disable_ipv6` | `true` | UniFi has issues with IPv6 firewall rules |
| `deny_action` | `DROP` | `DROP` (silent) or `REJECT` (sends reset) |
| `deny_log` | `false` | Log denied packets (can be noisy) |
| `iptables_chains` | `INPUT, FORWARD` | Block traffic to device and through device |
| `ipset_type` | `nethash` | ipset hash type |

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
ipset list crowdsec-blacklists | grep -c "^[0-9]"

# iptables rules in place?
iptables -L INPUT -n | grep crowdsec
iptables -L FORWARD -n | grep crowdsec

# Logs
tail -f /data/crowdsec-bouncer/log/crowdsec-firewall-bouncer.log

# Check from CrowdSec LAPI host
cscli bouncers list

# IMPORTANT: Monitor memory!
cat /proc/meminfo | grep MemAvailable
```

## How It Survives Firmware Updates

This is the core of what this repo provides. None of this is documented by Ubiquiti.

UniFi OS is a locked-down Debian derivative. Ubiquiti doesn't document or officially support running custom services on these devices. Through testing across firmware updates and reboots, we discovered:

- **ipset and iptables are available and functional** — UniFi OS ships with full ipset/iptables support, but Ubiquiti doesn't expose this to users. You can create custom ipsets and insert rules into INPUT/FORWARD chains alongside the controller's managed rules. This is how the bouncer blocks IPs at the firewall level — no controller API, no MongoDB
- **This is the only way to import custom blocklists** — UniFi has no built-in mechanism to add your own IP blocklists. Their Threat Management is a black box you can't feed custom data into. There's no blocklist import in the UI, no API for it, nothing. ipset is the only path to enforcing CrowdSec decisions, community threat intel, or any external blocklist on these devices
- **`/data` persists across firmware updates** — but nothing else is guaranteed
- **systemd service symlinks in `/etc/systemd/system/` get wiped** — your service vanishes after an update
- **iptables rules are reset** — the bouncer runs but silently stops blocking
- **The UniFi controller reprovisioning process can remove custom iptables rules at any time** — not just during updates, but during normal operation
- **On UDR devices, `/data` is a symlink to `/ssd1/.data`** — which isn't mounted yet at early boot, causing a race condition

Three mechanisms work together to handle all of this:

1. **`setup.sh` (ExecStartPre)** — Runs before every bouncer start. Loads ipset kernel modules, creates the ipset, adds iptables rules, and re-links the systemd service file if it was wiped. After a firmware update reboot, this single script rebuilds everything.

2. **`ensure-rules.sh` (cron, every 5 min)** — Catches the sneaky one: the UniFi controller can reprovision firewall rules during normal operation, silently removing your custom iptables rules while the bouncer is still running. This cron job detects and re-adds them.

3. **Everything in `/data/crowdsec-bouncer/`** — Binary, config, scripts, service file, logs. One persistent directory that survives whatever UniFi OS throws at it.

## Resource Usage

Bouncer process on UDM SE / UDR:

| Metric | Value |
|--------|-------|
| Process RAM | 15-22 MB |
| CPU | <1% average |
| Disk | ~15 MB (binary + logs) |

**Note:** ipset entries consume kernel memory separate from the bouncer process. Monitor with `cat /proc/meminfo | grep MemAvailable`.

## Memory Safety

`ensure-rules.sh` monitors your device's available memory every 5 minutes. If `MemAvailable` drops below a threshold (default 200MB), it stops the bouncer to prevent a crash. The ipset entries stay in place — your firewall keeps blocking the IPs already loaded. Nothing is lost.

Every run logs the current ipset count and available memory to `/data/crowdsec-bouncer/log/memory.log`:

```
2026-02-04 05:00 entries=12000 mem_avail=1200000kB bouncer=active
2026-02-04 05:05 entries=24000 mem_avail=900000kB bouncer=active
2026-02-04 05:10 entries=38000 mem_avail=600000kB bouncer=active
2026-02-04 05:15 GUARDRAIL: stopped bouncer at 52000 entries, mem_avail=190000kB
```

This tells you exactly how many entries your device can handle under its actual workload — which varies depending on what UniFi apps you run (Protect, Talk, Access all consume different amounts of RAM).

**Tuning the threshold:**

```bash
# Lower threshold for devices with less headroom
MEM_THRESHOLD=150000 /data/crowdsec-bouncer/ensure-rules.sh

# Or edit the default in the script
```

**After the guardrail triggers:** The bouncer is stopped but protection continues (ipset entries remain). Check the memory log to understand your device's capacity, then adjust `maxelem` in `setup.sh` to stay within safe range and restart the bouncer.

**CrowdSec Console warning:** If your CrowdSec instance is enrolled in the [CrowdSec Console](https://app.crowdsec.net) with `console_management` enabled, the console can push large numbers of blocklist decisions via CAPI. These bypass any local controls and are loaded by the bouncer like any other decision. Check with `cscli console status` and disable with `cscli console disable console_management` if needed.

## Capacity Monitoring

When ipset reaches its maxelem limit, the kernel returns "set is full" errors and new IPs cannot be added. Instead of crashing or failing silently, the `ipset-capacity-monitor.sh` script:

1. **Detects capacity errors** by monitoring the bouncer log for "set is full" messages
2. **Logs warnings** to `/data/crowdsec-bouncer/log/capacity.log` with details
3. **Tracks metrics** for dropped decisions (exposed via Prometheus)
4. **Continues operating** - existing blocked IPs remain in place

### Enable Capacity Monitoring

Add to cron (alongside ensure-rules.sh):

```bash
# Check capacity every 5 minutes
(crontab -l 2>/dev/null; echo "*/5 * * * * /data/crowdsec-bouncer/ipset-capacity-monitor.sh --check") | crontab -
```

Or run continuously via systemd (optional):

```bash
# Create a simple service file
cat > /data/crowdsec-bouncer/crowdsec-capacity-monitor.service << 'EOF'
[Unit]
Description=CrowdSec ipset Capacity Monitor
After=crowdsec-firewall-bouncer.service

[Service]
Type=simple
ExecStart=/data/crowdsec-bouncer/ipset-capacity-monitor.sh --watch
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

ln -sf /data/crowdsec-bouncer/crowdsec-capacity-monitor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now crowdsec-capacity-monitor
```

### Check Capacity Status

```bash
# Show current status and dropped decision count
/data/crowdsec-bouncer/ipset-capacity-monitor.sh --status

# Example output:
# === ipset Capacity Status ===
#
# Current Usage:
#   Entries:     18500 / 20000
#   Fill Ratio:  92.50%
#
# Dropped Decisions (cumulative):
#   Total dropped:    127
#   Capacity events:  3
#   Last event:       2026-02-17 10:30:45
#
# Status: WARNING - Approaching capacity limit
# Action: Monitor closely, consider reducing blocklist size
```

### Capacity Log

Events are logged to `/data/crowdsec-bouncer/log/capacity.log`:

```
2026-02-17 10:30:45 CAPACITY_ERROR: 5 decision(s) dropped - ipset full
  Current: 20000/20000 entries (100.00% full)
  Sample dropped IPs: 192.0.2.1 198.51.100.5 203.0.113.10
2026-02-17 10:35:00 WARNING: ipset CRITICAL - 100.00% full (20000/20000)
```

### What to Do When Capacity Is Reached

1. **Reduce blocklist size** - Disable some blocklists in CrowdSec Console or LAPI
2. **Increase maxelem** - Edit `MAXELEM` in setup.sh and `ipset_size` in bouncer config (if device has headroom)
3. **Use a dedicated LAPI** - Configure a separate LAPI instance with filtered/prioritized decisions
4. **Accept partial coverage** - The most important IPs (most recent decisions) are typically loaded first

## Prometheus Metrics

A lightweight Prometheus metrics endpoint exposes UniFi-specific operational metrics. This complements the official bouncer's built-in Prometheus support (which tracks decision-related metrics) with metrics about the persistence layer.

### Enable Metrics

```bash
# Link and start the metrics service
ln -sf /data/crowdsec-bouncer/crowdsec-unifi-metrics.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now crowdsec-unifi-metrics

# Verify
curl http://localhost:9101/metrics
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `crowdsec_unifi_bouncer_up` | Gauge | Whether bouncer service is running (1=up) |
| `crowdsec_unifi_bouncer_blocked_ips_total` | Gauge | Current IPs in ipset |
| `crowdsec_unifi_bouncer_ipset_size` | Gauge | Configured maxelem capacity |
| `crowdsec_unifi_bouncer_ipset_fill_ratio` | Gauge | Current/max capacity (0.0-1.0) |
| `crowdsec_unifi_bouncer_memory_available_kb` | Gauge | Available system memory |
| `crowdsec_unifi_bouncer_memory_total_kb` | Gauge | Total system memory |
| `crowdsec_unifi_bouncer_last_sync_timestamp` | Gauge | Last ensure-rules.sh run (Unix timestamp) |
| `crowdsec_unifi_bouncer_input_rule_present` | Gauge | INPUT DROP rule exists (1=yes) |
| `crowdsec_unifi_bouncer_forward_rule_present` | Gauge | FORWARD DROP rule exists (1=yes) |
| `crowdsec_unifi_bouncer_errors_total` | Counter | Total errors encountered |
| `crowdsec_unifi_bouncer_guardrail_triggered_total` | Counter | Memory guardrail activations |
| `crowdsec_unifi_bouncer_rules_restored_total` | Counter | Times iptables rules were re-added |
| `crowdsec_unifi_bouncer_decisions_dropped_total` | Counter | Decisions dropped due to ipset capacity |
| `crowdsec_unifi_bouncer_capacity_events_total` | Counter | Number of "set is full" events |
| `crowdsec_unifi_bouncer_last_capacity_event_timestamp` | Gauge | Unix timestamp of last capacity error |
| `crowdsec_unifi_bouncer_capacity_percent` | Gauge | Current ipset usage percentage (0-100) |
| `crowdsec_unifi_bouncer_degraded` | Gauge | Bouncer at capacity, dropping decisions (1=yes) |

### Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'crowdsec-unifi-bouncer'
    static_configs:
      - targets: ['192.168.1.1:9101']  # Your UniFi device IP
    scrape_interval: 60s
```

### Grafana Dashboard

A ready-to-import Grafana dashboard is included at `grafana/crowdsec-unifi-bouncer-dashboard.json`. Import it via Grafana UI (Dashboards > Import) and select your Prometheus data source.

**Dashboard panels:**
- Bouncer status (up/down)
- Blocked IPs count
- ipset capacity gauge (with warning thresholds)
- Available memory
- iptables rules status
- Guardrail trigger count
- Dropped decisions counter
- Historical graphs for IPs, memory, and events

**Example PromQL queries** for custom dashboards:

```promql
# ipset fill percentage
crowdsec_unifi_bouncer_ipset_fill_ratio * 100

# Memory pressure (MB available)
crowdsec_unifi_bouncer_memory_available_kb / 1024

# Alert: ipset >80% full
crowdsec_unifi_bouncer_ipset_fill_ratio > 0.8

# Alert: memory <300MB
crowdsec_unifi_bouncer_memory_available_kb < 300000

# Rule restoration rate (indicates controller reprovisioning)
rate(crowdsec_unifi_bouncer_rules_restored_total[1h])

# Alert: bouncer degraded (at capacity, dropping decisions)
crowdsec_unifi_bouncer_degraded == 1

# Decisions dropped due to capacity
crowdsec_unifi_bouncer_decisions_dropped_total

# Dropped decisions rate (decisions per hour that couldn't be added)
rate(crowdsec_unifi_bouncer_decisions_dropped_total[1h]) * 3600

# Alert: decisions are being dropped
increase(crowdsec_unifi_bouncer_capacity_events_total[5m]) > 0

# Capacity percentage
crowdsec_unifi_bouncer_capacity_percent

# Time since last capacity event (0 = never happened)
time() - crowdsec_unifi_bouncer_last_capacity_event_timestamp
```

### Configuration

Environment variables (set in systemd service or shell):

| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_PORT` | `9101` | HTTP server port |
| `BOUNCER_DIR` | `/data/crowdsec-bouncer` | Installation directory |
| `IPSET_NAME` | `crowdsec-blacklists` | ipset name |

### Port Selection

Default port is 9101. Common alternatives:
- 9100 is often used by node_exporter
- 60601 is used by the official bouncer's built-in Prometheus (if enabled)

To change the port, edit `/data/crowdsec-bouncer/crowdsec-unifi-metrics.service`:

```ini
Environment=METRICS_PORT=9102
```

Then reload: `systemctl daemon-reload && systemctl restart crowdsec-unifi-metrics`

## Migration from Python Bouncer

If you were using the previous Python-based bouncer (v1.x of this repo):

1. Stop and remove the old Docker container
2. Delete old firewall groups from UniFi controller (named `crowdsec-ban-*`)
3. Delete old firewall rules (indices 20000-20013)
4. Follow the [Installation](#installation) steps above
5. Register a new bouncer in CrowdSec (`cscli bouncers add`) or reuse the existing API key

The native bouncer uses ipset/iptables directly instead of the UniFi controller API:
- **No MongoDB thrashing** — the v1.x API approach wrote every IP update to the controller's MongoDB, causing router freezes at 2000+ IPs. ipset operates via netfilter with zero database overhead
- **No UniFi credentials needed** — no controller API, no login tokens, no CSRF
- **No Docker overhead** — single Go binary, 15MB RAM vs 256MB+
- **Faster response** — 10s polling vs 60s
- **Survives controller API outages** — iptables doesn't care if the controller is down

## Uninstall

```bash
systemctl stop crowdsec-firewall-bouncer
systemctl disable crowdsec-firewall-bouncer
rm /etc/systemd/system/crowdsec-firewall-bouncer.service
systemctl daemon-reload

# Remove iptables rules and ipset
iptables -D INPUT -m set --match-set crowdsec-blacklists src -j DROP 2>/dev/null
iptables -D FORWARD -m set --match-set crowdsec-blacklists src -j DROP 2>/dev/null
ipset destroy crowdsec-blacklists 2>/dev/null

# Remove cron
crontab -l | grep -v ensure-rules.sh | crontab -

# Remove files
rm -rf /data/crowdsec-bouncer

# On CrowdSec host:
cscli bouncers delete my-unifi-bouncer
```

## Troubleshooting

**Bouncer starts but no IPs blocked:**
```bash
# Check LAPI connectivity from the device
curl -s http://YOUR_LAPI:8081/v1/decisions -H "X-Api-Key: YOUR_KEY" | head
# Check logs
tail -50 /data/crowdsec-bouncer/log/crowdsec-firewall-bouncer.log
```

**iptables rules keep disappearing:**
```bash
# Verify cron is installed
crontab -l | grep ensure-rules
# Run manually
/data/crowdsec-bouncer/ensure-rules.sh
```

**Service gone after firmware update:**
```bash
ln -sf /data/crowdsec-bouncer/crowdsec-firewall-bouncer.service /etc/systemd/system/
systemctl daemon-reload
systemctl start crowdsec-firewall-bouncer
```

**Device becomes unresponsive with large blocklist:**
1. SSH in (if possible) and run: `systemctl stop crowdsec-firewall-bouncer`
2. If SSH fails, reboot the device via UniFi app or physical power cycle
3. Before restarting bouncer, reduce `ipset_size` in config and `MAXELEM` in setup.sh
4. See [Memory and ipset Limits](#memory-and-ipset-limits)

## Complete UniFi + CrowdSec Suite

This bouncer is part of a three-project suite that gives UniFi full CrowdSec integration:

| Project | Role | What it does |
|---------|------|-------------|
| **[crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser)** | Visibility | Deploys iptables LOG rules on your UDM/UDR so CrowdSec can detect port scans, brute force, and other threats from your firewall logs |
| **[crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import)** | Intelligence | Imports IPs from public threat feeds into CrowdSec — preemptive blocking before attackers even connect |
| **This repo** | Enforcement | Pushes CrowdSec ban decisions to your UniFi firewall via ipset/iptables |

Together: the **parser** detects threats, **blocklist-import** feeds threat intel, and this **bouncer** enforces bans. A complete detect → decide → enforce feedback loop on UniFi hardware for free.

## License

MIT — see [LICENSE](LICENSE)

## Credits

- [CrowdSec](https://crowdsec.net) — the open-source security engine
- [crowdsecurity/cs-firewall-bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) — the official Go binary
- [teifun2/cs-unifi-bouncer](https://github.com/teifun2/cs-unifi-bouncer) — original Go-based UniFi bouncer (inspired this project's v1.x Python approach)
- [unifi-utilities/unifios-utilities](https://github.com/unifi-utilities/unifios-utilities) — community patterns for persisting custom services on UniFi OS
