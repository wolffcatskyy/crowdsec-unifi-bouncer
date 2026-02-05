# CrowdSec Firewall Bouncer for UniFi OS

---
**Note:** This project was developed with and is supported exclusively by AI. There is no human support — issues and PRs are triaged and responded to by AI agents. If AI-assisted software isn't for you, no hard feelings — but you might want to reconsider, since so is most of the software you already use.

---

Drop-in install of the official [CrowdSec firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) on UniFi OS devices — with persistence that survives firmware updates, reboots, and controller reprovisioning.

> **New to CrowdSec?** [CrowdSec](https://crowdsec.net) is a free, open-source security engine that detects and blocks malicious IPs. It works like fail2ban but with crowd-sourced threat intelligence and a modern bouncer ecosystem. Install it, connect bouncers to your firewalls/proxies, and threats get blocked network-wide. Get started with the [official install guide](https://docs.crowdsec.net/docs/getting_started/install_crowdsec/).

**The problem:** The official bouncer binary works perfectly on UniFi devices, but UniFi OS doesn't make it easy to keep it running. Firmware updates wipe your iptables rules. Controller reprovisioning silently removes custom firewall rules. There's no package manager. Systemd service links disappear. You install it, it works, then one day it's quietly stopped blocking anything.

**The solution:** An installer and three small scripts that handle all of this automatically. Install once, forget about it.

> **v2.0**: Replaced the old Python/Docker bouncer that used the UniFi controller API. That approach hit MongoDB write storms that froze routers at 2000+ IPs. The native bouncer uses ipset and iptables directly — no controller API, no credentials, 15MB process RAM. See [Migration from Python Bouncer](#migration-from-python-bouncer) if upgrading from v1.x.
>
> **⚠️ ipset Size Limits:** UniFi devices have strict limits on ipset capacity. Large decision counts will crash the device or fail to load. See [Memory and ipset Limits](#memory-and-ipset-limits) before importing large blocklists.

## Memory and ipset Limits

**This is critical.** UniFi devices cannot handle large ipsets. Testing has established these limits:

| Device | Max Safe ipset Size | Notes |
|--------|---------------------|-------|
| UDM SE | ~50,000 IPs | Ubiquiti documents 55K max for firewall groups |
| UDR | ~40,000 IPs | Less RAM than UDM SE |
| UDM | ~40,000 IPs | Testing needed — start conservative |
| UDM Pro | ~50,000 IPs | Testing needed — start conservative |

**What happens if you exceed the limit:**
- Device becomes unresponsive
- Bouncer fails to load decisions silently
- ipset operations timeout
- Potential device crash requiring reboot

**Ubiquiti's official guidance** (from their forums): UniFi firewall groups support "up to 55,000 IPs" but real-world stability varies by device model and workload.

**Recommendations:**
1. Start with `maxelem` set to **40,000** in `setup.sh`
2. Monitor device stability for 24-48 hours
3. Increase gradually if stable (5K increments)
4. If using [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import), filter your lists to stay under limits

**Setting the limit in setup.sh:**
```bash
# Edit /data/crowdsec-bouncer/setup.sh
DESIRED_MAXELEM=40000  # Conservative default
```

**Also set in bouncer config:**
```yaml
# /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml
ipset_size: 40000
```

Both values must match. The bouncer config `ipset_size` controls how many decisions the bouncer requests from LAPI, and `DESIRED_MAXELEM` controls the kernel ipset capacity.

**If you have more decisions than your limit allows:** The bouncer will load decisions up to your limit. Excess decisions are silently dropped. Use CrowdSec Console to manage which blocklists are pushed to your LAPI, or configure the bouncer to use a dedicated LAPI with filtered decisions.

## What's Included

| File | Purpose |
|------|---------|
| `install.sh` | Downloads the official bouncer binary, installs to `/data/crowdsec-bouncer/` |
| `setup.sh` | ExecStartPre script — loads ipset modules, creates ipset, adds iptables rules, re-links systemd service |
| `ensure-rules.sh` | Cron job (every 5 min) — re-adds iptables rules if controller reprovisioning removed them |
| `crowdsec-firewall-bouncer.service` | systemd unit file |
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

### Quick Install

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
ipset_size: 40000                        # MUST match DESIRED_MAXELEM in setup.sh
```

### Config Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `mode` | `ipset` | Use ipset for efficient IP matching |
| `update_frequency` | `10s` | How often to poll LAPI for new decisions |
| `ipset_size` | `40000` | Max IPs to request from LAPI — **set this!** |
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
3. Before restarting bouncer, reduce `ipset_size` in config and `DESIRED_MAXELEM` in setup.sh
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
