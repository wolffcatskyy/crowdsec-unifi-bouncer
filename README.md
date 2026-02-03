# CrowdSec Firewall Bouncer for UniFi OS

Drop-in install of the official [CrowdSec firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) on UniFi OS devices — with persistence that survives firmware updates, reboots, and controller reprovisioning.

**The problem:** The official bouncer binary works perfectly on UniFi devices, but UniFi OS doesn't make it easy to keep it running. Firmware updates wipe your iptables rules. Controller reprovisioning silently removes custom firewall rules. There's no package manager. Systemd service links disappear. You install it, it works, then one day it's quietly stopped blocking anything.

**The solution:** An installer and three small scripts that handle all of this automatically. Install once, forget about it.

> **v2.0**: Replaced the old Python/Docker bouncer that used the UniFi controller API. That approach hit MongoDB write storms that froze routers at 2000+ IPs. The native bouncer uses kernel-level ipset — handles 100k+ IPs, 15MB RAM, no controller API, no credentials. See [Migration from Python Bouncer](#migration-from-python-bouncer) if upgrading from v1.x.

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

Set these two values:

```yaml
api_url: http://192.168.1.100:8081/    # Your CrowdSec LAPI address
api_key: YOUR_BOUNCER_API_KEY           # From 'cscli bouncers add'
```

### Config Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `mode` | `ipset` | Use ipset for efficient IP matching |
| `update_frequency` | `10s` | How often to poll LAPI for new decisions |
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

UniFi OS is a locked-down Debian derivative. Through testing across firmware updates and reboots, we discovered:

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

Typical on UDM SE / UDR:

| Metric | Value |
|--------|-------|
| Memory | 15-22 MB |
| CPU | <1% average |
| Disk | ~15 MB (binary + logs) |

## Migration from Python Bouncer

If you were using the previous Python-based bouncer (v1.x of this repo):

1. Stop and remove the old Docker container
2. Delete old firewall groups from UniFi controller (named `crowdsec-ban-*`)
3. Delete old firewall rules (indices 20000-20013)
4. Follow the [Installation](#installation) steps above
5. Register a new bouncer in CrowdSec (`cscli bouncers add`) or reuse the existing API key

The native bouncer uses ipset/iptables directly instead of the UniFi controller API:
- **No MongoDB thrashing** — the v1.x API approach wrote every IP update to the controller's MongoDB, causing router freezes at 2000+ IPs. ipset is a kernel-level operation with zero database overhead
- **No IP cap** — handle 100k+ IPs without stability concerns (v1.x had to cap at 2000)
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

## License

MIT — see [LICENSE](LICENSE)

## Credits

- [CrowdSec](https://crowdsec.net) — the open-source security engine
- [crowdsecurity/cs-firewall-bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer) — the official Go binary
- [teifun2/cs-unifi-bouncer](https://github.com/teifun2/cs-unifi-bouncer) — original Go-based UniFi bouncer (inspired this project's v1.x Python approach)
- [unifi-utilities/unifios-utilities](https://github.com/unifi-utilities/unifios-utilities) — community patterns for persisting custom services on UniFi OS
