# Architecture

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                     CrowdSec LAPI                           │
│              (local detections + CAPI feed)                  │
└──────────────┬──────────────────────┬───────────────────────┘
               │                      │
       Direct connection        With sidecar proxy
               │                      │
               ▼                      ▼
                               ┌──────────────────┐
                               │  Sidecar Proxy    │
                               │  Score & rank     │
                               │  120K → top 18K   │
                               │  Port 8084        │
                               └────────┬─────────┘
               │                        │
               ▼                        ▼
┌─────────────────────────────────────────────────────────────┐
│                   UniFi Device                              │
│  ┌─────────────────────┐  ┌──────────────────────────────┐  │
│  │  Firewall Bouncer   │  │  Persistence Layer           │  │
│  │  (official Go bin)  │  │  setup.sh     → ExecStartPre │  │
│  │  15 MB RAM          │  │  ensure-rules → cron (5 min) │  │
│  │  ipset + iptables   │  │  boot-restore → on_boot.d    │  │
│  │                     │  │  /data/       → survives FW  │  │
│  └─────────────────────┘  └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Persistence Mechanisms

1. **`setup.sh` (ExecStartPre)** — runs before every bouncer start; loads ipset modules, creates ipset, adds iptables rules, re-links systemd service
2. **`ensure-rules.sh` (cron, every 5 min)** — catches controller reprovisioning that silently removes iptables rules while the bouncer is running
3. **Everything in `/data/crowdsec-bouncer/`** — the one persistent directory that survives firmware updates
4. **`boot-restore.sh` (on_boot.d hook)** — firmware updates reset `/etc` and root's crontab, which removes the service link, the enable link, and the cron jobs. Mechanisms 1 and 2 can't recover from that on their own: `setup.sh` only runs when something starts the service, and `ensure-rules.sh` only acts while the bouncer is running. `boot-restore.sh` re-links and enables the service, restores the cron jobs, and starts the bouncer. It runs on every boot when [on-boot-script-2.x](https://github.com/unifi-utilities/unifios-utilities/tree/main/on-boot-script-2.x) is installed (`/data/on_boot.d/99-crowdsec-bouncer.sh`, added by `install.sh`); without it, run `boot-restore.sh --boot` by hand after an update.

## Resource Usage

| Component | RAM | CPU | Disk |
|-----------|-----|-----|------|
| Firewall bouncer | 15-22 MB | <1% avg | ~15 MB |
| Sidecar proxy | ~8 MB | <1% avg | ~10 MB (Docker image) |

## What's Included

| File | Purpose |
|------|---------|
| `bootstrap.sh` | One-line installer -- downloads everything and runs setup |
| `install.sh` | Downloads the official bouncer binary, installs to `/data/crowdsec-bouncer/` |
| `setup.sh` | ExecStartPre script -- loads ipset modules, creates ipset, adds iptables rules, re-links systemd service |
| `detect-device.sh` | Auto-detects UniFi model and sets safe maxelem defaults |
| `detect-sidecar.sh` | Detects whether bouncer uses sidecar proxy or direct LAPI |
| `ensure-rules.sh` | Cron job (every 5 min) -- re-adds iptables rules if controller reprovisioning removed them |
| `ipset-capacity-monitor.sh` | Monitors for "set is full" errors, logs dropped decisions, updates metrics |
| `metrics.sh` | Prometheus metrics endpoint for monitoring |
| `sidecar/` | Intelligent decision-filtering proxy (Go) -- see [Sidecar Proxy](sidecar.md) |

## Tested On

- UniFi Dream Machine SE (UDM SE) -- UniFi OS 4.x
- UniFi Dream Router (UDR) -- UniFi OS 4.x

Should work on any UniFi OS device with SSH access and iptables/ipset support.
