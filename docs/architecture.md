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
│  │  ipset + iptables   │  │  /data/       → survives FW  │  │
│  └─────────────────────┘  └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Persistence Mechanisms

Three persistence mechanisms keep the bouncer running through anything UniFi OS throws at it:

1. **`setup.sh` (ExecStartPre)** — runs before every bouncer start; loads ipset modules, creates ipset, adds iptables rules, re-links systemd service
2. **`ensure-rules.sh` (cron, every 5 min)** — catches controller reprovisioning that silently removes iptables rules while the bouncer is running
3. **Everything in `/data/crowdsec-bouncer/`** — the one persistent directory that survives firmware updates

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
