# Sidecar Proxy

The sidecar is an optional but recommended component that sits between the bouncer and CrowdSec LAPI. It scores all decisions across 7 factors and returns only the highest-priority threats that fit your device's ipset capacity.

## The Problem Without a Sidecar

When CrowdSec's LAPI has more decisions than your device can hold, the bouncer fills the ipset and silently drops everything else. There's no prioritization -- a stale probing ban from three weeks ago takes a slot that could go to an active SSH brute-force attack detected today.

```
CrowdSec LAPI: 120,000 decisions
        |
        v
Firewall Bouncer: loads first 20,000
        |
        v
ipset: FULL (remaining 100,000 silently dropped)
        |
        +-- No scoring, no prioritization
            New SSH attack? Too bad, set is full.
```

## How the Sidecar Fixes This

The sidecar proxy sits between the bouncer and LAPI. It fetches all decisions, scores each one across 7 factors, sorts by score, and returns only the top N that fit your device.

```
CrowdSec LAPI (120,000 decisions)
        |
        v
+---------------------------+
|   Sidecar Proxy           |
|                           |
|   Score all 120,000       |
|   Sort by priority        |
|   Return top 18,000       |
|                           |
|   Port 8084               |
+---------------------------+
        |
        v
Firewall Bouncer -> ipset (18,000 highest-priority threats)
```

## Scoring Factors

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

## What Survives Truncation

The scoring system ensures your highest-value detections are never dropped. In production with 125K LAPI decisions filtered to 38K:

| Source | Kept | Why |
|--------|------|-----|
| Your local CrowdSec detections | **100%** | Origin score 25 + freshness bonus = always survives |
| Manual bans (`cscli`) | **100%** | Origin score 20 = always survives |
| Community curated lists | **100%** | Higher signal than bulk imports |
| Community blocklist (CAPI) | **100%** | Scored above bulk feeds |
| Bulk blocklist-import feeds | **13%** | Absorbs all drops -- stale single-source IPs shed first |

Only low-signal bulk imports are dropped -- and even within those, IPs that appear in multiple sources get a recidivism bonus and survive.

## Do I Need the Sidecar?

| Situation | Sidecar? | Why |
|-----------|----------|-----|
| LAPI has <15K decisions | No | Everything fits in ipset |
| LAPI has 15K-30K decisions | Maybe | Depends on your device's maxelem |
| LAPI has >30K decisions | **Yes** | Overflow is guaranteed on all devices |
| You subscribe to community blocklists | **Yes** | Blocklists push decision counts way up |
| Multiple bouncers on different devices | **Yes** | Each device gets decisions sized for its capacity |
| You want to prioritize local detections | **Yes** | Scoring ensures your network's detections beat stale CAPI entries |

## Quick Setup

The sidecar image is published to **GHCR** (`ghcr.io/wolffcatskyy/crowdsec-sidecar`). Multi-arch (amd64/arm64).

**1. Deploy the sidecar on your CrowdSec host** (or any machine that can reach LAPI):

```bash
# Download example config
mkdir -p crowdsec-sidecar && cd crowdsec-sidecar
curl -sSLO https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-bouncer/main/sidecar/config.yaml.example
cp config.yaml.example config.yaml
# Edit config.yaml: set upstream_lapi_url, upstream_lapi_key, max_decisions

# Run with Docker
docker run -d --name crowdsec-sidecar \
  -p 8084:8084 \
  -v $(pwd)/config.yaml:/etc/crowdsec-sidecar/config.yaml:ro \
  --restart unless-stopped \
  ghcr.io/wolffcatskyy/crowdsec-sidecar:latest
```

Or use docker compose -- see [sidecar/README.md](../sidecar/README.md#docker-deployment-recommended) for the full compose file.

**2. Update your bouncer config** on the UniFi device:

```yaml
# Change api_url from LAPI to sidecar
api_url: http://YOUR_SIDECAR_HOST:8084/
```

**3. Restart the bouncer:**

```bash
systemctl restart crowdsec-firewall-bouncer
```

**4. Verify the sidecar is working:**

```bash
curl http://YOUR_SIDECAR_HOST:8084/health
curl http://YOUR_SIDECAR_HOST:8084/metrics
```

## Full Sidecar Documentation

For Docker Compose examples, all config options, and Prometheus metrics reference, see [sidecar/README.md](../sidecar/README.md).
