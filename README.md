# CrowdSec UniFi Bouncer

A simple, reliable Python bouncer that syncs [CrowdSec](https://crowdsec.net) ban decisions to UniFi firewall groups.

## Features

- **Simple**: ~300 lines of Python, no complex dependencies
- **Reliable**: Cookie-based auth that actually works with UniFi OS
- **Efficient**: Uses CrowdSec streaming API for real-time updates
- **Scalable**: Automatically splits large IP lists into multiple groups (UniFi has 10k limit per group)

## Why Another Bouncer?

The existing Go-based bouncer ([teifun2/cs-unifi-bouncer](https://github.com/teifun2/cs-unifi-bouncer)) has issues with UniFi OS API key authentication. This Python version uses proven cookie-based authentication that works reliably.

## Quick Start

### 1. Add bouncer to CrowdSec

```bash
sudo cscli bouncers add unifi-bouncer
# Save the API key that's displayed
```

### 2. Create .env file

```bash
cp .env.example .env
# Edit .env with your credentials
```

### 3. Run with Docker Compose

```bash
docker compose up -d
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CROWDSEC_URL` | `http://localhost:8080` | CrowdSec LAPI URL |
| `CROWDSEC_BOUNCER_API_KEY` | (required) | Bouncer API key from cscli |
| `CROWDSEC_ORIGINS` | (all) | Filter by origin (space-separated: `crowdsec cscli CAPI`) |
| `UNIFI_HOST` | `https://192.168.1.1` | UniFi controller URL |
| `UNIFI_USER` | (required) | UniFi username |
| `UNIFI_PASS` | (required) | UniFi password |
| `UNIFI_SITE` | `default` | UniFi site name |
| `UNIFI_SKIP_TLS_VERIFY` | `false` | Skip TLS certificate verification |
| `UNIFI_MAX_GROUP_SIZE` | `10000` | Max IPs per firewall group |
| `ENABLE_IPV6` | `false` | Include IPv6 addresses (UniFi has issues with IPv6) |
| `UPDATE_INTERVAL` | `60` | Seconds between updates |
| `GROUP_PREFIX` | `crowdsec-ban` | Prefix for firewall group names |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

## How It Works

1. **Connects to CrowdSec LAPI** using the bouncer API key
2. **Logs into UniFi** using username/password (cookie auth)
3. **Fetches ban decisions** from CrowdSec
4. **Creates firewall groups** named `crowdsec-ban-0`, `crowdsec-ban-1`, etc.
5. **Polls for updates** every `UPDATE_INTERVAL` seconds

### Firewall Rules

After the bouncer creates the groups, you need to create firewall rules in UniFi to block traffic from these groups:

1. Go to **Settings → Firewall & Security → Firewall Rules**
2. Create a new rule:
   - **Type**: Internet In
   - **Action**: Drop
   - **Source**: IP Group → `crowdsec-ban-0` (and any other bouncer groups)
   - **Destination**: Any

## Tested On

- UniFi Dream Machine SE (UniFi OS 5.x)
- UniFi Dream Machine Pro
- Should work on any UniFi OS device

## Origin Filtering

To reduce the number of IPs (useful if you have UniFi firewall rule limits), filter by origin:

```yaml
# Only local detections and manual bans (~100 IPs)
CROWDSEC_ORIGINS=crowdsec cscli

# Add community threat intel (~22k IPs)
CROWDSEC_ORIGINS=crowdsec cscli CAPI

# All decisions (default - can be 100k+ IPs)
# CROWDSEC_ORIGINS=
```

## Development

Run locally without Docker:

```bash
pip install -r requirements.txt
export CROWDSEC_BOUNCER_API_KEY=xxx
export UNIFI_USER=admin
export UNIFI_PASS=xxx
python bouncer.py
```

## License

MIT

## Credits

- [CrowdSec](https://crowdsec.net) - The open-source security engine
- Inspired by [teifun2/cs-unifi-bouncer](https://github.com/teifun2/cs-unifi-bouncer)
