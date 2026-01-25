# CrowdSec UniFi Bouncer

Sync CrowdSec ban decisions to UniFi firewall groups. Block malicious IPs at your router - the first line of defense.

## Why Use This?

CrowdSec detects threats. This bouncer **enforces** them at your UniFi router, blocking bad actors before they even reach your services.

| Protection Layer | What it Does |
|-----------------|--------------|
| **CrowdSec** | Detects attacks, maintains threat database |
| **This Bouncer** | Syncs bans to UniFi firewall groups |
| **Your Router** | Drops packets from banned IPs |

**Result:** Malicious traffic is blocked at the network edge, not at your applications.

> **Want more IPs blocked?** CrowdSec's free tier includes ~22k community IPs. Use our companion tool **[crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import)** to add 60k+ IPs from 28 free threat feeds - premium protection without the subscription!

## Features

- **Simple**: ~300 lines of Python, no complex dependencies
- **Docker Ready**: Pre-built multi-arch images (amd64/arm64)
- **Auto-Scaling**: Splits large IP lists across multiple firewall groups
- **Resilient**: Auto-reconnects on session expiry
- **Lightweight**: Polls CrowdSec stream API, minimal resource usage

## Quick Start

### Docker Compose (Recommended)

```yaml
version: "3.8"

services:
  crowdsec-unifi-bouncer:
    image: ghcr.io/wolffcatskyy/crowdsec-unifi-bouncer:latest
    container_name: crowdsec-unifi-bouncer
    restart: unless-stopped
    environment:
      - CROWDSEC_URL=http://crowdsec:8080
      - CROWDSEC_BOUNCER_API_KEY=your-api-key-here
      - UNIFI_HOST=https://192.168.1.1
      - UNIFI_USER=admin
      - UNIFI_PASS=your-password
      - UNIFI_SITE=default
      - UNIFI_SKIP_TLS_VERIFY=true
      - UPDATE_INTERVAL=60
      - LOG_LEVEL=INFO
```

### Get Your CrowdSec API Key

```bash
# On your CrowdSec host
docker exec crowdsec cscli bouncers add unifi-bouncer
```

### UniFi Setup

1. Create a **local admin user** in UniFi (not SSO/Ubiquiti account)
2. Use those credentials in `UNIFI_USER` and `UNIFI_PASS`
3. Create a firewall rule to DROP traffic from the `crowdsec-ban-*` groups

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CROWDSEC_URL` | `http://localhost:8080` | CrowdSec LAPI URL |
| `CROWDSEC_BOUNCER_API_KEY` | (required) | Bouncer API key from cscli |
| `CROWDSEC_ORIGINS` | (all) | Filter by origin (space-separated) |
| `UNIFI_HOST` | `https://192.168.1.1` | UniFi controller URL |
| `UNIFI_USER` | (required) | UniFi admin username |
| `UNIFI_PASS` | (required) | UniFi admin password |
| `UNIFI_SITE` | `default` | UniFi site name |
| `UNIFI_SKIP_TLS_VERIFY` | `false` | Skip SSL verification |
| `UNIFI_MAX_GROUP_SIZE` | `10000` | Max IPs per firewall group |
| `UPDATE_INTERVAL` | `60` | Seconds between syncs |
| `GROUP_PREFIX` | `crowdsec-ban` | Firewall group name prefix |
| `ENABLE_IPV6` | `false` | Include IPv6 addresses |
| `LOG_LEVEL` | `INFO` | DEBUG, INFO, WARNING, ERROR |

## How It Works

```
CrowdSec LAPI ──► Stream API ──► UniFi Bouncer ──► UniFi Controller
                                      │
                                      ▼
                              Firewall Groups:
                              - crowdsec-ban-0
                              - crowdsec-ban-1
                              - crowdsec-ban-2
                                      │
                                      ▼
                              Firewall Rules:
                              DROP from crowdsec-ban-*
```

1. Bouncer polls CrowdSec's stream API for new/deleted decisions
2. Creates/updates UniFi firewall address groups with banned IPs
3. Your firewall rules block traffic from those groups
4. When bans expire, IPs are automatically removed

## UniFi Firewall Rule Setup

After the bouncer creates the groups, add a firewall rule:

1. **Settings** → **Firewall & Security** → **Firewall Rules**
2. Create new rule:
   - **Type**: Internet In (or LAN In)
   - **Action**: Drop
   - **Source**: Address Group → `crowdsec-ban-0` (repeat for each group)
   - **Destination**: Any

## Related Projects

| Project | Description |
|---------|-------------|
| **[crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import)** | Import 60k+ IPs from 28 free threat feeds into CrowdSec |

## Troubleshooting

**"Invalid username or password"**
- Use a LOCAL UniFi admin, not Ubiquiti SSO account
- Check credentials are correct

**"No decisions found"**
- Verify CrowdSec has decisions: `docker exec crowdsec cscli decisions list`
- Check `CROWDSEC_ORIGINS` filter isn't excluding everything

**Groups not appearing in UniFi**
- Check bouncer logs for API errors
- Verify UniFi user has admin permissions

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
