# CrowdSec UniFi Bouncer

A simple, reliable Python bouncer that syncs [CrowdSec](https://crowdsec.net) ban decisions to UniFi firewall groups.

## Features

- **Simple**: ~600 lines of Python, no complex dependencies
- **Reliable**: Cookie-based auth that actually works with UniFi OS
- **Efficient**: Uses CrowdSec streaming API for real-time updates
- **Scalable**: Automatically splits large IP lists into multiple groups (UniFi has 10k limit per group)
- **Resilient**: Exponential backoff for UniFi API errors (502/503/504/429)
- **Observable**: Health check endpoint for Docker health checks and monitoring
- **Memory-conscious**: Garbage collection and memory logging for large IP sets

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

### Core Settings

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

### Health Check Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `HEALTH_ENABLED` | `true` | Enable health check HTTP endpoint |
| `HEALTH_PORT` | `8080` | Port for health check endpoint |

### Retry/Backoff Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `UNIFI_MAX_RETRIES` | `5` | Max retry attempts for UniFi API errors |
| `UNIFI_INITIAL_BACKOFF` | `1.0` | Initial backoff delay in seconds |
| `UNIFI_MAX_BACKOFF` | `60.0` | Maximum backoff delay in seconds |

### Memory Management

| Variable | Default | Description |
|----------|---------|-------------|
| `SYNC_BATCH_SIZE` | `1000` | IPs processed per batch during sync |

## Health Check Endpoint

The bouncer exposes an HTTP health check endpoint on port 8080 (configurable via `HEALTH_PORT`).

### Endpoints

| Endpoint | Description | Response |
|----------|-------------|----------|
| `GET /health` | Full status JSON | 200 OK (healthy) or 503 (unhealthy) |
| `GET /ready` | Readiness probe | 200 "ready" or 503 "not ready" |
| `GET /live` | Liveness probe | 200 "alive" (always) |

### Health Response Example

```json
{
  "status": "healthy",
  "version": "1.3.0",
  "uptime_seconds": 3600,
  "crowdsec_connected": true,
  "unifi_connected": true,
  "last_sync_time": 1706500000.123,
  "last_sync_ips": 4521,
  "last_error": null,
  "memory_mb": 45.2
}
```

### Docker Compose Health Check

```yaml
services:
  crowdsec-unifi-bouncer:
    # ... other config ...
    ports:
      - "8080:8080"  # Optional: expose for external monitoring
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
```

## How It Works

1. **Connects to CrowdSec LAPI** using the bouncer API key
2. **Logs into UniFi** using username/password (cookie auth)
3. **Fetches ban decisions** from CrowdSec
4. **Creates firewall groups** named `crowdsec-ban-0`, `crowdsec-ban-1`, etc.
5. **Polls for updates** every `UPDATE_INTERVAL` seconds
6. **Retries with backoff** on UniFi 502/503/504/429 errors

### Firewall Rules

After the bouncer creates the groups, you need to create firewall rules in UniFi to block traffic from these groups:

1. Go to **Settings -> Firewall & Security -> Firewall Rules**
2. Create a new rule:
   - **Type**: Internet In
   - **Action**: Drop
   - **Source**: IP Group -> `crowdsec-ban-0` (and any other bouncer groups)
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

## Troubleshooting

### OOM Killed (Exit 137)

If the container is being OOM killed when syncing large IP sets:

1. Increase container memory limit (recommend 512MB for 100k+ IPs)
2. Reduce `UNIFI_MAX_GROUP_SIZE` to process smaller chunks
3. Enable `LOG_LEVEL=DEBUG` to see memory usage logs

### UniFi 502/503 Errors

The bouncer automatically retries with exponential backoff. If errors persist:

1. Check UniFi controller health
2. Increase `UNIFI_MAX_RETRIES` for more attempts
3. Increase `UNIFI_INITIAL_BACKOFF` to reduce API pressure

### Health Check Shows Unhealthy

Check `/health` endpoint for details:
- `crowdsec_connected: false` - Check CrowdSec LAPI connectivity
- `unifi_connected: false` - Check UniFi credentials and connectivity
- `last_error` field shows the most recent error

## Development

Run locally without Docker:

```bash
pip install -r requirements.txt
export CROWDSEC_BOUNCER_API_KEY=xxx
export UNIFI_USER=admin
export UNIFI_PASS=xxx
python bouncer.py
```

## Changelog

### v1.3.0
- Added health check HTTP endpoint (/health, /ready, /live)
- Added exponential backoff for UniFi API errors (502/503/504/429)
- Added memory-conscious batch processing with gc.collect()
- Added memory usage logging (visible at DEBUG level)
- Improved error messages with more context
- Added configurable retry settings (UNIFI_MAX_RETRIES, UNIFI_INITIAL_BACKOFF, UNIFI_MAX_BACKOFF)

### v1.2.2
- Added telemetry support

### v1.2.1
- Initial public release

## License

MIT

## Credits

- [CrowdSec](https://crowdsec.net) - The open-source security engine
- Inspired by [teifun2/cs-unifi-bouncer](https://github.com/teifun2/cs-unifi-bouncer)
