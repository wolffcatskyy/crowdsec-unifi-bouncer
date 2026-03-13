# AbuseIPDB Reporting

The sidecar proxy can automatically report locally-banned IPs to [AbuseIPDB](https://www.abuseipdb.com), contributing your CrowdSec detections to community threat intelligence.

**New to AbuseIPDB?** AbuseIPDB is a free, community-driven database of malicious IPs where users report attacks and check IP reputations. Get started at [abuseipdb.com](https://www.abuseipdb.com).

## How It Works

When the sidecar processes new ban decisions from your local CrowdSec instance, it asynchronously reports each banned IP to AbuseIPDB with the appropriate abuse category and a comment describing the CrowdSec scenario that triggered the ban. Reporting is fire-and-forget -- it never blocks or affects decision processing.

**Smart filtering prevents circular reporting:**
- Only local CrowdSec detections and manual `cscli` bans are reported
- CAPI (community blocklist) decisions are skipped -- they already exist in threat intel
- Blocklist-import decisions are skipped -- avoids re-reporting IPs from other feeds
- Only individual IP bans are reported (not CIDR ranges or captcha decisions)

## Configuration

Enable via environment variables in your sidecar deployment:

```yaml
# docker-compose.yaml
environment:
  - ABUSEIPDB_API_KEY=your_api_key_here
  - ABUSEIPDB_REPORT_ENABLED=true
```

Or in the sidecar `config.yaml`:

```yaml
abuseipdb:
  enabled: true
  api_key: "your_api_key_here"
  daily_limit: 100  # Free tier: 100/day, Premium: 3000/day
```

| Setting | Env Var | Default | Description |
|---------|---------|---------|-------------|
| `abuseipdb.enabled` | `ABUSEIPDB_REPORT_ENABLED` | `false` | Enable reporting |
| `abuseipdb.api_key` | `ABUSEIPDB_API_KEY` | -- | API key from [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |
| `abuseipdb.daily_limit` | -- | `100` | Max reports per 24h window |

## Scenario Category Mapping

CrowdSec scenarios are automatically mapped to AbuseIPDB abuse categories:

| CrowdSec Scenario | AbuseIPDB Categories |
|--------------------|----------------------|
| SSH attacks (`ssh-bf`, `ssh-slow-bf`, etc.) | 22 (SSH), 18 (Brute-Force) |
| Telnet attacks | 23 (Telnet), 18 (Brute-Force) |
| HTTP attacks (`http-*`) | 21 (Web App Attack) |
| SMB/FTP brute force | 18 (Brute-Force) |
| Other scenarios | 14 (Port Scan) |

## Rate Limits

The reporter enforces a daily limit (default: 100) that resets every 24 hours. When the limit is reached, additional reports are silently skipped until the window resets. AbuseIPDB API 429 responses are also handled gracefully.

## Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `abuseipdb_reports_total` | Counter | Total reports by status (`success`, `failed`, `skipped`) |
| `abuseipdb_reports_queued` | Counter | Reports queued for async sending |
