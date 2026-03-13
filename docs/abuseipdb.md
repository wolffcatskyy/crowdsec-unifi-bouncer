# AbuseIPDB Reporting

[AbuseIPDB](https://www.abuseipdb.com/) is a community-driven IP reputation database where network operators report and check malicious IP addresses. The sidecar can automatically submit your locally-detected threats to AbuseIPDB, turning your CrowdSec detections into actionable threat intelligence for the broader internet community.

> [!NOTE]
> AbuseIPDB reporting is part of the sidecar proxy (v2.4.0+). It requires the sidecar to be running — it is not available in the standalone bouncer.

---

## What is AbuseIPDB?

AbuseIPDB operates on a simple principle: the people who get attacked know the attackers. When an IP brute-forces your SSH server, that IP is probably also attacking thousands of other servers. If every victim reports the attacker, everyone benefits.

- **Free to use** — basic API access is free (100 reports/day, 1,000 checks/day)
- **Community-sourced** — reports come from real operators who observed real attacks
- **Widely integrated** — used by firewalls, mail servers, CDNs, and security tools worldwide
- **Confidence scoring** — each IP has a 0-100 confidence-of-abuse score based on report frequency and recency

When you enable reporting in the sidecar, your CrowdSec detections flow directly into this database. An SSH brute-force you stop today could prevent the same IP from reaching someone else tomorrow.

---

## How It Works With the Bouncer

The sidecar watches the stream of new ban decisions from your CrowdSec instance. When it processes a ban from a **local detection** (an attack your own CrowdSec detected), it queues a report to AbuseIPDB asynchronously.

```
Your Network
     |
     v
CrowdSec detects SSH brute force from 1.2.3.4
     |
     v
Ban decision: {ip: "1.2.3.4", origin: "crowdsec", scenario: "ssh-bf"}
     |
     v
Sidecar Proxy
  ├── Passes ban to bouncer (IP blocked on UniFi)
  └── Queues AbuseIPDB report (fire-and-forget)
         |
         v
     AbuseIPDB API
       category: 22 (SSH), 18 (Brute-Force)
       comment: "CrowdSec scenario: crowdsecurity/ssh-bf, ban duration: 4h"
```

Reporting is **fire-and-forget**: it happens asynchronously in the background and never delays or affects decision processing. If the AbuseIPDB API is unreachable, the report is skipped and the ban proceeds normally.

---

## Why Report?

**You contribute to collective defense.** AbuseIPDB aggregates reports from thousands of operators. When your detection confirms an IP that others have also seen, its confidence score rises, making it easier for other operators to justify blocking it. You benefit from their reports too — when you check an IP's history, you're seeing the aggregated experience of everyone who reported it.

**Your local detections have high value.** CrowdSec CAPI (community blocklists) already includes crowd-sourced bans from other CrowdSec users. But AbuseIPDB is independent — your reports reach a different audience. An IP that appears in both databases has stronger evidence against it.

**It costs nothing and takes no extra work.** Once enabled, reporting runs automatically. You set it up once and forget it.

**It improves your AbuseIPDB confidence score.** Regular reporters with consistent, accurate submissions build a track record that increases the weight of their reports. The more you report, the more useful your reports become.

---

## Smart Filtering: Avoiding Circular Reporting

The sidecar only reports decisions that **your network originated** — not decisions that came from external threat feeds. This prevents circular reporting loops.

| Decision Origin | Reported? | Reason |
|-----------------|-----------|--------|
| `crowdsec` — local CrowdSec detection | Yes | Your network witnessed this attack directly |
| `cscli` — manual admin ban | Yes | Explicit human judgment, high confidence |
| `CAPI` — community blocklist | No | Already in threat intel; re-reporting adds noise |
| `blocklist-import` — external feed import | No | Imported from other databases; circular if re-reported |
| CIDR ranges | No | AbuseIPDB works with individual IPs only |
| `captcha`/throttle decisions | No | Not confirmed attacks; only full bans are reported |

Only **new incremental decisions** are reported (not the full decision set on startup), so you never flood the API when the sidecar first starts.

---

## Scenario-to-Category Mapping

AbuseIPDB uses a standard set of [abuse categories](https://www.abuseipdb.com/categories). The sidecar maps CrowdSec scenario names to the most appropriate categories automatically.

| CrowdSec Scenario Pattern | AbuseIPDB Categories | Category Names |
|---------------------------|----------------------|----------------|
| `*ssh*` | 22, 18 | SSH, Brute-Force |
| `*telnet*` | 23, 18 | Telnet, Brute-Force |
| `*http*` | 21 | Web App Attack |
| `*smb*`, `*ftp*` | 18 | Brute-Force |
| Default (anything else) | 14 | Port Scan |

The comment field included with each report contains the full CrowdSec scenario name and ban duration. For example:

```
CrowdSec scenario: crowdsecurity/ssh-bf, ban duration: 4h
```

This gives AbuseIPDB reviewers and downstream users the context to understand what was observed, not just the category bucket.

---

## Getting an API Key

1. Create a free account at [abuseipdb.com](https://www.abuseipdb.com/)
2. Go to [Account > API](https://www.abuseipdb.com/account/api)
3. Generate a new API key
4. Add it to your sidecar configuration (see below)

### API Tier Limits

| Tier | Reports/Day | Checks/Day | Price |
|------|-------------|------------|-------|
| Free | 100 | 1,000 | Free |
| Basic | 500 | 10,000 | ~$20/mo |
| Premium | 3,000 | 100,000 | ~$50/mo |

For most home and small business deployments, the free tier (100 reports/day) is sufficient. CrowdSec typically detects 5-30 unique attackers per day on a residential IP, well within the free limit.

---

## Configuration

### Environment Variables (Docker)

```yaml
# docker-compose.yaml
services:
  crowdsec-sidecar:
    image: ghcr.io/wolffcatskyy/crowdsec-sidecar:latest
    environment:
      - ABUSEIPDB_API_KEY=your_api_key_here
      - ABUSEIPDB_REPORT_ENABLED=true
```

### config.yaml

```yaml
abuseipdb:
  enabled: true
  api_key: "your_api_key_here"
  daily_limit: 100  # match your API tier
```

### Settings Reference

| Setting | Env Var | Default | Description |
|---------|---------|---------|-------------|
| `abuseipdb.enabled` | `ABUSEIPDB_REPORT_ENABLED` | `false` | Enable reporting. Must be explicitly set to `true`. |
| `abuseipdb.api_key` | `ABUSEIPDB_API_KEY` | — | API key from [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api). |
| `abuseipdb.daily_limit` | — | `100` | Maximum reports in a rolling 24-hour window. Matches free tier default. Premium users should increase this. |

Environment variables take precedence over `config.yaml` values.

---

## Rate Limiting

The sidecar enforces the daily limit in a rolling 24-hour window (not a midnight reset). Once the limit is reached:

- Additional reports are **silently skipped** — the ban still takes effect on your firewall
- The count resets 24 hours after the first report in the current window
- AbuseIPDB API `429 Too Many Requests` responses are handled gracefully and do not cause errors

If you find the free tier limit is regularly being hit, consider upgrading your API tier or reducing the reporting scope (e.g., SSH-only reporting is not currently configurable but can be requested as a feature).

---

## Privacy

The sidecar reports only what is necessary:

- **IP address** — the attacking IP (required)
- **Categories** — numeric AbuseIPDB category codes derived from the CrowdSec scenario
- **Comment** — the CrowdSec scenario name and ban duration (e.g., `crowdsecurity/ssh-bf, ban duration: 4h`)

No usernames, no log lines, no request payloads, no source ports, and no information about your network topology are ever included in reports. AbuseIPDB's own privacy policy governs what they do with submitted data.

---

## Monitoring

### Prometheus Metrics

When enabled, the sidecar exposes AbuseIPDB metrics at the `/metrics` endpoint:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `abuseipdb_reports_total` | Counter | `status` | Reports by outcome: `success`, `failed`, `skipped` |
| `abuseipdb_reports_queued` | Counter | — | Reports queued for async sending |

The `skipped` label covers both rate-limited reports (daily limit reached) and filtered decisions (CAPI/blocklist-import origins).

### Grafana

If you're using the included [Grafana dashboard](../grafana/), add a panel using:

```promql
# Reports sent successfully (last 24h)
increase(abuseipdb_reports_total{status="success"}[24h])

# Reports skipped due to rate limit or filter
increase(abuseipdb_reports_total{status="skipped"}[24h])

# Failed reports (API errors)
increase(abuseipdb_reports_total{status="failed"}[24h])
```

### Verifying Reports

After enabling, you can verify reports are reaching AbuseIPDB:

1. Go to [abuseipdb.com/account](https://www.abuseipdb.com/account)
2. Navigate to **API > Report History**
3. Reports from your sidecar will appear within a few minutes of any new local detection

---

## Troubleshooting

<details>
<summary><strong>No reports appearing in AbuseIPDB account</strong></summary>

Check that the sidecar has actually received new local decisions since enabling:

```bash
# Check sidecar logs for AbuseIPDB activity
docker logs crowdsec-sidecar --tail 100 | grep -i abuseipdb

# Check metrics — success counter should be > 0 after any new local ban
curl -s http://YOUR_SIDECAR_HOST:8084/metrics | grep abuseipdb
```

If the metrics show `abuseipdb_reports_total{status="skipped"}` climbing but no `success`, check:
- API key is correct and not expired
- `daily_limit` has not been reached
- New decisions are coming in with `crowdsec` or `cscli` origin (not CAPI)

To check if CrowdSec is generating local decisions:
```bash
# On your CrowdSec host
cscli decisions list --origin crowdsec --limit 10
```

If the list is empty, your CrowdSec instance may not have any active parsers or scenarios detecting local traffic.
</details>

<details>
<summary><strong>Reports failing with API error</strong></summary>

```bash
# Check for failed reports in metrics
curl -s http://YOUR_SIDECAR_HOST:8084/metrics | grep 'abuseipdb_reports_total{status="failed"}'

# Check sidecar logs for the specific error
docker logs crowdsec-sidecar 2>&1 | grep -i "abuseipdb\|429\|401\|403"
```

Common causes:
- **401 Unauthorized** — API key is invalid or missing
- **422 Unprocessable** — IP address format issue (rare; file an issue if seen)
- **429 Too Many Requests** — daily limit exceeded on the AbuseIPDB side (independent of the sidecar's local limit)
- **Network error** — sidecar container cannot reach `api.abuseipdb.com` (check DNS and outbound firewall rules)
</details>

<details>
<summary><strong>Sidecar reporting CAPI decisions (unexpected)</strong></summary>

This should not happen — the sidecar filters by origin before reporting. If you believe CAPI decisions are being reported, check the sidecar version:

```bash
docker exec crowdsec-sidecar /app/crowdsec-sidecar -version
```

Version 2.4.0 or later includes origin filtering. Earlier builds did not have the reporting feature. If you're on a version prior to 2.4.0, update the image:

```bash
docker pull ghcr.io/wolffcatskyy/crowdsec-sidecar:latest
docker compose up -d crowdsec-sidecar
```
</details>

<details>
<summary><strong>Daily limit reached faster than expected</strong></summary>

If your network is under heavy attack, 100 reports/day can fill up in a few hours. Options:

1. **Upgrade AbuseIPDB tier** — Basic (500/day) or Premium (3,000/day) for high-volume environments
2. **Set a lower daily_limit** to pace reporting across the day (reports are queued and processed in order)
3. **Accept the tradeoff** — once the limit is reached, bans still work normally on your firewall; only the reporting to AbuseIPDB is paused

To check current usage, the `abuseipdb_reports_total{status="success"}` metric shows cumulative reports since the sidecar last started.
</details>

---

## See Also

- [Sidecar Proxy](../sidecar/README.md) — full sidecar configuration reference
- [AbuseIPDB Categories](https://www.abuseipdb.com/categories) — complete list of abuse category codes
- [AbuseIPDB API Documentation](https://docs.abuseipdb.com/) — official API reference
- [CrowdSec Hub](https://hub.crowdsec.net/browse/#collections) — available CrowdSec scenarios and collections
