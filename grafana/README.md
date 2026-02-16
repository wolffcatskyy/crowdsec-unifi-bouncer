# CrowdSec UniFi Bouncer - Grafana Dashboard

Pre-built Grafana dashboard for monitoring the CrowdSec Firewall Bouncer on UniFi OS devices.

## Prerequisites

1. **CrowdSec Firewall Bouncer** v0.0.30+ with Prometheus metrics enabled
2. **Prometheus** scraping the bouncer metrics endpoint
3. **Grafana** 10.0.0+ (compatible with older versions, some features may vary)

## Enable Prometheus Metrics on the Bouncer

Edit `/data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml` on your UniFi device:

```yaml
prometheus:
  enabled: true
  listen_addr: 0.0.0.0
  listen_port: 60601
```

Restart the bouncer:
```bash
systemctl restart crowdsec-firewall-bouncer
```

## Configure Prometheus Scrape

Add to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'crowdsec-firewall-bouncer'
    static_configs:
      - targets:
        - 'udm-ip:60601'    # UDM/UDM SE
        - 'udr-ip:60601'    # UDR
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
```

## Import the Dashboard

### Option 1: Import from File
1. In Grafana, go to **Dashboards** > **Import**
2. Click **Upload JSON file**
3. Select `crowdsec-unifi-bouncer-dashboard.json`
4. Select your Prometheus datasource
5. Click **Import**

### Option 2: Copy/Paste JSON
1. In Grafana, go to **Dashboards** > **Import**
2. Paste the contents of `crowdsec-unifi-bouncer-dashboard.json`
3. Select your Prometheus datasource
4. Click **Import**

## Dashboard Panels

### Status Row
| Panel | Description |
|-------|-------------|
| **Blocked IPs (Total)** | Gauge showing total blocked IPs across all origins |
| **Sync Status** | Time since last metric update (green <2m, yellow 2-5m, red >5m) |
| **Packet Drop Rate** | Percentage of packets being blocked |
| **Bouncer Status** | UP/DOWN indicator |

### Blocked IPs by Origin Row
| Panel | Description |
|-------|-------------|
| **Blocked IPs by Origin** | Breakdown by source (CAPI, local decisions, blocklists) |
| **Traffic Stats** | Current dropped packets, bytes, and total processed |

### Historical Data Row
| Panel | Description |
|-------|-------------|
| **Blocked IPs Over Time** | Time series of blocked IPs by origin (log scale) |
| **Packet Rate** | Dropped vs processed packets per second |
| **Error/Drop Rate Over Time** | Percentage of traffic being blocked |
| **Blocked Bandwidth Over Time** | Data volume blocked (bytes/sec) |

## Available Metrics

The CrowdSec Firewall Bouncer exposes these Prometheus metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `fw_bouncer_banned_ips` | Gauge | Number of banned IPs by origin |
| `fw_bouncer_dropped_packets` | Counter | Total packets dropped |
| `fw_bouncer_dropped_bytes` | Counter | Total bytes dropped |
| `fw_bouncer_processed_packets` | Counter | Total packets processed |

## Variables

The dashboard supports these template variables:

- **datasource**: Select the Prometheus datasource
- **instance**: Filter by bouncer instance (supports multi-select)

## Alerting

Recommended alerts to configure:

```yaml
# Bouncer down
- alert: CrowdSecBouncerDown
  expr: up{job="crowdsec-firewall-bouncer"} == 0
  for: 5m
  labels:
    severity: critical

# High drop rate
- alert: CrowdSecHighDropRate
  expr: (sum(rate(fw_bouncer_dropped_packets[5m])) / sum(rate(fw_bouncer_processed_packets[5m]))) > 0.3
  for: 10m
  labels:
    severity: warning

# Stale metrics
- alert: CrowdSecBouncerStale
  expr: time() - max(timestamp(fw_bouncer_banned_ips)) > 300
  for: 5m
  labels:
    severity: warning
```

## Troubleshooting

### No data showing
1. Verify metrics are enabled in bouncer config
2. Check bouncer is running: `systemctl status crowdsec-firewall-bouncer`
3. Test metrics endpoint: `curl http://localhost:60601/metrics`
4. Verify Prometheus is scraping: check Prometheus targets page

### Metrics endpoint not accessible
- Ensure `listen_addr` is set to `0.0.0.0` (not `127.0.0.1`) if accessing remotely
- Check firewall rules allow access to port 60601

## License

MIT License - see repository root for details.
