# CrowdSec UniFi Bouncer - Grafana Dashboard

Pre-built Grafana dashboard for monitoring the CrowdSec Firewall Bouncer on UniFi OS devices (UDM, UDM SE, UDR).

## Prerequisites

1. **CrowdSec Firewall Bouncer** installed on your UniFi device
2. **UniFi Metrics Service** (`crowdsec-unifi-metrics.service`) running
3. **Prometheus** scraping the metrics endpoint
4. **Grafana** 10.0.0+ (compatible with older versions)

## Enable Metrics

Install and start the metrics service on your UniFi device:

```bash
# Link and start the metrics service
ln -sf /data/crowdsec-bouncer/crowdsec-unifi-metrics.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now crowdsec-unifi-metrics

# Verify metrics are available
curl http://localhost:9101/metrics
```

## Configure Prometheus Scrape

Add to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'crowdsec-unifi-bouncer'
    static_configs:
      - targets:
        - 'udm-ip:9101'    # UDM/UDM SE
        - 'udr-ip:9101'    # UDR
    scrape_interval: 60s
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

### Status Row (Top)
| Panel | Description |
|-------|-------------|
| **Bouncer Status** | UP/DOWN indicator based on `crowdsec_unifi_bouncer_up` |
| **Blocked IPs** | Current count of IPs in ipset (stat with mini graph) |
| **ipset Capacity** | Gauge showing ipset fill ratio (green <70%, yellow 70-85%, red >85%) |
| **Available Memory** | System memory available in MB (red <300MB, yellow 300-500MB, green >500MB) |
| **iptables Rules** | OK/MISSING indicator for INPUT and FORWARD DROP rules |
| **Guardrail Triggers** | Count of memory guardrail activations |

### Time Series Row (Middle)
| Panel | Description |
|-------|-------------|
| **ipset Usage Over Time** | Blocked IPs vs max capacity with threshold lines |
| **Memory Over Time** | Available memory with threshold lines |

### Event Row (Middle-Bottom)
| Panel | Description |
|-------|-------------|
| **Event Counters** | Rules restored, guardrail triggers, and errors over time |
| **ipset Fill Ratio Over Time** | Percentage fill over time |

### Capacity Row (Bottom)
| Panel | Description |
|-------|-------------|
| **Capacity Status** | Normal/DEGRADED indicator (degraded = at capacity, dropping decisions) |
| **Decisions Dropped** | Total count of decisions that couldn't be added to ipset |
| **Capacity %** | Gauge showing current capacity usage (red >95%) |
| **Decisions Dropped Rate** | Rate of dropped decisions per minute over time |

## Available Metrics

The UniFi metrics endpoint exposes these Prometheus metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `crowdsec_unifi_bouncer_up` | Gauge | Whether bouncer service is running (1=up) |
| `crowdsec_unifi_bouncer_blocked_ips_total` | Gauge | Current IPs in ipset |
| `crowdsec_unifi_bouncer_ipset_size` | Gauge | Configured maxelem capacity |
| `crowdsec_unifi_bouncer_ipset_fill_ratio` | Gauge | Current/max capacity (0.0-1.0) |
| `crowdsec_unifi_bouncer_memory_available_kb` | Gauge | Available system memory |
| `crowdsec_unifi_bouncer_memory_total_kb` | Gauge | Total system memory |
| `crowdsec_unifi_bouncer_last_sync_timestamp` | Gauge | Last ensure-rules.sh run (Unix timestamp) |
| `crowdsec_unifi_bouncer_input_rule_present` | Gauge | INPUT DROP rule exists (1=yes) |
| `crowdsec_unifi_bouncer_forward_rule_present` | Gauge | FORWARD DROP rule exists (1=yes) |
| `crowdsec_unifi_bouncer_errors_total` | Counter | Total errors encountered |
| `crowdsec_unifi_bouncer_guardrail_triggered_total` | Counter | Memory guardrail activations |
| `crowdsec_unifi_bouncer_rules_restored_total` | Counter | Times iptables rules were re-added |
| `crowdsec_unifi_bouncer_decisions_dropped_total` | Counter | Decisions that couldn't be added (ipset full) |
| `crowdsec_unifi_bouncer_capacity_percent` | Gauge | Current ipset usage percentage (0-100) |
| `crowdsec_unifi_bouncer_degraded` | Gauge | Bouncer at capacity and dropping decisions (1=yes) |

## Variables

The dashboard supports these template variables:

- **instance**: Filter by bouncer instance (supports multi-select, defaults to all)

## Alerting

Recommended alerts to configure in Prometheus/Alertmanager:

```yaml
groups:
  - name: crowdsec-unifi-bouncer
    rules:
      # Bouncer down
      - alert: CrowdSecBouncerDown
        expr: crowdsec_unifi_bouncer_up == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "CrowdSec bouncer is down on {{ $labels.instance }}"

      # ipset >80% full
      - alert: CrowdSecIpsetNearCapacity
        expr: crowdsec_unifi_bouncer_ipset_fill_ratio > 0.8
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "CrowdSec ipset at {{ $value | humanizePercentage }} capacity"

      # Memory <300MB
      - alert: CrowdSecLowMemory
        expr: crowdsec_unifi_bouncer_memory_available_kb < 300000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low memory on {{ $labels.instance }}: {{ $value | humanize1024 }}B available"

      # iptables rules missing
      - alert: CrowdSecRulesMissing
        expr: crowdsec_unifi_bouncer_input_rule_present == 0 or crowdsec_unifi_bouncer_forward_rule_present == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "CrowdSec iptables rules missing on {{ $labels.instance }}"

      # Guardrail triggered
      - alert: CrowdSecGuardrailTriggered
        expr: increase(crowdsec_unifi_bouncer_guardrail_triggered_total[1h]) > 0
        labels:
          severity: warning
        annotations:
          summary: "CrowdSec memory guardrail triggered on {{ $labels.instance }}"

      # Bouncer degraded (at capacity, dropping decisions)
      - alert: CrowdSecBouncerDegraded
        expr: crowdsec_unifi_bouncer_degraded == 1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "CrowdSec bouncer at capacity on {{ $labels.instance }} - decisions being dropped"
          description: "ipset is full. Increase maxelem or reduce blocklist subscriptions."

      # Decisions being dropped
      - alert: CrowdSecDecisionsDropped
        expr: increase(crowdsec_unifi_bouncer_decisions_dropped_total[1h]) > 0
        labels:
          severity: warning
        annotations:
          summary: "{{ $value }} CrowdSec decisions dropped on {{ $labels.instance }} in last hour"
```

## Troubleshooting

### No data showing
1. Verify metrics service is running: `systemctl status crowdsec-unifi-metrics`
2. Test metrics endpoint: `curl http://localhost:9101/metrics`
3. Check Prometheus targets page for scrape errors
4. Verify firewall allows access to port 9101

### Metrics endpoint not accessible remotely
- Default binds to `0.0.0.0:9101`
- Check UniFi firewall rules for the metrics port
- Verify no conflicting services on port 9101

### "No data" for specific panels
- Check if the bouncer is running: `systemctl status crowdsec-firewall-bouncer`
- Verify ipset exists: `ipset list crowdsec-blacklists | head`
- Check iptables rules: `iptables -L INPUT -n | grep crowdsec`

## License

MIT License - see repository root for details.
