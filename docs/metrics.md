# Prometheus Metrics

## Bouncer Metrics (port 9101)

Enable the metrics service on your UniFi device:

```bash
ln -sf /data/crowdsec-bouncer/crowdsec-unifi-metrics.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now crowdsec-unifi-metrics

curl http://localhost:9101/metrics
```

| Metric | Description |
|--------|-------------|
| `crowdsec_unifi_bouncer_blocked_ips_total` | Current IPs in ipset |
| `crowdsec_unifi_bouncer_ipset_fill_ratio` | Capacity usage (0.0-1.0) |
| `crowdsec_unifi_bouncer_decisions_dropped_total` | Decisions dropped due to capacity |
| `crowdsec_unifi_bouncer_memory_available_kb` | Available system memory |

## Sidecar Metrics (port 8084)

If using the sidecar, it exposes its own metrics at `/metrics` including effectiveness metrics that show per-origin kept/dropped counts, score distribution, and false-negative detection.

```bash
curl http://YOUR_SIDECAR_HOST:8084/metrics
```

See [sidecar/README.md](../sidecar/README.md#prometheus-metrics-reference) for the full sidecar metrics list.

## AbuseIPDB Metrics

If AbuseIPDB reporting is enabled, additional metrics are exposed alongside sidecar metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `abuseipdb_reports_total` | Counter | Total reports by status (`success`, `failed`, `skipped`) |
| `abuseipdb_reports_queued` | Counter | Reports queued for async sending |

## Grafana Dashboard

A ready-to-import Grafana dashboard is included at [`grafana/crowdsec-unifi-bouncer-dashboard.json`](../grafana/crowdsec-unifi-bouncer-dashboard.json).

Import it via Grafana UI: **Dashboards → Import → Upload JSON file**.
