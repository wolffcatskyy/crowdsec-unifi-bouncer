# Roadmap

Development direction for crowdsec-unifi-bouncer.

## Current Version

**v2.0.0** (February 2026)

Native ipset/iptables implementation replacing the Python/Docker API approach:
- Official CrowdSec firewall bouncer binary (Go)
- ipset-based blocking — no MongoDB thrashing
- Firmware update persistence
- Controller reprovisioning recovery
- Memory guardrail protection
- Prometheus metrics
- Device auto-detection
- One-line installer

## Next Release: v2.1.0

### IPv6 Support
- Test ip6tables rules across device models
- Separate ipset for IPv6 (hash:net family inet6)
- Add IPv6 toggle with clear documentation
- Update ensure-rules.sh for IPv6 persistence

### Alerting Integration
- Webhook support for guardrail events
- Integration docs for ntfy, Telegram, Pushover
- Alert deduplication

## Future Releases

### UniFi Gateway Max Support
- New device (12GB RAM) — add to detect-device.sh when available

### nftables Migration
- Modern UniFi OS versions may support nftables
- Prepare migration path when iptables deprecated
- Maintain backwards compatibility

### Health Check API
- Lightweight HTTP endpoint for external monitoring
- Report: bouncer status, ipset count, memory, last sync

### Multi-LAPI Support
- Connect to multiple CrowdSec LAPI instances
- Aggregate decisions from different sources

## Known Limitations

| Limitation | Reason | Workaround |
|------------|--------|------------|
| Device capacity limits | Hardware constraint | Use CrowdSec Console to filter blocklists |
| No GUI integration | UniFi API doesn't support custom rules | Monitor via Prometheus/Grafana |
| ARM64 binary only | UniFi devices are ARM64 | N/A |
| No official Ubiquiti support | Unofficial modification | Everything in /data/ persists |

## Device Defaults

| Device | Default | RAM |
|--------|---------|-----|
| UDM Pro Max | 30,000 | 8GB |
| UDM Pro / SE | 20,000 | 4GB |
| UDR / UCG | 15,000 | 2GB |
| UniFi Express | 10,000 | 1GB |

Advanced users can increase `ipset_size` in config. Monitor for UI slowness or packet drops, which indicate the limit is too high for your device.

## Related Projects

- [crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser) — Detect threats from UniFi firewall logs
- [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) — Import public threat feeds into CrowdSec
