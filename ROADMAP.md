# Roadmap

This document outlines the development direction for crowdsec-unifi-bouncer.

## Current Version

**v2.0.0** (February 2026)

Major rewrite from Python/Docker API-based bouncer to native ipset/iptables approach. Key features:
- Native CrowdSec firewall bouncer binary (Go)
- ipset-based blocking (no MongoDB thrashing)
- Firmware update persistence via setup.sh
- Controller reprovisioning recovery via ensure-rules.sh (cron)
- Memory guardrail protection
- Prometheus metrics endpoint
- Auto device detection with conservative defaults
- One-line bootstrap installer

## Next Release: v2.1.0

Planned improvements for the next minor release:

### Community-Sourced ipset Limits
- **Problem**: All maxelem values are untested estimates (20,000 for all devices)
- **Solution**: Create a community database of verified stable limits
- **Tasks**:
  - Add `report-limits.sh` script to generate device/firmware/limit reports
  - Document submission format in CONTRIBUTING.md
  - Update detect-device.sh with verified limits as reports come in
  - Add firmware version to detection output

### IPv6 Support
- **Problem**: IPv6 disabled by default due to UniFi quirks
- **Solution**: Test and document IPv6 firewall rules on each device model
- **Tasks**:
  - Test ip6tables rules on UDM SE, UDR, UCG devices
  - Create separate ipset for IPv6 (hash:net family inet6)
  - Add IPv6 toggle to config with clear documentation
  - Update ensure-rules.sh for IPv6 rule persistence

### Alerting Integration
- **Problem**: Memory guardrail triggers silently (only logged)
- **Solution**: Optional alerting when guardrail activates or rules restored
- **Tasks**:
  - Add webhook support for guardrail events
  - Document integration with ntfy, Telegram, Pushover
  - Add alert deduplication (don't spam on repeated triggers)

## Future Releases: v2.2.0+

### UniFi Gateway Max Support
- New device (12GB RAM) needs testing
- Add to detect-device.sh once available

### Auto-Tuning Mode
- Experimental: Gradually increase maxelem while monitoring memory
- Stop and report when memory threshold approached
- Find safe limit automatically instead of manual testing

### nftables Migration
- Modern UniFi OS versions may support nftables
- Prepare migration path when iptables deprecated
- Maintain backwards compatibility

### Health Check API
- Lightweight HTTP endpoint for external monitoring
- Report: bouncer status, ipset count, memory, last sync
- Complement existing Prometheus metrics

### Multi-LAPI Support
- Connect to multiple CrowdSec LAPI instances
- Aggregate decisions from different sources
- Use case: separate internal/external threat feeds

## Known Limitations

These are architectural constraints, not planned features:

| Limitation | Reason | Workaround |
|------------|--------|------------|
| Cannot exceed device RAM | Hardware constraint | Use CrowdSec Console to filter blocklists |
| No GUI integration | UniFi API doesn't support custom rules | Monitor via Prometheus/Grafana |
| ARM64 binary only | UniFi devices are ARM64 | N/A (correct architecture) |
| No official Ubiquiti support | Unofficial modification | Everything in /data/ persists |

## Tested Device Matrix

Help us build this by reporting your results!

| Device | Firmware | Stable maxelem | RAM | Reporter |
|--------|----------|----------------|-----|----------|
| UDM SE | 4.x | 20,000 (untested higher) | 4GB | - |
| UDR | 4.x | 20,000 (untested higher) | 2GB | - |
| UDM Pro | - | Untested | 4GB | - |
| UDM Pro Max | - | Untested | 8GB | - |
| UCG Ultra | - | Untested | 2GB | - |
| UniFi Express | - | Untested | 1GB | - |

**To contribute**: Run with monitoring for 48+ hours, then open an issue with:
- Device model
- Firmware version
- UniFi apps running (Protect, Talk, Access)
- Stable maxelem achieved
- MemAvailable at that level

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to help with:
- Device testing and limit reporting
- Documentation improvements
- Bug fixes and feature development

## Related Projects

Complete UniFi + CrowdSec integration:
- [crowdsec-unifi-parser](https://github.com/wolffcatskyy/crowdsec-unifi-parser) - Detect threats from UniFi firewall logs
- [crowdsec-blocklist-import](https://github.com/wolffcatskyy/crowdsec-blocklist-import) - Import public threat feeds into CrowdSec
