# Device Compatibility & Defaults

The bouncer auto-detects your UniFi device model on startup and applies safe default ipset limits based on [Ubiquiti's CyberSecure IPS signature capacity specifications](https://help.ui.com/hc/en-us/articles/25930305913751).

## Detection Methods

Detection is tried in order:

1. `ubnt-device-info model` — most reliable on UniFi OS 3+
2. `/proc/ubnthal/system.info` shortname field
3. `/etc/unifi-os/unifi_version` model field
4. `/sys/firmware/devicetree/base/model` device tree
5. `dmesg` pattern matching (last resort)

## Device Capacity Matrix

| Model | Tier | Default ipset | Memory Optimized | Sidecar Cap |
|-------|------|---------------|------------------|-------------|
| EFG | Enterprise | 80,000 | -- | 78,000 |
| UXG-Enterprise | Enterprise | 80,000 | -- | 78,000 |
| UDM-Pro-Max | Pro | 50,000 | 30,000 | 48,000 |
| UDM-SE | Pro | 50,000 | 30,000 | 48,000 |
| UDM-Pro | Pro | 50,000 | 30,000 | 48,000 |
| UDW | Pro | 50,000 | 30,000 | 48,000 |
| UCG-Max | Pro | 50,000 | 30,000 | 48,000 |
| UCG-Ultra | Pro | 50,000 | 30,000 | 48,000 |
| UCG-Fiber | Pro | 50,000 | 30,000 | 48,000 |
| UXG-Max | Pro | 50,000 | 30,000 | 48,000 |
| UXG-Pro | Pro | 50,000 | 30,000 | 48,000 |
| UXG-Fiber | Pro | 50,000 | 30,000 | 48,000 |
| UDM | Consumer | 15,000 | -- | 13,000 |
| UDR | Consumer | 15,000 | -- | 13,000 |
| UDR7 | Consumer | 15,000 | -- | 13,000 |
| UX7 | Consumer | 15,000 | -- | 13,000 |
| UX | **Unsupported** | -- | -- | -- |
| UXG-Lite | **Unsupported** | -- | -- | -- |
| Unknown device | -- | 10,000 | -- | 8,000 |

"Sidecar Cap" = recommended `max_decisions` for the sidecar proxy, leaving 2,000 entries of headroom for manual bans.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MAXELEM_OVERRIDE` | Manual override for ipset maxelem. Bypasses auto-detection. Logs a warning if it exceeds the recommended limit for your device. | Auto-detected |
| `MEMORY_OPTIMIZED` | Set to `true` to use reduced limits for devices running BGP, ad-blocking, content filtering, or multiple UniFi applications. | `false` |

## Usage Scenarios

**Scenario 1: Default (auto-detect, safe limits)**
```bash
# No configuration needed — bouncer auto-detects and uses safe defaults
systemctl start crowdsec-firewall-bouncer
```

**Scenario 2: Power user (higher limits)**

For users NOT running Protect, Talk, Access, BGP, ad-blocking, or content filtering:
```bash
MAXELEM_OVERRIDE=70000 /data/crowdsec-bouncer/setup.sh
```

**Scenario 3: Memory constrained**

For devices running BGP, ad-blocking, content filtering, or multiple UniFi applications:
```bash
MEMORY_OPTIMIZED=true /data/crowdsec-bouncer/setup.sh
```

**Scenario 4: Unknown device**
```
[WARNING] Could not detect device model, using conservative limit of 10000
[INFO] Set MAXELEM_OVERRIDE to specify a higher limit if needed
[INFO] Using ipset maxelem: 10000
```

**Scenario 5: Unsupported device**
```
[ERROR] Detected device model: UXG-Lite
[ERROR] This device does not support firewall groups/ipsets
[ERROR] crowdsec-unifi-bouncer cannot run on this device
```

## Custom Limits

To use a different limit, set `MAXELEM_OVERRIDE` as an environment variable before starting the bouncer. If using the sidecar, also set `max_decisions` in the sidecar config to match (`MAXELEM_OVERRIDE - 2000`).
