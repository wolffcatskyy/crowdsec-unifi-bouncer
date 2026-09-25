# Device Compatibility & Defaults

The bouncer auto-detects your UniFi device model on startup and applies safe default ipset limits based on [Ubiquiti's CyberSecure IPS signature capacity specifications](https://help.ui.com/hc/en-us/articles/25930305913751).

## Measured capacity (one canonical table)

Where do the numbers come from? Three sources have circulated in this repo, and
they did not agree. This table reconciles them:

- **Measured** values come from real-device testing reported in
  [#28](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/issues/28):
  `hash:net` ipset uses ~46 bytes of kernel memory per entry, and the practical
  ceiling is set by UniFi Network application stability, not RAM (the Network
  app crashes when entry counts exceed what the device handles).
- **Spec-derived** values are the conservative defaults below, based on
  Ubiquiti's published IPS signature capacity per tier.
- **Estimate** values are extrapolations with no device testing behind them.

| Device | RAM | Safe maxelem (measured) | Basis | Current default |
|--------|-----|------------------------|-------|-----------------|
| UDM SE | 4 GB | 120,000 | **Measured** — stable at 60K active entries (#28) | 50,000 |
| UDM Pro | 4 GB | 120,000 | **Estimate** — same hardware class as UDM SE (#28) | 50,000 |
| UDR | ~1 GB | 40,000 | **Measured** — stable at 20K active entries (#28) | 15,000 |
| USG-3P | 512 MB | ~15,000 | **Estimate** — untested, use caution (#28) | n/a (legacy) |
| EFG / UXG-Enterprise | -- | 80,000 | **Spec-derived** (Ubiquiti IPS capacity), untested with this bouncer | 80,000 |
| Other Pro tier (UDM-Pro-Max, UDW, UCG-*, UXG-*) | -- | 50,000 | **Spec-derived**, untested with this bouncer | 50,000 |
| Other Consumer tier (UDM, UDR7, UX7) | -- | 15,000 | **Spec-derived**, untested with this bouncer | 15,000 |

Notes:

- The current defaults are deliberately **below** the measured ceilings. If you
  want the measured headroom on a tested device, set `MAXELEM_OVERRIDE` (and
  the sidecar's `max_decisions` to match, minus 2,000 headroom for manual bans).
- Memory is a secondary constraint: 120K entries is only ~5.5 MB of kernel
  memory. The primary constraint is Network app stability — raise limits
  incrementally and watch the controller.
- The defaults above are derived from Ubiquiti's own published per-device
  capacity figures; they are not measurements from this project. "Untested
  with this bouncer" means not validated on that hardware - it does not mean
  the hardware lacks the capability.
- Older claims you may still see quoted: "15K-30K entries depending on model"
  (old README), "120K+ capacity" (v2.0 notes, applies to UDM SE-class hardware
  only), and "50K/80K" (spec-derived defaults). The table above supersedes them.


## IPv6

**IPv6 can be enforced in v2.6** (beta: not yet verified on real hardware). With
`disable_ipv6: false` in the bouncer config (the default in the v2.6+ template)
the bouncer fills a separate inet6 ipset (`crowdsec6-blacklists`) and
`setup.sh`/`ensure-rules.sh` mirror the DROP rules into `ip6tables` at position
1. **On v2.5.x and earlier the bouncer is IPv4 only** — IPv6 decisions are not
enforced, and on dual-stack connections a banned host can simply reach you over
IPv6. Existing v2.5.x configs retain `disable_ipv6: true` on upgrade; the
installer does not rewrite them. `setup.sh` warns while IPv6 is off. To opt in
after hardware verification, set `disable_ipv6: false` in the existing config
and restart the bouncer. New installs use the v2.6 template with IPv6 on.

The v4 and v6 sets have **separate capacities**: each set has its own
`maxelem`, and the sidecar caps them independently (`max_decisions` /
`max_decisions_v6`). Without overrides the v6 set holds at most 2,000 entries and the sidecar
returns at most 1,000 IPv6 decisions. Set `MAXELEM_V6_OVERRIDE` and
`max_decisions_v6` explicitly to change them; leave headroom. These entries
add to the v4 set, and the UDR 40K measured figure was total memory, not
40K for each set. Combined limits need verification on real hardware.

## UniFi OS 5.x

**OS 5.x: iptables confirmed.** A community capture from a UCG Fiber on UniFi OS
5.1.12 (Network 10.4.57, [issue #50](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/issues/50))
shows the legacy iptables backend with all seven `UBIOS_WAN_*_USER` chains
present - the same layout this bouncer installs into on OS 4.x. No public
evidence that UniFi OS 5 moved to nftables. Details: [zone-placement.md](zone-placement.md).

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
| UXG-Lite | **Unvalidated** | -- | -- | -- |
| Unknown device | -- | 10,000 | -- | 8,000 |

**Why is UXG-Lite "Unvalidated" and not "Unsupported"?** The UXG-Lite does have ipset - community dynamic-blocklist scripts drive it directly. It is listed as unvalidated because there is no tested on-device install/persistence path for the bouncer binary: unifios-utilities' on-boot-script covers the UDM/UDR family, uxg-boot covers the UXG-Pro only, and the Lite's hardware (1 GHz dual-core Cortex-A53, 1 GB RAM) is far below every tested device. See [discussion #48](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/discussions/48) - if you have a UXG-Lite and want to help validate it, start there.

"Sidecar Cap" = recommended `max_decisions` for the sidecar proxy, leaving 2,000 entries of headroom for manual bans. IPv6 (v2.6+): the inet6 set defaults to 2,000 entries and the sidecar caps it separately with `max_decisions_v6` (defaults to 1,000). The two limits are independent - each set has its own maxelem, so a flood in one family can't evict the other.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MAXELEM_OVERRIDE` | Manual override for ipset maxelem. Bypasses auto-detection. Logs a warning if it exceeds the recommended limit for your device. | Auto-detected |
| `MAXELEM_V6_OVERRIDE` | Manual override for the IPv6 ipset (inet6) maxelem. The v6 set is a separate set with its own maxelem; without an override it uses 2,000 entries. | 2,000 |
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
[ERROR] This device has no validated on-device install/persistence path (see discussion #48)
[ERROR] crowdsec-unifi-bouncer cannot run on this device
```

## Custom Limits

To use a different limit, set `MAXELEM_OVERRIDE` as an environment variable before starting the bouncer. If using the sidecar, also set `max_decisions` in the sidecar config to match (`MAXELEM_OVERRIDE - 2000`).
