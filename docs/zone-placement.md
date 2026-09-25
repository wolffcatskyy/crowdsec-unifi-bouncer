# Rule Placement vs UniFi Zone-Based Firewall

Research notes for the future nftables decision. Nothing here changes how the
bouncer blocks traffic. The only code that came out of this is a read-only
check (`ipset-capacity-monitor.sh --placement`, also part of `--status`).

Every claim below is tagged:

- **[source]** read from this repo's code
- **[docs]** from CrowdSec or Ubiquiti documentation
- **[community]** from someone's `iptables` output posted online
- **[unverified]** inferred; not confirmed with a capture on real hardware

We do not yet have a full `iptables -S` capture from a maintainer device in
this repo. Until someone posts one (see [Help wanted](#help-wanted)), the UniFi
side of this document rests on community captures.

## Short version

1. The bouncer puts one `DROP` rule at **position 1** of the built-in `INPUT`
   and `FORWARD` chains. **[source]**
2. UniFi hangs all of its filtering off jumps in those same two chains (`TOR`,
   `ALIEN`, `IPS`/`LO_IPS`, `UBIOS_INPUT_JUMP`, `UBIOS_FORWARD_JUMP`). Zone
   policies live in `UBIOS_<SRC>_<DST>_USER` chains reached through the
   `UBIOS_*_JUMP` chains. **[community]**
3. So when the rule is at position 1, banned IPs are dropped before any
   UniFi rule runs: before legacy rules, before zone policies, before
   "Allow Return Traffic", before UniFi's own IPS. This is the same on the
   legacy firewall and on the zone-based firewall. **[source] + [community]**
4. The zone-based firewall is a **UniFi Network application** feature (9.0+),
   not a UniFi OS feature. UniFi OS 4.x and 5.x can both run it. **[docs]**
5. Every public capture we found, including one from UniFi OS 5.1.12 in this
   repo's issue tracker, still shows legacy iptables with `UBIOS_*` chains. We
   found no evidence that UniFi OS 5 moved to nftables. **[community]**
6. The one real weak spot: `ensure-rules.sh` checks that the rule **exists**
   (`iptables -C`), not that it is **first**. If UniFi ever re-inserts its
   jumps above ours without flushing, the rule would sit below the zone chains
   and nothing would notice. The new check warns about exactly that.
   Whether UniFi actually does this is **[unverified]**.

## What the bouncer installs

| What | Where | Tag |
|------|-------|-----|
| ipset `crowdsec-blacklists`, `hash:net`, IPv4 | `setup.sh` (create), filled by the official bouncer | [source] |
| `iptables -I INPUT 1 -m set --match-set crowdsec-blacklists src -j DROP` | `setup.sh` at service start, `ensure-rules.sh` every 5 min | [source] |
| `iptables -I FORWARD 1 -m set --match-set crowdsec-blacklists src -j DROP` | same | [source] |
| `LOG` rules before each `DROP` in `UBIOS_WAN_*_USER` chains | `log-rules.sh` (cron, every 5 min) | [source] |

Notes:

- The official bouncer runs in `mode: ipset`. In that mode it only manages set
  contents; creating the iptables rules is our job. **[docs]** That means the
  `iptables_chains: [INPUT, FORWARD]` lines in
  `crowdsec-firewall-bouncer.yaml.example` do nothing. The rules come from
  `setup.sh`/`ensure-rules.sh` only.
  Source: https://docs.crowdsec.net/u/bouncers/firewall.md ("Set Only: Iptables/Ipset table")
- `ensure-rules.sh` uses `iptables -C` then `iptables -I <chain> 1`. It fixes a
  missing rule; it does not fix a rule that is present but in the wrong place.
  **[source]**
- IPv4 only. The example config has `disable_ipv6: true` and no script creates
  an `ip6tables` rule. IPv6 traffic from banned sources is not blocked. Not a
  placement issue, but worth knowing. **[source]**
- `log-rules.sh` lists both legacy and zone chain names
  (`UBIOS_WAN_IN_USER` next to `UBIOS_WAN_LAN_USER`, `UBIOS_WAN_LOCAL_USER`,
  `UBIOS_WAN_DMZ_USER`, ...), so it already covers both firewall models.
  **[source]**

## UniFi's chain layout

### Built-in chains

`INPUT` (traffic to the gateway itself), as posted by a UniFi community member:

```
Chain INPUT (policy ACCEPT)
TOR
ALIEN
LO_IPS
UBIOS_INPUT_JUMP
   -> UBIOS_INPUT_GEOIP_PRECHK
   -> UBIOS_DNS_PBR_JUMP
   -> UBIOS_INPUT_USER_HOOK      (user / zone policies to the Gateway zone)
```

**[community]** https://uisp.community.ui.com/questions/fc8ec36f-8e7a-4ad9-965a-e8a7c3592feb

`FORWARD` (routed traffic), from an EFG capture and an IDS/IPS write-up:

```
Chain FORWARD (policy ACCEPT)
ALIEN
TOR
IPS
UBIOS_FORWARD_JUMP               (user / zone policies between zones)
```

**[community]** https://gist.github.com/pensz/e88a8c893a041a453173574157fb1b01 (EFG, published 2026-05; firmware version not stated),
https://cg1network.com/unifi-ids-ips/

`TOR` and `ALIEN` come from CyberSecure's "Dark Web" and "Malicious Hosts"
lists; `IPS` from Suricata IPS. **[community]** (cg1network, above)

### Legacy firewall vs zone-based firewall

Legacy firewall (pre-Network 9.0 rules): **[community]**

- `UBIOS_INPUT_USER_HOOK` -> `UBIOS_{LAN,WAN,GUEST}_LOCAL_USER` by ingress interface
- `UBIOS_FORWARD_IN_USER` -> `UBIOS_{LAN,WAN,GUEST}_IN_USER` by ingress interface
- `UBIOS_FORWARD_OUT_USER` -> `UBIOS_{LAN,WAN,GUEST}_OUT_USER` by egress interface

Zone-based firewall: **[community]**

- Traffic is split by ingress interface, then by **destination address**
  (ipsets such as `UBIOS_LAN_subnets`, `UBIOS_local_zoned_subnets`) into
  `UBIOS_<SRCZONE>_<DSTZONE>_USER` chains, e.g. `UBIOS_WAN_LAN_USER`
  (External -> Internal), `UBIOS_WAN_LOCAL_USER` (External -> Gateway),
  `UBIOS_LAN_WAN_USER`.
- Example rule: `-A UBIOS_LAN_IN_USER -m set ! --match-set UBIOS_local_zoned_subnets dst -j UBIOS_LAN_WAN_USER`

Source: https://www.reddit.com/r/Ubiquiti/comments/1m8kv7q/zone_based_firewall_implemented_incorrectly/

Ubiquiti's migration table maps the old rulesets onto zone pairs (for example
`WAN_IN` -> External to Internal/Hotspot/External/VPN, `WAN_LOCAL` ->
External to Gateway). **[docs]**
https://help.ui.com/hc/en-us/articles/28223082254743-Migrating-to-Zone-Based-Firewalls-in-UniFi

Built-in zone policies include "Allow Return Traffic" (established/related)
and "Block Invalid Traffic" on the External zone. **[docs]**
https://help.ui.com/hc/en-us/articles/115003173168-Zone-Based-Firewalls-in-UniFi

UniFi's own system chains (e.g. `UBIOS_FORWARD_JUMP`, `UBIOS_DNS_PBR_JUMP`)
can accept traffic before zone policies are consulted, which is why people
end up inserting rules by hand. **[community]**
https://discussion.scottibyte.com/t/unifi-zone-based-firewall-fail/690

### Where our rule lands

```
INPUT                                   FORWARD
 1  crowdsec DROP   <- ours              1  crowdsec DROP   <- ours
 2  TOR                                  2  ALIEN
 3  ALIEN                                3  TOR
 4  LO_IPS                               4  IPS
 5  UBIOS_INPUT_JUMP -> zone chains      5  UBIOS_FORWARD_JUMP -> zone chains
```

**[source]** for our position, **[community]** for the rest.

What that means:

- Banned sources never reach a zone policy. A port forward, a custom allow
  policy, or "Allow Return Traffic" cannot let them back in.
- Our `DROP` sits before any established/related accept, so existing sessions
  from a newly banned IP are cut too.
- The flip side: you cannot allow-list a banned IP with a UniFi zone policy.
  Allow-listing has to happen in CrowdSec.
- UniFi's IPS never sees traffic we drop, so it will not log it. The LOG rules
  from `log-rules.sh` are for traffic UniFi itself drops, not ours.

## UniFi OS 4 vs UniFi OS 5

| | UniFi OS 4.x | UniFi OS 5.x |
|---|---|---|
| Zone-based firewall available | Yes, with Network 9.0+ **[docs]** | Yes; OS 5.0.16 ships Network 10.0.162 **[docs]** |
| iptables backend | Legacy iptables; `nft list ruleset` empty on an EFG capture (OS version not stated) **[community]** | No capture found. **[unverified]** |
| `UBIOS_*` chains present | Yes **[community]** | Yes: issue #50 (UCG Fiber, UniFi OS 5.1.12, Network 10.4.57) shows `log-rules.sh --status` finding all seven `UBIOS_WAN_*_USER` chains, legacy and zone names both **[community]** |
| Our DROP at position 1 | Same code path **[source]**; tested on UDM SE and UDR per `architecture.md`, no capture recorded | Same code path **[source]**; placement on hardware **[unverified]** |
| Top of `INPUT`/`FORWARD` order | TOR/ALIEN/IPS then UBIOS jumps **[community]** | **[unverified]** |

Sources: https://amplifi.community.ui.com/releases/UniFi-OS-Dream-Routers-5-0-16/28b70dc1-d629-44c7-9aa3-26a6fd7d1ff0,
https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/issues/50

Short answer: from everything public, OS 4 and OS 5 look the same to this
bouncer. The firewall model (legacy vs zone) is set by the Network app
version and the user's migration choice, not by the OS major version.

## Failure modes

| Case | What happens | Covered by |
|------|--------------|------------|
| Rule flushed (reprovision, bouncer restart) | Rule missing until the next cron run | `ensure-rules.sh` re-adds within 5 min; `--placement` warns |
| UniFi re-inserts its jumps above ours (no flush) | Our rule sits below the zone chains; allow policies win | **Not auto-fixed.** `--placement` warns. Whether UniFi does this is **[unverified]** |
| An `ACCEPT` added above ours (by a user script, e.g. the scottibyte approach) | Accepted traffic skips our drop | `--placement` warns |
| UniFi moves to native nftables | See next section | `--placement` warns on native nft tables or missing UniFi jumps |

Community tooling reports that UniFi provisioning flushes custom iptables rules
and that polling for this every few seconds is a workable fix.
**[community]** https://github.com/unredacted/unifi-scripts/

## The placement check

```bash
/data/crowdsec-bouncer/ipset-capacity-monitor.sh --placement   # exit 1 on warning
/data/crowdsec-bouncer/ipset-capacity-monitor.sh --status      # includes the same section
```

It only reads (`iptables -V`, `iptables -S`, `ipset list -n`, `nft list tables`).
It reports:

- iptables backend (`legacy` or `nf_tables`)
- firewall model, as a heuristic: zone-based if the `UBIOS_local_zoned_subnets`
  ipset exists, plus the number of `UBIOS_*_USER` chains
- for `INPUT` and `FORWARD`:
  - `WARN` if the crowdsec `DROP` is missing
  - `WARN` if it is below the first UniFi jump (`UBIOS_*`, `TOR`, `ALIEN`, `IPS`, `LO_IPS`)
  - `WARN` if any `ACCEPT` comes before it
  - `WARN` if no UniFi jumps exist at all (unknown layout)
  - `INFO` if there are duplicate copies
- `WARN` if native nftables tables exist that the iptables view cannot see

Example of a healthy result (from a test with a stubbed `iptables`, not a real device):

```
  [OK]   INPUT: crowdsec DROP is rule 1 of 5, ahead of TOR (rule 2)
  [OK]   FORWARD: crowdsec DROP is rule 1 of 5, ahead of ALIEN (rule 2)

Placement: OK
```

It does not move rules. When it warns about order it prints the two commands
to put the rule back on top.

## If Ubiquiti moves to nftables

How to tell: `iptables -V` shows `(nf_tables)` instead of `(legacy)`, or
`nft list tables` shows tables other than the iptables-nft compat ones
(`ip filter`, `ip nat`, `ip mangle`, ...). **[docs]** (CrowdSec firewall docs, above)

There are two different moves Ubiquiti could make.

### A. iptables-nft (same rules, new backend)

UniFi keeps writing iptables rules but through the `iptables-nft` shim.

- Our `iptables -C` / `iptables -I ... 1` calls keep working; rules land in
  the compat `ip filter` table's `INPUT`/`FORWARD` chains, same order.
  **[unverified]** on UniFi
- `-m set` needs the kernel ipset (`ip_set`, `xt_set`) modules to stay.
  **[unverified]**
- Mixing: if our install ever used `iptables-legacy` while UniFi used
  `iptables-nft`, each would see only its own rules. Both still filter, and a
  drop in either is final, but the placement check would only see one side.

Changes needed: probably none beyond confirming the modules and binary.

### B. Native nftables (UniFi's own tables and base chains)

nftables orders **base chains by priority** on each hook. A `drop` anywhere is
final. An `accept` only ends that one chain; the packet still goes through
later base chains on the same hook. **[docs]**
https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains

That changes the problem:

- Rule order inside UniFi's chains stops mattering to us. What matters is that
  our drop sits in **its own table** with a base chain on the right hooks. A
  UniFi `accept` in its own table cannot override our `drop`.
- The risk moves elsewhere: if UniFi provisioning does `flush ruleset`, our
  table goes with it. **[unverified]**
- Hooks: CrowdSec's documented set-only example uses `hook input priority
  filter`. For a router we would also need `hook forward`, the same as the
  `FORWARD` rule today. **[docs]**

What would have to change in this repo:

| Piece | Today | nftables version |
|-------|-------|------------------|
| Bouncer mode | `mode: ipset` | `mode: nftables` (managed: bouncer creates table `crowdsec` / chain `crowdsec-chain`), or `set-only: true` with our own table **[docs]** |
| `setup.sh` | `ipset create` + `iptables -I` | `nft -f` a `table ip crowdsec` with the set and `input` + `forward` base chains (set-only), or nothing (managed) |
| `ensure-rules.sh` | `iptables -C` / `-I` | `nft list table ip crowdsec` exists, else re-create; check chains and hooks |
| `log-rules.sh` | `iptables LOG` before DROPs in `UBIOS_WAN_*_USER` | `log` statements; UniFi chain names under nft unknown **[unverified]** |
| `ipset-capacity-monitor.sh`, `metrics.sh`, `ensure-rules.sh` capacity | `ipset list -t` (entries, maxelem) | count set elements via `nft list set`; `maxelem` becomes the set `size` |
| `detect-device.sh` limits | ipset `maxelem` | nft set `size`; memory per element needs re-measuring **[unverified]** |
| `install.sh` | requires `ipset` binary | requires `nft` |
| Placement check | iptables order vs UniFi jumps | our table exists, base chains on `input`/`forward`, priority vs UniFi's base chains |
| IPv6 | not blocked | easy to add `table ip6 crowdsec6` at the same time |
| Timeouts | ipset caps at 2147483 s | nft sets have no such cap noted in CrowdSec docs (cap is ipset-specific) **[docs]** |

Recommendation for the decision: don't build nftables mode until a UniFi
release actually ships native nft tables. When the placement check starts
warning about native tables or missing UniFi jumps on real devices, that is
the signal.

## Help wanted

To replace the **[unverified]** tags we need, from UniFi OS 4.x and 5.x
devices, with zone-based firewall on and off:

```bash
cat /etc/unifi-os/unifi_version 2>/dev/null; ubnt-device-info firmware 2>/dev/null
iptables -V
iptables -S INPUT; iptables -S FORWARD
iptables -S | grep -c '^-N UBIOS_'
nft list tables 2>/dev/null
/data/crowdsec-bouncer/ipset-capacity-monitor.sh --placement
```

Useful extra: the same `iptables -S INPUT` / `FORWARD` output again right after
changing a firewall policy in the UI, to see whether provisioning flushes our
rule or pushes it down.
