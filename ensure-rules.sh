#!/bin/bash
# Ensures CrowdSec iptables rules are in place and monitors memory safety
# Run via cron every 5 minutes to survive controller reprovisioning
#
# Add to crontab:
#   */5 * * * * /data/crowdsec-bouncer/ensure-rules.sh

# --- PATH hardening -----------------------------------------------------------
# cron and systemd hand this script a minimal PATH that does NOT include
# /usr/sbin on UniFi OS, where ipset/iptables/logger live. Without this,
# every ipset/iptables call below silently fails ("command not found",
# swallowed by 2>/dev/null), so rule restoration and the memory guardrail
# never actually run under cron. See issue #53.
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

IPSET_NAME="crowdsec-blacklists"
IPSET_V6_NAME="${IPSET_V6_NAME:-crowdsec6-blacklists}"
BOUNCER_DIR="/data/crowdsec-bouncer"
LOGFILE="$BOUNCER_DIR/log/memory.log"
METRICS_SCRIPT="$BOUNCER_DIR/metrics.sh"

# Marker recording that THIS script's memory guardrail stopped the bouncer.
# Presence of the marker is what authorizes auto-restart: an operator who
# manually stopped the bouncer leaves no marker, so we never fight them.
GUARDRAIL_MARKER="$BOUNCER_DIR/.guardrail-stopped"

# Detect sidecar mode for capacity recommendations
SIDECAR_MODE=""
if [ -f "$BOUNCER_DIR/detect-sidecar.sh" ]; then
    source "$BOUNCER_DIR/detect-sidecar.sh"
fi

# Memory threshold in kB — stop bouncer if MemAvailable drops below this.
# 200MB default. Override with MEM_THRESHOLD env var.
MEM_THRESHOLD="${MEM_THRESHOLD:-200000}"

# Recovery hysteresis (issue #54): the bouncer is only auto-restarted once
# MemAvailable climbs back above MEM_THRESHOLD + MEM_RECOVERY_MARGIN, and stays
# there for RECOVERY_CONFIRM_RUNS consecutive checks. The margin prevents
# flapping around the threshold; the run count avoids restarting into a
# transient recovery that immediately re-triggers the guardrail.
MEM_RECOVERY_MARGIN="${MEM_RECOVERY_MARGIN:-100000}"   # +100MB default
RECOVERY_CONFIRM_RUNS="${RECOVERY_CONFIRM_RUNS:-2}"    # 2 healthy runs (~10min)
RECOVERY_THRESHOLD=$((MEM_THRESHOLD + MEM_RECOVERY_MARGIN))

# --- Rule placement helper --------------------------------------------------
# ensure_drop_at_top <iptables|ip6tables> <chain> <ipset>
# The bouncer's DROP rules must sit at position 1 of INPUT and FORWARD, ahead of
# every UniFi-managed jump (TOR, ALIEN, IPS, UBIOS_*). UniFi reprovisioning can
# insert its jumps ABOVE an existing rule without removing it, so an existence
# check (-C) alone would leave the rule stranded below the zone chains where an
# allow policy can accept a banned source first (see docs/zone-placement.md).
# Missing rule -> insert at position 1. Existing rule not at position 1 ->
# delete and re-insert at position 1. Prints "added", "moved", or "ok".
ensure_drop_at_top() {
    local cmd="$1" chain="$2" set_name="$3" first
    if "$cmd" -C "$chain" -m set --match-set "$set_name" src -j DROP 2>/dev/null; then
        first=$("$cmd" -S "$chain" 2>/dev/null | grep -m1 -- "^-A $chain ")
        case "$first" in
            "-A $chain -m set --match-set $set_name src -j DROP"*)
                echo "ok"
                return 0
                ;;
        esac
        # Rule exists but something sits above it - move it back to the top.
        "$cmd" -D "$chain" -m set --match-set "$set_name" src -j DROP 2>/dev/null || return 1
        "$cmd" -I "$chain" 1 -m set --match-set "$set_name" src -j DROP || return 1
        echo "moved"
        return 0
    fi
    "$cmd" -I "$chain" 1 -m set --match-set "$set_name" src -j DROP || return 1
    echo "added"
    return 0
}

# --- Memory monitoring ---

MEM_AVAIL=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
MEM_AVAIL="${MEM_AVAIL:-0}"
IPSET_COUNT=$(ipset list "$IPSET_NAME" -t 2>/dev/null | awk '/^Number of entries:/{print $NF}')
IPSET_COUNT="${IPSET_COUNT:-0}"
IPSET_MAXELEM=$(ipset list "$IPSET_NAME" -t 2>/dev/null | awk '/^Maxelem:/{print $NF}')
IPSET_MAXELEM="${IPSET_MAXELEM:-0}"
BOUNCER_ACTIVE=$(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null)

# Capacity threshold percentage (95% = at capacity)
CAPACITY_THRESHOLD="${CAPACITY_THRESHOLD:-95}"

# Log ipset count and memory every run (rotate at 1000 lines)
if [ -f "$LOGFILE" ] && [ "$(wc -l < "$LOGFILE")" -gt 1000 ]; then
    tail -500 "$LOGFILE" > "$LOGFILE.tmp" && mv "$LOGFILE.tmp" "$LOGFILE"
fi
echo "$(date '+%F %T') entries=$IPSET_COUNT mem_avail=${MEM_AVAIL}kB bouncer=$BOUNCER_ACTIVE" >> "$LOGFILE"

# If memory is critical and bouncer is running, stop it (ipset entries stay — protection continues)
if [ "$MEM_AVAIL" -lt "$MEM_THRESHOLD" ] && [ "$BOUNCER_ACTIVE" = "active" ] && [ "$IPSET_COUNT" -gt 0 ]; then
    systemctl stop crowdsec-firewall-bouncer
    # Record that WE stopped it, and reset the healthy-run counter to 0.
    echo "0" > "$GUARDRAIL_MARKER"
    echo "$(date '+%F %T') GUARDRAIL: stopped bouncer at $IPSET_COUNT entries, mem_avail=${MEM_AVAIL}kB (threshold=${MEM_THRESHOLD}kB)" >> "$LOGFILE"
    logger -t crowdsec-bouncer "GUARDRAIL: stopped bouncer — mem_avail=${MEM_AVAIL}kB, entries=$IPSET_COUNT"
    # Record guardrail event for Prometheus metrics
    [ -x "$METRICS_SCRIPT" ] && "$METRICS_SCRIPT" --record-guardrail 2>/dev/null || true
    exit 0
fi

# --- Memory guardrail recovery (issue #54) ---
# If the bouncer is down AND we hold a guardrail marker (i.e. WE stopped it for
# low memory), auto-restart once memory has recovered with hysteresis. Without
# this, the guardrail was a one-way trip: the WAN-facing bouncer stayed stopped
# with zero active blocking until a human noticed and restarted it by hand.
if [ -f "$GUARDRAIL_MARKER" ]; then
    if [ "$BOUNCER_ACTIVE" = "active" ]; then
        # Bouncer is running again (operator restart, or a previous recovery).
        # Nothing to recover — clear the marker.
        rm -f "$GUARDRAIL_MARKER"
    else
        healthy_runs=$(cat "$GUARDRAIL_MARKER" 2>/dev/null)
        case "$healthy_runs" in
            ''|*[!0-9]*) healthy_runs=0 ;;
        esac
        if [ "$MEM_AVAIL" -ge "$RECOVERY_THRESHOLD" ]; then
            healthy_runs=$((healthy_runs + 1))
            if [ "$healthy_runs" -ge "$RECOVERY_CONFIRM_RUNS" ]; then
                systemctl start crowdsec-firewall-bouncer
                rm -f "$GUARDRAIL_MARKER"
                BOUNCER_ACTIVE=$(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null)
                echo "$(date '+%F %T') GUARDRAIL: restarted bouncer, mem_avail=${MEM_AVAIL}kB recovered above ${RECOVERY_THRESHOLD}kB for ${healthy_runs} checks (now bouncer=$BOUNCER_ACTIVE)" >> "$LOGFILE"
                logger -t crowdsec-bouncer "GUARDRAIL: restarted bouncer — mem_avail=${MEM_AVAIL}kB recovered (bouncer=$BOUNCER_ACTIVE)"
                [ -x "$METRICS_SCRIPT" ] && "$METRICS_SCRIPT" --record-guardrail-recovery 2>/dev/null || true
                # Fall through so rules are re-verified now that it's running.
            else
                # Healthy but not yet confirmed — persist the count and wait.
                echo "$healthy_runs" > "$GUARDRAIL_MARKER"
                echo "$(date '+%F %T') GUARDRAIL: memory recovered (${MEM_AVAIL}kB >= ${RECOVERY_THRESHOLD}kB), awaiting confirmation ${healthy_runs}/${RECOVERY_CONFIRM_RUNS} before restart" >> "$LOGFILE"
                exit 0
            fi
        else
            # Still below recovery threshold — reset the streak, stay stopped.
            echo "0" > "$GUARDRAIL_MARKER"
            exit 0
        fi
    fi
fi

# --- Capacity monitoring ---
# Check if ipset is at/near capacity (decisions may be dropped)
if [ "$IPSET_MAXELEM" -gt 0 ]; then
    CAPACITY_USED=$((IPSET_COUNT * 100 / IPSET_MAXELEM))

    if [ "$CAPACITY_USED" -ge "$CAPACITY_THRESHOLD" ]; then
        # At capacity - decisions are being dropped
        echo "$(date '+%F %T') CAPACITY: ipset at ${CAPACITY_USED}% ($IPSET_COUNT/$IPSET_MAXELEM) - decisions may be dropped" >> "$LOGFILE"
        if [ "$SIDECAR_MODE" = "sidecar" ]; then
            logger -t crowdsec-bouncer "CAPACITY WARNING: ipset at ${CAPACITY_USED}% ($IPSET_COUNT/$IPSET_MAXELEM) - reduce sidecar max_decisions setting"
        else
            logger -t crowdsec-bouncer "CAPACITY WARNING: ipset at ${CAPACITY_USED}% ($IPSET_COUNT/$IPSET_MAXELEM) - deploy sidecar proxy to prioritize decisions"
        fi
    elif [ "$CAPACITY_USED" -ge 80 ]; then
        # Approaching capacity - warn
        echo "$(date '+%F %T') CAPACITY: ipset at ${CAPACITY_USED}% ($IPSET_COUNT/$IPSET_MAXELEM) - approaching limit" >> "$LOGFILE"
    else
        # Capacity OK - clear degraded status if previously set
        [ -x "$METRICS_SCRIPT" ] && "$METRICS_SCRIPT" --clear-degraded 2>/dev/null || true
    fi
fi

# IPv6 set capacity - the v6 set has its own maxelem, so its limit is tracked
# independently of the v4 set (see docs/device-compatibility.md).
if ipset list "$IPSET_V6_NAME" >/dev/null 2>&1; then
    IPSET6_COUNT=$(ipset list "$IPSET_V6_NAME" -t 2>/dev/null | awk '/^Number of entries:/{print $NF}')
    IPSET6_COUNT="${IPSET6_COUNT:-0}"
    IPSET6_MAXELEM=$(ipset list "$IPSET_V6_NAME" -t 2>/dev/null | awk '/^Maxelem:/{print $NF}')
    IPSET6_MAXELEM="${IPSET6_MAXELEM:-0}"
    if [ "$IPSET6_MAXELEM" -gt 0 ]; then
        CAPACITY6_USED=$((IPSET6_COUNT * 100 / IPSET6_MAXELEM))
        if [ "$CAPACITY6_USED" -ge "$CAPACITY_THRESHOLD" ]; then
            echo "$(date '+%F %T') CAPACITY: IPv6 ipset at ${CAPACITY6_USED}% ($IPSET6_COUNT/$IPSET6_MAXELEM) - decisions may be dropped" >> "$LOGFILE"
            logger -t crowdsec-bouncer "CAPACITY WARNING: IPv6 ipset at ${CAPACITY6_USED}% ($IPSET6_COUNT/$IPSET6_MAXELEM) - reduce sidecar max_decisions_v6 setting"
        elif [ "$CAPACITY6_USED" -ge 80 ]; then
            echo "$(date '+%F %T') CAPACITY: IPv6 ipset at ${CAPACITY6_USED}% ($IPSET6_COUNT/$IPSET6_MAXELEM) - approaching limit" >> "$LOGFILE"
        fi
    fi
fi

# --- Rule persistence ---
# Rules are restored at position 1, not merely made present: an existence check
# alone leaves a rule stranded below UniFi's jumps if reprovisioning inserted
# them above ours. ensure_drop_at_top handles both cases.

# Only check rules if bouncer is running
if [ "$BOUNCER_ACTIVE" != "active" ]; then
    exit 0
fi

# Only act if ipset exists
if ! ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    exit 0
fi

for chain in INPUT FORWARD; do
    result=$(ensure_drop_at_top iptables "$chain" "$IPSET_NAME")
    case "$result" in
        added)
            logger -t crowdsec-bouncer "Re-added $chain DROP rule at position 1"
            # Record rule restoration for Prometheus metrics
            [ -x "$METRICS_SCRIPT" ] && "$METRICS_SCRIPT" --record-rule-restored 2>/dev/null || true
            ;;
        moved)
            logger -t crowdsec-bouncer "Moved $chain DROP rule back to position 1 (UniFi jumps had slipped above it)"
            [ -x "$METRICS_SCRIPT" ] && "$METRICS_SCRIPT" --record-rule-restored 2>/dev/null || true
            ;;
    esac
done

# IPv6 mirror - only when the v6 set exists (setup.sh creates it when the
# bouncer config has disable_ipv6: false).
if command -v ip6tables >/dev/null 2>&1 && ipset list "$IPSET_V6_NAME" >/dev/null 2>&1; then
    for chain in INPUT FORWARD; do
        result=$(ensure_drop_at_top ip6tables "$chain" "$IPSET_V6_NAME")
        case "$result" in
            added)
                logger -t crowdsec-bouncer "Re-added IPv6 $chain DROP rule at position 1"
                [ -x "$METRICS_SCRIPT" ] && "$METRICS_SCRIPT" --record-rule-restored 2>/dev/null || true
                ;;
            moved)
                logger -t crowdsec-bouncer "Moved IPv6 $chain DROP rule back to position 1 (UniFi jumps had slipped above it)"
                [ -x "$METRICS_SCRIPT" ] && "$METRICS_SCRIPT" --record-rule-restored 2>/dev/null || true
                ;;
        esac
    done
fi

# --- LOG rule persistence ---
# Deploy iptables LOG rules before DROP rules in WAN chains
# This gives CrowdSec visibility into blocked traffic for detection and reporting
LOG_RULES_SCRIPT="$BOUNCER_DIR/log-rules.sh"
if [ -x "$LOG_RULES_SCRIPT" ]; then
    "$LOG_RULES_SCRIPT" --quiet 2>/dev/null || true
fi

# --- Rule placement drift check (Prometheus gauge) ---
# Runs on this script's 5-minute cron cadence so drift is caught even when
# nobody runs --placement by hand. The warning count lands in the metrics
# endpoint as crowdsec_unifi_bouncer_rule_placement_ok / _warnings.
PLACEMENT_MONITOR="$BOUNCER_DIR/ipset-capacity-monitor.sh"
if [ -x "$PLACEMENT_MONITOR" ] && [ -x "$METRICS_SCRIPT" ]; then
    PLACEMENT_OUT=$("$PLACEMENT_MONITOR" --placement 2>/dev/null || true)
    PLACEMENT_WARNINGS=$(printf '%s\n' "$PLACEMENT_OUT" | grep -c '\[WARN\]' || true)
    "$METRICS_SCRIPT" --record-placement "${PLACEMENT_WARNINGS:-0}" 2>/dev/null || true
fi
