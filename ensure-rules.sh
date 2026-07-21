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

# --- Rule persistence (existing behavior) ---

# Only check rules if bouncer is running
if [ "$BOUNCER_ACTIVE" != "active" ]; then
    exit 0
fi

# Only act if ipset exists
if ! ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    exit 0
fi

# Re-add rules if missing (controller reprovisioning can remove them)
if ! iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    iptables -I INPUT 1 -m set --match-set "$IPSET_NAME" src -j DROP
    logger -t crowdsec-bouncer "Re-added INPUT DROP rule"
    # Record rule restoration for Prometheus metrics
    [ -x "$METRICS_SCRIPT" ] && "$METRICS_SCRIPT" --record-rule-restored 2>/dev/null || true
fi

if ! iptables -C FORWARD -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    iptables -I FORWARD 1 -m set --match-set "$IPSET_NAME" src -j DROP
    logger -t crowdsec-bouncer "Re-added FORWARD DROP rule"
    # Record rule restoration for Prometheus metrics
    [ -x "$METRICS_SCRIPT" ] && "$METRICS_SCRIPT" --record-rule-restored 2>/dev/null || true
fi

# --- LOG rule persistence ---
# Deploy iptables LOG rules before DROP rules in WAN chains
# This gives CrowdSec visibility into blocked traffic for detection and reporting
LOG_RULES_SCRIPT="$BOUNCER_DIR/log-rules.sh"
if [ -x "$LOG_RULES_SCRIPT" ]; then
    "$LOG_RULES_SCRIPT" --quiet 2>/dev/null || true
fi
