#!/bin/bash
# Ensures CrowdSec iptables rules are in place and monitors memory safety
# Run via cron every 5 minutes to survive controller reprovisioning
#
# Add to crontab:
#   */5 * * * * /data/crowdsec-bouncer/ensure-rules.sh

export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

IPSET_NAME="crowdsec-blacklists"
BOUNCER_DIR="/data/crowdsec-bouncer"
LOGFILE="$BOUNCER_DIR/log/memory.log"
METRICS_SCRIPT="$BOUNCER_DIR/metrics.sh"
GUARDRAIL_FLAG="$BOUNCER_DIR/.guardrail-triggered"

# Detect sidecar mode for capacity recommendations
SIDECAR_MODE=""
if [ -f "$BOUNCER_DIR/detect-sidecar.sh" ]; then
    source "$BOUNCER_DIR/detect-sidecar.sh"
fi

# Memory threshold in kB — stop bouncer if MemAvailable drops below this.
# 200MB default. Override with MEM_THRESHOLD env var.
MEM_THRESHOLD="${MEM_THRESHOLD:-200000}"

# --- Memory monitoring ---

MEM_AVAIL=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
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

# --- Memory guardrail recovery ---
# If the guardrail previously stopped the bouncer and memory has recovered
# above threshold (with 20% hysteresis to prevent flapping), restart it.
RECOVERY_HYSTERESIS_PCT=120  # require memory at 120% of threshold before restarting
RECOVERY_THRESHOLD=$((MEM_THRESHOLD * RECOVERY_HYSTERESIS_PCT / 100))

if [ -f "$GUARDRAIL_FLAG" ]; then
    if [ "$BOUNCER_ACTIVE" = "active" ]; then
        # Bouncer was restarted manually — clean up stale flag
        rm -f "$GUARDRAIL_FLAG"
        echo "$(date '+%F %T') GUARDRAIL: stale flag cleared — bouncer was restarted externally" >> "$LOGFILE"
    elif [ "$MEM_AVAIL" -ge "$RECOVERY_THRESHOLD" ]; then
        # Memory has recovered sufficiently — restart the bouncer
        systemctl start crowdsec-firewall-bouncer
        rm -f "$GUARDRAIL_FLAG"
        echo "$(date '+%F %T') RECOVERY: restarted bouncer — mem_avail=${MEM_AVAIL}kB (threshold=${MEM_THRESHOLD}kB, recovery=${RECOVERY_THRESHOLD}kB)" >> "$LOGFILE"
        logger -t crowdsec-bouncer "RECOVERY: restarted bouncer — mem_avail=${MEM_AVAIL}kB recovered above threshold"
        # Re-read bouncer status for the rule-check section below
        BOUNCER_ACTIVE="active"
        # Record recovery event for Prometheus metrics
        [ -x "$METRICS_SCRIPT" ] && "$METRICS_SCRIPT" --record-guardrail-recovery 2>/dev/null || true
    fi
fi

# If memory is critical and bouncer is running, stop it (ipset entries stay — protection continues)
if [ "$MEM_AVAIL" -lt "$MEM_THRESHOLD" ] && [ "$BOUNCER_ACTIVE" = "active" ] && [ "$IPSET_COUNT" -gt 0 ]; then
    systemctl stop crowdsec-firewall-bouncer
    touch "$GUARDRAIL_FLAG"
    echo "$(date '+%F %T') GUARDRAIL: stopped bouncer at $IPSET_COUNT entries, mem_avail=${MEM_AVAIL}kB (threshold=${MEM_THRESHOLD}kB)" >> "$LOGFILE"
    logger -t crowdsec-bouncer "GUARDRAIL: stopped bouncer — mem_avail=${MEM_AVAIL}kB, entries=$IPSET_COUNT"
    # Record guardrail event for Prometheus metrics
    [ -x "$METRICS_SCRIPT" ] && "$METRICS_SCRIPT" --record-guardrail 2>/dev/null || true
    exit 0
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
