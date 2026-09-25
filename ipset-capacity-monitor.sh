#!/bin/bash
# CrowdSec UniFi Bouncer - ipset Capacity Monitor
# Monitors bouncer logs for "set is full" errors and tracks dropped decisions
#
# The official cs-firewall-bouncer binary handles ipset add operations internally.
# When ipset reaches maxelem, the kernel returns "set is full" errors. This script
# monitors for those errors, logs warnings, and updates metrics for observability.
#
# Run modes:
#   ./ipset-capacity-monitor.sh              # One-shot check (for cron)
#   ./ipset-capacity-monitor.sh --watch      # Continuous monitoring (for systemd)
#   ./ipset-capacity-monitor.sh --status     # Show current capacity status
#   ./ipset-capacity-monitor.sh --placement  # Check DROP rule placement vs UniFi zone chains
#
# Environment variables:
#   BOUNCER_DIR       - Installation directory (default: /data/crowdsec-bouncer)
#   IPSET_NAME        - Name of the ipset (default: crowdsec-blacklists)
#   CAPACITY_LOG      - Log file for capacity events (default: $BOUNCER_DIR/log/capacity.log)
#   STATE_FILE        - Metrics state file (default: $BOUNCER_DIR/metrics-state)

set -euo pipefail

# --- PATH hardening -----------------------------------------------------------
# cron/systemd provide a minimal PATH without /usr/sbin, where ipset/iptables
# live on UniFi OS. Without this, those calls silently fail under unattended
# execution while working fine in an interactive shell. See issue #53.
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Configuration
BOUNCER_DIR="${BOUNCER_DIR:-/data/crowdsec-bouncer}"
IPSET_NAME="${IPSET_NAME:-crowdsec-blacklists}"
IPSET_V6_NAME="${IPSET_V6_NAME:-crowdsec6-blacklists}"
CAPACITY_LOG="${CAPACITY_LOG:-$BOUNCER_DIR/log/capacity.log}"
STATE_FILE="${STATE_FILE:-$BOUNCER_DIR/metrics-state}"
BOUNCER_LOG="$BOUNCER_DIR/log/crowdsec-firewall-bouncer.log"

# Last processed line marker (to avoid duplicate counting)
MARKER_FILE="$BOUNCER_DIR/.capacity-monitor-marker"

# Initialize capacity log
init_log() {
    mkdir -p "$(dirname "$CAPACITY_LOG")"
    if [ ! -f "$CAPACITY_LOG" ]; then
        echo "# CrowdSec ipset Capacity Log" > "$CAPACITY_LOG"
        echo "# Tracks 'set is full' errors when ipset reaches maxelem" >> "$CAPACITY_LOG"
        echo "" >> "$CAPACITY_LOG"
    fi
}

# Initialize state file if it doesn't exist
init_state() {
    if [ ! -f "$STATE_FILE" ]; then
        cat > "$STATE_FILE" << 'STATEOF'
errors_total=0
guardrail_triggered_total=0
rules_restored_total=0
decisions_dropped_total=0
capacity_events_total=0
last_capacity_event=0
STATEOF
    fi

    # Add new counters if they don't exist (upgrade path)
    if ! grep -q "^decisions_dropped_total=" "$STATE_FILE" 2>/dev/null; then
        echo "decisions_dropped_total=0" >> "$STATE_FILE"
    fi
    if ! grep -q "^capacity_events_total=" "$STATE_FILE" 2>/dev/null; then
        echo "capacity_events_total=0" >> "$STATE_FILE"
    fi
    if ! grep -q "^last_capacity_event=" "$STATE_FILE" 2>/dev/null; then
        echo "last_capacity_event=0" >> "$STATE_FILE"
    fi
}

# Read counter from state file
read_counter() {
    local name="$1"
    grep "^${name}=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "0"
}

# Update counter in state file
update_counter() {
    local name="$1"
    local value="$2"
    if grep -q "^${name}=" "$STATE_FILE" 2>/dev/null; then
        sed -i "s/^${name}=.*/${name}=${value}/" "$STATE_FILE"
    else
        echo "${name}=${value}" >> "$STATE_FILE"
    fi
}

# Increment counter in state file
increment_counter() {
    local name="$1"
    local increment="${2:-1}"
    local current
    current=$(read_counter "$name")
    local new=$((current + increment))
    update_counter "$name" "$new"
    echo "$new"
}

# Get current ipset stats
get_ipset_stats() {
    local entries=0
    local maxelem=0
    local fill_ratio=0

    if ipset list "$IPSET_NAME" -t 2>/dev/null | grep -q "^Name:"; then
        entries=$(ipset list "$IPSET_NAME" -t 2>/dev/null | awk '/^Number of entries:/{print $NF}')
        # ipset 7.x (UniFi OS) prints capacity inline in the Header line; older
        # ipset prints a standalone "Maxelem:" line. Try Header first, fall back.
        maxelem=$(ipset list "$IPSET_NAME" -t 2>/dev/null | awk '/^Header:/{for(i=1;i<=NF;i++) if($i=="maxelem") print $(i+1)}')
        if [ -z "$maxelem" ]; then
            maxelem=$(ipset list "$IPSET_NAME" -t 2>/dev/null | awk '/^Maxelem:/{print $NF}')
        fi
        entries="${entries:-0}"
        maxelem="${maxelem:-0}"
        if [ "$maxelem" -gt 0 ]; then
            fill_ratio=$(awk "BEGIN {printf \"%.2f\", ($entries/$maxelem)*100}")
        fi
    fi

    echo "$entries $maxelem $fill_ratio"
}

# Check for capacity errors in bouncer log
check_for_capacity_errors() {
    init_log
    init_state

    # If bouncer log doesn't exist, nothing to check
    if [ ! -f "$BOUNCER_LOG" ]; then
        return 0
    fi

    # Get the last processed line number
    local last_line=0
    if [ -f "$MARKER_FILE" ]; then
        last_line=$(cat "$MARKER_FILE" 2>/dev/null || echo "0")
    fi

    # Count current lines
    local current_lines
    current_lines=$(wc -l < "$BOUNCER_LOG" 2>/dev/null || echo "0")

    # If log was rotated (current < last), reset marker
    if [ "$current_lines" -lt "$last_line" ]; then
        last_line=0
    fi

    # Search for capacity errors in new lines
    # Common error patterns from ipset:
    # - "set is full"
    # - "Hash is full, cannot add more elements"
    # - "The set is full, cannot add more elements"
    local new_errors=0
    local error_ips=""

    if [ "$current_lines" -gt "$last_line" ]; then
        # Extract new lines and search for capacity errors
        local new_content
        new_content=$(tail -n +"$((last_line + 1))" "$BOUNCER_LOG" 2>/dev/null || echo "")

        # Count "set is full" errors
        local full_errors
        full_errors=$(echo "$new_content" | grep -ci "set is full\|hash is full\|cannot add more elements" 2>/dev/null || echo "0")

        if [ "$full_errors" -gt 0 ]; then
            new_errors=$full_errors

            # Try to extract IPs that failed (if logged)
            error_ips=$(echo "$new_content" | grep -i "set is full\|cannot add" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | head -10 | tr '\n' ' ')
        fi
    fi

    # Update marker
    echo "$current_lines" > "$MARKER_FILE"

    # If errors found, log and update metrics
    if [ "$new_errors" -gt 0 ]; then
        local stats
        stats=$(get_ipset_stats)
        local entries maxelem fill_ratio
        read -r entries maxelem fill_ratio <<< "$stats"

        local timestamp
        timestamp=$(date '+%F %T')

        # Log to capacity log
        {
            echo "$timestamp CAPACITY_ERROR: $new_errors decision(s) dropped - ipset full"
            echo "  Current: $entries/$maxelem entries (${fill_ratio}% full)"
            if [ -n "$error_ips" ]; then
                echo "  Sample dropped IPs: $error_ips"
            fi
        } >> "$CAPACITY_LOG"

        # Update metrics
        increment_counter "decisions_dropped_total" "$new_errors" >/dev/null
        increment_counter "capacity_events_total" >/dev/null
        update_counter "last_capacity_event" "$(date +%s)"

        # Log to syslog for visibility
        logger -t crowdsec-bouncer "CAPACITY WARNING: $new_errors decision(s) dropped - ipset at ${fill_ratio}% ($entries/$maxelem)"

        # Return 1 to indicate errors were found
        return 1
    fi

    return 0
}

# One-shot capacity check with proactive warning
check_capacity() {
    init_log
    init_state

    local stats
    stats=$(get_ipset_stats)
    local entries maxelem fill_ratio
    read -r entries maxelem fill_ratio <<< "$stats"

    local timestamp
    timestamp=$(date '+%F %T')

    # Check for recent capacity errors in log
    check_for_capacity_errors || true

    # Proactive warning at 90% capacity
    if [ "$maxelem" -gt 0 ]; then
        local fill_int
        fill_int=$(awk "BEGIN {printf \"%.0f\", $fill_ratio}")

        if [ "$fill_int" -ge 95 ]; then
            echo "$timestamp WARNING: ipset CRITICAL - ${fill_ratio}% full ($entries/$maxelem)" >> "$CAPACITY_LOG"
            logger -t crowdsec-bouncer "CRITICAL: ipset at ${fill_ratio}% capacity - decisions will be dropped!"
            return 2
        elif [ "$fill_int" -ge 90 ]; then
            echo "$timestamp WARNING: ipset HIGH - ${fill_ratio}% full ($entries/$maxelem)" >> "$CAPACITY_LOG"
            logger -t crowdsec-bouncer "WARNING: ipset at ${fill_ratio}% capacity - approaching limit"
            return 1
        fi
    fi

    # IPv6 set capacity (independent set, independent maxelem)
    if ipset list "$IPSET_V6_NAME" -t >/dev/null 2>&1; then
        local entries6 maxelem6
        entries6=$(ipset list "$IPSET_V6_NAME" -t 2>/dev/null | awk '/^Number of entries:/{print $NF}')
        maxelem6=$(ipset list "$IPSET_V6_NAME" -t 2>/dev/null | awk '/^Maxelem:/{print $NF}')
        entries6="${entries6:-0}"
        maxelem6="${maxelem6:-0}"
        if [ "$maxelem6" -gt 0 ]; then
            local fill6=$((entries6 * 100 / maxelem6))
            if [ "$fill6" -ge 95 ]; then
                echo "$timestamp WARNING: IPv6 ipset CRITICAL - ${fill6}% full ($entries6/$maxelem6)" >> "$CAPACITY_LOG"
                logger -t crowdsec-bouncer "CRITICAL: IPv6 ipset at ${fill6}% capacity - decisions will be dropped!"
                return 2
            elif [ "$fill6" -ge 90 ]; then
                echo "$timestamp WARNING: IPv6 ipset HIGH - ${fill6}% full ($entries6/$maxelem6)" >> "$CAPACITY_LOG"
                logger -t crowdsec-bouncer "WARNING: IPv6 ipset at ${fill6}% capacity - approaching limit"
                return 1
            fi
        fi
    fi

    return 0
}

# --- Rule placement relative to UniFi zone chains ---------------------------
# Read-only check. The bouncer's DROP rules are meant to sit at the very top of
# the built-in INPUT and FORWARD chains, ahead of every UniFi-managed jump
# (TOR, ALIEN, IPS/LO_IPS, UBIOS_INPUT_JUMP, UBIOS_FORWARD_JUMP). All UniFi
# firewall policies, legacy rules and zone-based policies alike, are reached
# through those jumps. If a DROP ends up below them, a zone "allow" policy
# (port forward, Allow Return Traffic, ...) can accept a banned source first.
# Background and sources: docs/zone-placement.md
#
# IPTABLES / NFT / IPSET_CMD can be overridden (used for testing).
IPTABLES="${IPTABLES:-iptables}"
IP6TABLES="${IP6TABLES:-ip6tables}"
NFT="${NFT:-nft}"
IPSET_CMD="${IPSET_CMD:-ipset}"
UNIFI_TARGET_RE='^(UBIOS_[A-Za-z0-9_]+|ALIEN|TOR|IPS|LO_IPS)$'

# Print placement of the crowdsec DROP rule within one built-in chain.
# Args: <iptables-cmd> <chain> <ipset-name>. Family-aware: pass ip6tables and
# the inet6 set for the IPv6 check.
# Returns the number of warnings found (0 = OK).
check_chain_placement() {
    local ipt_cmd="$1" chain="$2" set_name="$3"
    local rules line target
    local idx=0 cs_pos=0 cs_count=0
    local unifi_pos=0 unifi_target="" accept_pos=0

    rules=$("$ipt_cmd" -S "$chain" 2>/dev/null || true)
    while IFS= read -r line; do
        case "$line" in
            "-A $chain "*) ;;
            *) continue ;;
        esac
        idx=$((idx + 1))
        target=$(sed -n 's/.* -[jg] \([^ ]*\).*/\1/p' <<< "$line")
        if [[ "$line" == *"--match-set $set_name src"* ]] && [ "$target" = "DROP" ]; then
            cs_count=$((cs_count + 1))
            [ "$cs_pos" -eq 0 ] && cs_pos=$idx
            continue
        fi
        if [ "$unifi_pos" -eq 0 ] && [[ "$target" =~ $UNIFI_TARGET_RE ]]; then
            unifi_pos=$idx
            unifi_target="$target"
        fi
        if [ "$accept_pos" -eq 0 ] && [ "$target" = "ACCEPT" ]; then
            accept_pos=$idx
        fi
    done <<< "$rules"

    local warn=0 misplaced=0
    if [ "$cs_pos" -eq 0 ]; then
        echo "  [WARN] $chain: no crowdsec DROP rule (ensure-rules.sh re-adds it within 5 min while the bouncer runs)"
        return 1
    fi

    if [ "$unifi_pos" -gt 0 ] && [ "$cs_pos" -gt "$unifi_pos" ]; then
        echo "  [WARN] $chain: crowdsec DROP is rule $cs_pos, below UniFi chain $unifi_target (rule $unifi_pos)."
        echo "         UniFi zone policies run first, so an allow policy can accept banned IPs."
        warn=$((warn + 1))
        misplaced=1
    fi
    if [ "$accept_pos" -gt 0 ] && [ "$cs_pos" -gt "$accept_pos" ]; then
        echo "  [WARN] $chain: an ACCEPT rule (rule $accept_pos) comes before the crowdsec DROP (rule $cs_pos)."
        warn=$((warn + 1))
        misplaced=1
    fi
    if [ "$unifi_pos" -eq 0 ]; then
        echo "  [WARN] $chain: no UniFi jump chains (UBIOS_*, TOR, ALIEN, IPS) found."
        echo "         This is not the UniFi OS layout this check knows. Possible nftables move; see docs/zone-placement.md."
        warn=$((warn + 1))
    fi
    if [ "$misplaced" -eq 1 ]; then
        echo "         ensure-rules.sh moves it back within 5 min. By hand:"
        echo "           $ipt_cmd -D $chain -m set --match-set $set_name src -j DROP"
        echo "           $ipt_cmd -I $chain 1 -m set --match-set $set_name src -j DROP"
    elif [ "$warn" -eq 0 ]; then
        echo "  [OK]   $chain: crowdsec DROP is rule $cs_pos of $idx, ahead of $unifi_target (rule $unifi_pos)"
    fi
    if [ "$cs_count" -gt 1 ]; then
        echo "  [INFO] $chain: $cs_count copies of the crowdsec DROP rule (harmless, but unexpected)"
    fi
    return "$warn"
}

check_rule_placement() {
    local warnings=0 chain rc

    echo "=== Rule Placement (vs UniFi firewall/zone chains) ==="
    echo ""

    if ! command -v "$IPTABLES" >/dev/null 2>&1; then
        echo "  [WARN] $IPTABLES not found - cannot check rule placement"
        return 1
    fi

    local ipt_version backend="legacy"
    ipt_version=$("$IPTABLES" -V 2>/dev/null || true)
    case "$ipt_version" in
        *nf_tables*) backend="nf_tables" ;;
    esac
    echo "  iptables:      ${ipt_version:-unknown} (backend: $backend)"

    # Firewall model, informational only. UBIOS_local_zoned_subnets is an ipset
    # UniFi creates for zone-based firewall dispatch (community-observed, see docs).
    local fw_model="legacy rules or unknown"
    local set_names=""
    if command -v "$IPSET_CMD" >/dev/null 2>&1; then
        set_names=$("$IPSET_CMD" list -n 2>/dev/null || true)
    fi
    if grep -qx 'UBIOS_local_zoned_subnets' <<< "$set_names"; then
        fw_model="zone-based (heuristic)"
    fi
    local zone_chain_count
    zone_chain_count=$("$IPTABLES" -S 2>/dev/null \
        | awk '$1=="-N" && $2 ~ /^UBIOS_[A-Z0-9]+_[A-Z0-9]+_USER$/ {n++} END {print n+0}' || true)
    echo "  Firewall:      $fw_model, $zone_chain_count UBIOS_*_USER policy chains"

    # Native nftables tables that the iptables view cannot see.
    if command -v "$NFT" >/dev/null 2>&1; then
        local native_tables
        native_tables=$("$NFT" list tables 2>/dev/null \
            | awk '$1=="table" && !($2 ~ /^(ip|ip6|arp|bridge)$/ && $3 ~ /^(filter|nat|mangle|raw|security|broute)$/) {printf "%s %s, ", $2, $3}' \
            | sed 's/, $//' || true)
        if [ -n "$native_tables" ]; then
            echo "  [WARN] Native nftables tables present: $native_tables"
            echo "         Rules there are not visible to this check. A drop in any table is final,"
            echo "         but this is not the layout the bouncer was built for. See docs/zone-placement.md."
            warnings=$((warnings + 1))
        fi
    fi
    echo ""

    for chain in INPUT FORWARD; do
        rc=0
        check_chain_placement "$IPTABLES" "$chain" "$IPSET_NAME" || rc=$?
        warnings=$((warnings + rc))
    done

    # IPv6: only when the v6 set exists (setup.sh creates it when the bouncer
    # config has disable_ipv6: false). Skip silently otherwise.
    if command -v "$IP6TABLES" >/dev/null 2>&1 \
        && command -v "$IPSET_CMD" >/dev/null 2>&1 \
        && "$IPSET_CMD" list "$IPSET_V6_NAME" >/dev/null 2>&1; then
        echo ""
        echo "  IPv6 ($IP6TABLES, set $IPSET_V6_NAME):"
        for chain in INPUT FORWARD; do
            rc=0
            check_chain_placement "$IP6TABLES" "$chain" "$IPSET_V6_NAME" || rc=$?
            warnings=$((warnings + rc))
        done
    fi

    echo ""
    if [ "$warnings" -gt 0 ]; then
        echo "Placement: WARNING ($warnings issue(s))"
        return 1
    fi
    echo "Placement: OK"
    return 0
}

# Show current status
show_status() {
    init_state

    local stats
    stats=$(get_ipset_stats)
    local entries maxelem fill_ratio
    read -r entries maxelem fill_ratio <<< "$stats"

    local dropped_total
    dropped_total=$(read_counter "decisions_dropped_total")

    local capacity_events
    capacity_events=$(read_counter "capacity_events_total")

    local last_event
    last_event=$(read_counter "last_capacity_event")

    local last_event_str="never"
    if [ "$last_event" -gt 0 ]; then
        last_event_str=$(date -d "@$last_event" '+%F %T' 2>/dev/null || date -r "$last_event" '+%F %T' 2>/dev/null || echo "unknown")
    fi

    echo "=== ipset Capacity Status ==="
    echo ""
    echo "Current Usage:"
    echo "  Entries:     $entries / $maxelem"
    echo "  Fill Ratio:  ${fill_ratio}%"
    echo ""
    echo "Dropped Decisions (cumulative):"
    echo "  Total dropped:    $dropped_total"
    echo "  Capacity events:  $capacity_events"
    echo "  Last event:       $last_event_str"
    echo ""

    # Sidecar detection
    local sidecar_mode=""
    if [ -f "$BOUNCER_DIR/detect-sidecar.sh" ]; then
        source "$BOUNCER_DIR/detect-sidecar.sh"
        sidecar_mode="$SIDECAR_MODE"
    fi

    echo "Upstream Configuration:"
    if [ "$sidecar_mode" = "sidecar" ]; then
        echo "  Mode:        sidecar proxy (port ${SIDECAR_PORT:-8084})"
        echo "  api_url:     ${BOUNCER_UPSTREAM:-unknown}"
        echo "  Status:      Decisions are filtered and prioritized before reaching this device"
    elif [ "$sidecar_mode" = "lapi" ]; then
        echo "  Mode:        direct LAPI connection"
        echo "  api_url:     ${BOUNCER_UPSTREAM:-unknown}"
        echo "  Note:        LAPI sends ALL decisions — if more than maxelem, excess are silently dropped"
    else
        echo "  Mode:        unknown (could not parse bouncer config)"
    fi
    echo ""

    # Status assessment
    local fill_int
    fill_int=$(awk "BEGIN {printf \"%.0f\", $fill_ratio}")

    if [ "$fill_int" -ge 95 ]; then
        echo "Status: CRITICAL - Decisions are being dropped!"
        if [ "$sidecar_mode" = "sidecar" ]; then
            echo "Action: Reduce max_decisions in sidecar config (currently set too high for this device)"
            echo "  Recommended: $((maxelem - 2000)) or less"
        else
            echo "Action: Deploy the sidecar proxy to filter and prioritize decisions"
            echo "  See: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer#sidecar-proxy"
            echo "  Recommended sidecar max_decisions: $((maxelem - 2000))"
        fi
    elif [ "$fill_int" -ge 90 ]; then
        echo "Status: WARNING - Approaching capacity limit"
        if [ "$sidecar_mode" = "sidecar" ]; then
            echo "Action: Consider reducing sidecar max_decisions"
        else
            echo "Action: Monitor closely, consider deploying the sidecar proxy"
        fi
    elif [ "$fill_int" -ge 80 ]; then
        echo "Status: ELEVATED - Getting full"
        if [ "$sidecar_mode" != "sidecar" ]; then
            echo "Action: Consider deploying the sidecar proxy for decision prioritization"
        fi
    else
        echo "Status: OK"
    fi

    # Show recent capacity log entries if any
    if [ -f "$CAPACITY_LOG" ]; then
        local recent
        recent=$(grep -v "^#" "$CAPACITY_LOG" 2>/dev/null | tail -5)
        if [ -n "$recent" ]; then
            echo ""
            echo "Recent capacity events:"
            echo "$recent" | sed 's/^/  /'
        fi
    fi

    echo ""
    check_rule_placement || true
}

# Continuous watch mode (for systemd service)
watch_mode() {
    echo "Starting ipset capacity monitor (watching bouncer log)..."
    init_log

    # Initial check
    check_capacity || true

    # Watch loop - check every 30 seconds
    while true; do
        sleep 30
        check_for_capacity_errors || true
    done
}

# Rotate capacity log if too large
rotate_log() {
    if [ -f "$CAPACITY_LOG" ] && [ "$(wc -l < "$CAPACITY_LOG" 2>/dev/null || echo 0)" -gt 1000 ]; then
        tail -500 "$CAPACITY_LOG" > "${CAPACITY_LOG}.tmp"
        mv "${CAPACITY_LOG}.tmp" "$CAPACITY_LOG"
    fi
}

# Record a capacity event (called by other scripts)
record_capacity_event() {
    local count="${1:-1}"
    init_state
    increment_counter "decisions_dropped_total" "$count" >/dev/null
    increment_counter "capacity_events_total" >/dev/null
    update_counter "last_capacity_event" "$(date +%s)"
}

# Main
case "${1:-}" in
    --watch)
        watch_mode
        ;;
    --status)
        show_status
        ;;
    --check)
        check_capacity
        ;;
    --placement)
        check_rule_placement
        ;;
    --record-dropped)
        shift
        record_capacity_event "${1:-1}"
        ;;
    --help|-h)
        cat << HELPEOF
CrowdSec UniFi Bouncer - ipset Capacity Monitor

Monitors for "set is full" errors when ipset reaches maxelem capacity.
Tracks dropped decisions and provides metrics for observability.

Usage:
  $0              One-shot capacity check (for cron)
  $0 --watch      Continuous monitoring (for systemd)
  $0 --status     Show current capacity status, stats, and rule placement
  $0 --placement  Check that the crowdsec DROP rules sit above UniFi's
                  firewall/zone chains (read-only; exit 1 on warning)
  $0 --check      Check capacity and log warnings
  $0 --record-dropped [N]  Record N dropped decisions (for external scripts)

Environment variables:
  BOUNCER_DIR     Installation directory (default: /data/crowdsec-bouncer)
  IPSET_NAME      ipset name (default: crowdsec-blacklists)
  CAPACITY_LOG    Capacity event log (default: \$BOUNCER_DIR/log/capacity.log)
  STATE_FILE      Metrics state file (default: \$BOUNCER_DIR/metrics-state)

Exit codes:
  0  OK (or errors found and logged)
  1  Warning (90%+ capacity or errors detected)
  2  Critical (95%+ capacity)

Metrics updated in state file:
  decisions_dropped_total    Total IPs that couldn't be added due to capacity
  capacity_events_total      Number of capacity error events
  last_capacity_event        Unix timestamp of last capacity error

For cron (check every 5 minutes):
  */5 * * * * /data/crowdsec-bouncer/ipset-capacity-monitor.sh --check

For systemd (continuous monitoring):
  See crowdsec-unifi-capacity-monitor.service
HELPEOF
        ;;
    *)
        rotate_log
        check_capacity
        ;;
esac
