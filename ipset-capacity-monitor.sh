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
#
# Environment variables:
#   BOUNCER_DIR       - Installation directory (default: /data/crowdsec-bouncer)
#   IPSET_NAME        - Name of the ipset (default: crowdsec-blacklists)
#   CAPACITY_LOG      - Log file for capacity events (default: $BOUNCER_DIR/log/capacity.log)
#   STATE_FILE        - Metrics state file (default: $BOUNCER_DIR/metrics-state)

set -euo pipefail

# Configuration
BOUNCER_DIR="${BOUNCER_DIR:-/data/crowdsec-bouncer}"
IPSET_NAME="${IPSET_NAME:-crowdsec-blacklists}"
CAPACITY_LOG="${CAPACITY_LOG:-$BOUNCER_DIR/log/capacity.log}"
STATE_FILE="${STATE_FILE:-$BOUNCER_DIR/metrics-state}"
BOUNCER_LOG="$BOUNCER_DIR/log/crowdsec-firewall-bouncer.log"
METRICS_SCRIPT="$BOUNCER_DIR/metrics.sh"

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
        maxelem=$(ipset list "$IPSET_NAME" -t 2>/dev/null | awk '/^Maxelem:/{print $NF}')
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

    # Status assessment
    local fill_int
    fill_int=$(awk "BEGIN {printf \"%.0f\", $fill_ratio}")

    if [ "$fill_int" -ge 95 ]; then
        echo "Status: CRITICAL - Decisions are being dropped!"
        echo "Action: Reduce ipset_size in config or increase MAXELEM"
    elif [ "$fill_int" -ge 90 ]; then
        echo "Status: WARNING - Approaching capacity limit"
        echo "Action: Monitor closely, consider reducing blocklist size"
    elif [ "$fill_int" -ge 80 ]; then
        echo "Status: ELEVATED - Getting full"
        echo "Action: Plan for capacity increase or blocklist reduction"
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
  $0 --status     Show current capacity status and stats
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
