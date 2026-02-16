#!/bin/bash
# CrowdSec UniFi Bouncer - Prometheus Metrics Collector
# Outputs metrics in Prometheus text format
#
# Usage:
#   ./metrics.sh              # Output metrics to stdout
#   ./metrics.sh --serve      # Start HTTP server on METRICS_PORT (default 9101)
#
# Environment variables:
#   METRICS_PORT      - HTTP server port (default: 9101)
#   BOUNCER_DIR       - Bouncer installation directory (default: /data/crowdsec-bouncer)
#   IPSET_NAME        - Name of the ipset (default: crowdsec-blacklists)
#   STATE_FILE        - Persistent state file for counters (default: $BOUNCER_DIR/metrics-state)

set -euo pipefail

# Configuration
METRICS_PORT="${METRICS_PORT:-9101}"
BOUNCER_DIR="${BOUNCER_DIR:-/data/crowdsec-bouncer}"
IPSET_NAME="${IPSET_NAME:-crowdsec-blacklists}"
STATE_FILE="${STATE_FILE:-$BOUNCER_DIR/metrics-state}"
MEMORY_LOG="$BOUNCER_DIR/log/memory.log"

# Initialize state file if it doesn't exist
init_state() {
    if [ ! -f "$STATE_FILE" ]; then
        cat > "$STATE_FILE" << 'STATEOF'
errors_total=0
guardrail_triggered_total=0
rules_restored_total=0
STATEOF
    fi
}

# Read counter from state file
read_counter() {
    local name="$1"
    grep "^${name}=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "0"
}

# Increment counter in state file
increment_counter() {
    local name="$1"
    local current
    current=$(read_counter "$name")
    local new=$((current + 1))
    if grep -q "^${name}=" "$STATE_FILE" 2>/dev/null; then
        sed -i "s/^${name}=.*/${name}=${new}/" "$STATE_FILE"
    else
        echo "${name}=${new}" >> "$STATE_FILE"
    fi
    echo "$new"
}

# Collect and output metrics in Prometheus format
collect_metrics() {
    local timestamp
    timestamp=$(date +%s)

    # --- Bouncer Status ---
    local bouncer_up=0
    if systemctl is-active --quiet crowdsec-firewall-bouncer 2>/dev/null; then
        bouncer_up=1
    fi

    # --- ipset Metrics ---
    local ipset_entries=0
    local ipset_maxelem=0

    if ipset list "$IPSET_NAME" -t 2>/dev/null | grep -q "^Name:"; then
        ipset_entries=$(ipset list "$IPSET_NAME" -t 2>/dev/null | awk '/^Number of entries:/{print $NF}')
        ipset_maxelem=$(ipset list "$IPSET_NAME" -t 2>/dev/null | awk '/^Maxelem:/{print $NF}')
    fi
    ipset_entries="${ipset_entries:-0}"
    ipset_maxelem="${ipset_maxelem:-0}"

    # --- Memory Metrics ---
    local mem_available_kb=0
    mem_available_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null || echo "0")

    local mem_total_kb=0
    mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo "0")

    # --- iptables Rules ---
    local input_rule_present=0
    local forward_rule_present=0

    if iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
        input_rule_present=1
    fi
    if iptables -C FORWARD -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
        forward_rule_present=1
    fi

    # --- Last Sync from memory.log ---
    local last_sync_timestamp=0

    if [ -f "$MEMORY_LOG" ]; then
        local last_line
        last_line=$(tail -1 "$MEMORY_LOG" 2>/dev/null || echo "")
        if [ -n "$last_line" ]; then
            # Parse timestamp from format: "2026-02-04 05:00 entries=..."
            local date_str
            date_str=$(echo "$last_line" | awk '{print $1" "$2}')
            if [ -n "$date_str" ]; then
                last_sync_timestamp=$(date -d "$date_str" +%s 2>/dev/null || echo "0")
            fi
        fi
    fi

    # --- Counters from state file ---
    init_state
    local errors_total
    local guardrail_triggered_total
    local rules_restored_total
    errors_total=$(read_counter "errors_total")
    guardrail_triggered_total=$(read_counter "guardrail_triggered_total")
    rules_restored_total=$(read_counter "rules_restored_total")

    # --- Output Prometheus Format ---
    cat << METRICSEOF
# HELP crowdsec_unifi_bouncer_up Whether the CrowdSec bouncer service is running (1=up, 0=down)
# TYPE crowdsec_unifi_bouncer_up gauge
crowdsec_unifi_bouncer_up $bouncer_up

# HELP crowdsec_unifi_bouncer_blocked_ips_total Current number of IPs in the crowdsec ipset
# TYPE crowdsec_unifi_bouncer_blocked_ips_total gauge
crowdsec_unifi_bouncer_blocked_ips_total $ipset_entries

# HELP crowdsec_unifi_bouncer_ipset_size Configured maximum size of the ipset (maxelem)
# TYPE crowdsec_unifi_bouncer_ipset_size gauge
crowdsec_unifi_bouncer_ipset_size $ipset_maxelem

# HELP crowdsec_unifi_bouncer_ipset_fill_ratio Ratio of current entries to max capacity (0.0-1.0)
# TYPE crowdsec_unifi_bouncer_ipset_fill_ratio gauge
crowdsec_unifi_bouncer_ipset_fill_ratio $(awk "BEGIN {if ($ipset_maxelem > 0) printf \"%.4f\", $ipset_entries/$ipset_maxelem; else print 0}")

# HELP crowdsec_unifi_bouncer_memory_available_kb Available system memory in kilobytes
# TYPE crowdsec_unifi_bouncer_memory_available_kb gauge
crowdsec_unifi_bouncer_memory_available_kb $mem_available_kb

# HELP crowdsec_unifi_bouncer_memory_total_kb Total system memory in kilobytes
# TYPE crowdsec_unifi_bouncer_memory_total_kb gauge
crowdsec_unifi_bouncer_memory_total_kb $mem_total_kb

# HELP crowdsec_unifi_bouncer_last_sync_timestamp Unix timestamp of the last ensure-rules.sh execution
# TYPE crowdsec_unifi_bouncer_last_sync_timestamp gauge
crowdsec_unifi_bouncer_last_sync_timestamp $last_sync_timestamp

# HELP crowdsec_unifi_bouncer_input_rule_present Whether the INPUT chain DROP rule is present (1=yes, 0=no)
# TYPE crowdsec_unifi_bouncer_input_rule_present gauge
crowdsec_unifi_bouncer_input_rule_present $input_rule_present

# HELP crowdsec_unifi_bouncer_forward_rule_present Whether the FORWARD chain DROP rule is present (1=yes, 0=no)
# TYPE crowdsec_unifi_bouncer_forward_rule_present gauge
crowdsec_unifi_bouncer_forward_rule_present $forward_rule_present

# HELP crowdsec_unifi_bouncer_errors_total Total number of errors encountered
# TYPE crowdsec_unifi_bouncer_errors_total counter
crowdsec_unifi_bouncer_errors_total $errors_total

# HELP crowdsec_unifi_bouncer_guardrail_triggered_total Number of times memory guardrail stopped the bouncer
# TYPE crowdsec_unifi_bouncer_guardrail_triggered_total counter
crowdsec_unifi_bouncer_guardrail_triggered_total $guardrail_triggered_total

# HELP crowdsec_unifi_bouncer_rules_restored_total Number of times iptables rules were re-added after removal
# TYPE crowdsec_unifi_bouncer_rules_restored_total counter
crowdsec_unifi_bouncer_rules_restored_total $rules_restored_total

# HELP crowdsec_unifi_bouncer_scrape_timestamp Unix timestamp when these metrics were collected
# TYPE crowdsec_unifi_bouncer_scrape_timestamp gauge
crowdsec_unifi_bouncer_scrape_timestamp $timestamp
METRICSEOF
}

# Simple HTTP server using netcat
serve_metrics() {
    echo "Starting CrowdSec UniFi Bouncer metrics server on port $METRICS_PORT..."

    # Check for netcat variants
    local nc_cmd=""
    if command -v nc >/dev/null 2>&1; then
        nc_cmd="nc"
    elif command -v netcat >/dev/null 2>&1; then
        nc_cmd="netcat"
    else
        echo "Error: netcat (nc) not found" >&2
        exit 1
    fi

    while true; do
        # Collect metrics
        local metrics
        metrics=$(collect_metrics)

        # Build HTTP response
        local response
        response=$(cat << HTTPEOF
HTTP/1.1 200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
Content-Length: ${#metrics}
Connection: close

$metrics
HTTPEOF
)

        # Serve single request (netcat behavior varies by version)
        echo -e "$response" | $nc_cmd -l -p "$METRICS_PORT" -q 1 2>/dev/null || \
        echo -e "$response" | $nc_cmd -l "$METRICS_PORT" 2>/dev/null || \
        echo -e "$response" | $nc_cmd -l -p "$METRICS_PORT" 2>/dev/null || true
    done
}

# Helper functions for ensure-rules.sh to call
record_error() {
    init_state
    increment_counter "errors_total" >/dev/null
}

record_guardrail() {
    init_state
    increment_counter "guardrail_triggered_total" >/dev/null
}

record_rule_restored() {
    init_state
    increment_counter "rules_restored_total" >/dev/null
}

# Main
case "${1:-}" in
    --serve)
        serve_metrics
        ;;
    --record-error)
        record_error
        ;;
    --record-guardrail)
        record_guardrail
        ;;
    --record-rule-restored)
        record_rule_restored
        ;;
    --help|-h)
        cat << HELPEOF
CrowdSec UniFi Bouncer - Prometheus Metrics

Usage:
  $0              Output metrics to stdout (for debugging)
  $0 --serve      Start HTTP server on port \$METRICS_PORT (default: 9101)

Recording helpers (for use by ensure-rules.sh):
  $0 --record-error          Increment errors_total counter
  $0 --record-guardrail      Increment guardrail_triggered_total counter
  $0 --record-rule-restored  Increment rules_restored_total counter

Environment variables:
  METRICS_PORT    HTTP server port (default: 9101)
  BOUNCER_DIR     Installation directory (default: /data/crowdsec-bouncer)
  IPSET_NAME      ipset name (default: crowdsec-blacklists)
  STATE_FILE      Counter state file (default: \$BOUNCER_DIR/metrics-state)

Example Prometheus scrape config:
  - job_name: 'crowdsec-unifi-bouncer'
    static_configs:
      - targets: ['<unifi-device-ip>:9101']
    scrape_interval: 60s
HELPEOF
        ;;
    *)
        collect_metrics
        ;;
esac
