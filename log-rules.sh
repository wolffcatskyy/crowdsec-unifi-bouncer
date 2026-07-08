#!/bin/bash
# CrowdSec Firewall Bouncer - iptables LOG Rule Deployment
# Inserts LOG rules before DROP rules in UniFi WAN chains for CrowdSec visibility
#
# Without LOG rules, the bouncer blocks traffic but CrowdSec cannot detect
# port scans or other malicious patterns in dropped packets. This script
# makes dropped packets visible via syslog, enabling:
#   - CrowdSec detection scenarios (port scans, brute force on dropped IPs)
#   - AbuseIPDB reporting of detected attacks
#   - CAPI contribution (sharing detections with the CrowdSec community)
#
# Usage:
#   ./log-rules.sh              # Deploy LOG rules (idempotent)
#   ./log-rules.sh --remove     # Remove all LOG rules
#   ./log-rules.sh --status     # Show current LOG rule count per chain
#   ./log-rules.sh --quiet      # Deploy with minimal output
#
# Called automatically by ensure-rules.sh every 5 minutes.
# Safe to run manually at any time.

BOUNCER_DIR="${BOUNCER_DIR:-/data/crowdsec-bouncer}"
COMMENT_MARKER="CROWDSEC_LOG"
RATE_LIMIT="10/min"
RATE_BURST="20"
LOG_LEVEL="4"

# Chains to process — all WAN-facing USER chains on UniFi OS
CHAINS=(
    "UBIOS_WAN_LOCAL_USER"
    "UBIOS_WAN_LAN_USER"
    "UBIOS_WAN_IN_USER"
    "UBIOS_WAN_DMZ_USER"
    "UBIOS_WAN_GUEST_USER"
    "UBIOS_WAN_VPN_USER"
    "UBIOS_WAN_WAN_USER"
)

# Parse arguments
QUIET=false
REMOVE_ONLY=false
STATUS_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --quiet|-q)  QUIET=true ;;
        --remove)    REMOVE_ONLY=true ;;
        --status)    STATUS_ONLY=true ;;
        --help|-h)
            echo "Usage: $0 [--quiet|--remove|--status|--help]"
            echo ""
            echo "  --quiet   Minimal output (for cron/ensure-rules.sh)"
            echo "  --remove  Remove all CROWDSEC_LOG rules and exit"
            echo "  --status  Show current LOG rule count per chain"
            echo "  --help    Show this help"
            exit 0
            ;;
    esac
done

# Logging helpers
log_info() {
    if [ "$QUIET" = false ]; then
        echo "[INFO] $1" >&2
    fi
}

log_warn() {
    echo "[WARN] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

# Convert chain name to short form for log prefix
# UBIOS_WAN_LOCAL_USER -> WAN_LOCAL
chain_to_short() {
    local chain="$1"
    local short="$chain"
    short="${short#UBIOS_}"
    short="${short%_USER}"
    echo "$short"
}

# Check if a chain exists in iptables
chain_exists() {
    iptables -L "$1" -n >/dev/null 2>&1
}

# Remove all existing CROWDSEC_LOG rules from all chains
cleanup_rules() {
    local total_removed=0

    for chain in "${CHAINS[@]}"; do
        if ! chain_exists "$chain"; then
            continue
        fi

        # Loop: find and remove the first CROWDSEC_LOG rule, repeat until none left.
        # We always remove the lowest-numbered match because indices shift after deletion.
        while true; do
            local rule_num
            rule_num=$(iptables -L "$chain" --line-numbers -n 2>/dev/null \
                | grep "$COMMENT_MARKER" \
                | head -1 \
                | awk '{print $1}')

            if [ -z "$rule_num" ]; then
                break
            fi

            iptables -D "$chain" "$rule_num" 2>/dev/null
            total_removed=$((total_removed + 1))
        done
    done

    echo "$total_removed"
}

# Show status of LOG rules in each chain
show_status() {
    local total=0
    printf "%-25s %s\n" "Chain" "LOG Rules"
    printf "%-25s %s\n" "-------------------------" "---------"

    for chain in "${CHAINS[@]}"; do
        if ! chain_exists "$chain"; then
            printf "%-25s %s\n" "$chain" "(not present)"
            continue
        fi

        local count
        count=$(iptables -S "$chain" 2>/dev/null | grep -c "$COMMENT_MARKER" || true)
        printf "%-25s %d\n" "$chain" "$count"
        total=$((total + count))
    done

    echo ""
    echo "Total LOG rules: $total"
}

# Deploy LOG rules before every DROP rule in a chain
deploy_chain() {
    local chain="$1"
    local short
    short=$(chain_to_short "$chain")
    local deployed=0

    if ! chain_exists "$chain"; then
        log_info "Chain $chain does not exist, skipping"
        return 0
    fi

    # Parse DROP rules using iptables -S (machine-parseable output)
    # Collect rule indices and metadata
    local drop_indices=()
    local drop_invalid=()
    local drop_matches=()
    local rule_index=0

    while IFS= read -r line; do
        # Only count -A lines (actual rules in the chain)
        case "$line" in
            -A\ *) ;;
            *) continue ;;
        esac

        rule_index=$((rule_index + 1))

        # Skip non-DROP rules
        case "$line" in
            *"-j DROP"*) ;;
            *) continue ;;
        esac

        # Check if this is an INVALID state rule
        local is_invalid=false
        case "$line" in
            *"--ctstate"*"INVALID"*) is_invalid=true ;;
        esac

        # Extract match portion: strip "-A CHAINNAME" and "-j DROP..."
        local match_portion="$line"
        # Remove -A CHAINNAME from front
        match_portion="${match_portion#-A $chain }"
        match_portion="${match_portion#-A $chain}"
        # Remove -j DROP and everything after from end
        match_portion="${match_portion%%-j DROP*}"
        # Trim whitespace
        match_portion="$(echo "$match_portion" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

        drop_indices+=("$rule_index")
        drop_invalid+=("$is_invalid")
        drop_matches+=("$match_portion")
    done < <(iptables -S "$chain" 2>/dev/null)

    if [ ${#drop_indices[@]} -eq 0 ]; then
        log_info "  No DROP rules in $chain"
        return 0
    fi

    log_info "  Found ${#drop_indices[@]} DROP rule(s) in $chain"

    # Insert from bottom to top to preserve rule indices
    local i
    for ((i = ${#drop_indices[@]} - 1; i >= 0; i--)); do
        local idx="${drop_indices[$i]}"
        local invalid="${drop_invalid[$i]}"
        local match="${drop_matches[$i]}"

        local suffix="ALL"
        if [ "$invalid" = true ]; then
            suffix="INVALID"
        fi

        local prefix="[UNIFI-${short}-D-${suffix}]"

        # Build iptables insert command
        local cmd="iptables -I $chain $idx"
        if [ -n "$match" ]; then
            cmd="$cmd $match"
        fi
        cmd="$cmd -m limit --limit $RATE_LIMIT --limit-burst $RATE_BURST"
        cmd="$cmd -m comment --comment $COMMENT_MARKER"
        cmd="$cmd -j LOG --log-prefix \"$prefix \" --log-level $LOG_LEVEL"

        if eval "$cmd" 2>/dev/null; then
            deployed=$((deployed + 1))
        else
            log_error "Failed to insert LOG rule at position $idx in $chain"
        fi
    done

    log_info "  Deployed $deployed LOG rule(s) in $chain"
    echo "$deployed"
}

# Verify LOG rules are present
verify_rules() {
    local total=0

    for chain in "${CHAINS[@]}"; do
        if ! chain_exists "$chain"; then
            continue
        fi

        local count
        count=$(iptables -S "$chain" 2>/dev/null | grep -c "$COMMENT_MARKER" || true)
        if [ "$count" -gt 0 ]; then
            log_info "  Verified: $count LOG rule(s) in $(chain_to_short "$chain")"
        fi
        total=$((total + count))
    done

    echo "$total"
}

# --- Main ---

# Status mode
if [ "$STATUS_ONLY" = true ]; then
    show_status
    exit 0
fi

# Remove mode
if [ "$REMOVE_ONLY" = true ]; then
    log_info "Removing all $COMMENT_MARKER rules..."
    removed=$(cleanup_rules)
    echo "Removed $removed LOG rule(s)"
    exit 0
fi

# Deploy mode (default)
log_info "=== CrowdSec LOG Rule Deployment ==="

# Phase 1: Cleanup existing rules (idempotent)
log_info "Phase 1: Cleanup existing $COMMENT_MARKER rules"
removed=$(cleanup_rules)
if [ "$removed" -gt 0 ]; then
    log_info "Removed $removed existing LOG rule(s)"
else
    log_info "No existing LOG rules to remove"
fi

# Phase 2: Deploy LOG rules before every DROP rule
log_info "Phase 2: Deploy LOG rules"
total_deployed=0

for chain in "${CHAINS[@]}"; do
    result=$(deploy_chain "$chain")
    if [ -n "$result" ]; then
        total_deployed=$((total_deployed + result))
    fi
done

# Phase 3: Verify
log_info "Phase 3: Verification"
verified=$(verify_rules)

# Summary
if [ "$QUIET" = false ]; then
    echo ""
    echo "=== Summary ==="
    echo "Removed:  $removed"
    echo "Deployed: $total_deployed"
    echo "Verified: $verified"
fi

if [ "$total_deployed" -ne "$verified" ]; then
    log_error "MISMATCH: deployed $total_deployed but verified $verified"
    exit 1
fi

if [ "$total_deployed" -eq 0 ]; then
    log_info "No DROP rules found in any chain (normal if bouncer hasn't started yet)"
else
    log_info "Deployed $total_deployed LOG rule(s)"
    logger -t crowdsec-bouncer "Deployed $total_deployed iptables LOG rules for CrowdSec visibility"
fi

exit 0
