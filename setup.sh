#!/bin/bash
# CrowdSec Firewall Bouncer - Setup/Recovery Script
# Ensures ipset, iptables rules, and systemd service persist across firmware updates
# Run as ExecStartPre in systemd service

set -e

BOUNCER_DIR="/data/crowdsec-bouncer"
IPSET_NAME="crowdsec-blacklists"
IPSET_V6_NAME="${IPSET_V6_NAME:-crowdsec6-blacklists}"

# ensure_drop_at_top <iptables|ip6tables> <chain> <ipset>
# The DROP rules must sit at position 1, ahead of UniFi's jumps (TOR, ALIEN,
# IPS, UBIOS_*). If the rule exists lower down (UniFi reprovisioning inserted
# jumps above it), delete and re-insert at position 1. See docs/zone-placement.md.
ensure_drop_at_top() {
    local cmd="$1" chain="$2" set_name="$3" first
    if "$cmd" -C "$chain" -m set --match-set "$set_name" src -j DROP 2>/dev/null; then
        first=$("$cmd" -S "$chain" 2>/dev/null | grep -m1 -- "^-A $chain ")
        case "$first" in
            "-A $chain -m set --match-set $set_name src -j DROP"*)
                return 0
                ;;
        esac
        "$cmd" -D "$chain" -m set --match-set "$set_name" src -j DROP 2>/dev/null || return 1
        "$cmd" -I "$chain" 1 -m set --match-set "$set_name" src -j DROP || return 1
        echo "Moved $chain DROP rule back to position 1"
        return 0
    fi
    "$cmd" -I "$chain" 1 -m set --match-set "$set_name" src -j DROP || return 1
    echo "Added $chain DROP rule at position 1"
    return 0
}

# Source device detection for safe maxelem defaults
SCRIPT_DIR="$(dirname "$0")"
if [ -f "$SCRIPT_DIR/detect-device.sh" ]; then
    source "$SCRIPT_DIR/detect-device.sh"
elif [ -f "$BOUNCER_DIR/detect-device.sh" ]; then
    source "$BOUNCER_DIR/detect-device.sh"
fi

# Check for unsupported device
if [ "${UNSUPPORTED_DEVICE:-false}" = "true" ]; then
    echo "[ERROR] Detected device model: ${DETECTED_NORMALIZED:-Unknown}"
    echo "[ERROR] This device does not support firewall groups/ipsets"
    echo "[ERROR] crowdsec-unifi-bouncer cannot run on this device"
    exit 1
fi

# Print startup detection info
if type print_startup_info >/dev/null 2>&1; then
    print_startup_info "$DETECTED_MODEL"
fi

# Maxelem selection: FINAL_MAXELEM from detect-device.sh handles override logic
# Fallback chain: MAXELEM env -> FINAL_MAXELEM -> SAFE_MAXELEM -> 10000
if [ -n "${MAXELEM:-}" ]; then
    # Legacy MAXELEM env var support (deprecated in favor of MAXELEM_OVERRIDE)
    echo "[INFO] Using legacy MAXELEM=$MAXELEM (consider switching to MAXELEM_OVERRIDE)"
elif [ -n "${FINAL_MAXELEM:-}" ] && [ "$FINAL_MAXELEM" -gt 0 ] 2>/dev/null; then
    MAXELEM="$FINAL_MAXELEM"
else
    MAXELEM="${SAFE_MAXELEM:-10000}"
fi

echo "Device: ${DETECTED_NORMALIZED:-Unknown}"
echo "Maxelem: $MAXELEM"

# Detect sidecar configuration
if [ -f "$SCRIPT_DIR/detect-sidecar.sh" ]; then
    source "$SCRIPT_DIR/detect-sidecar.sh"
elif [ -f "$BOUNCER_DIR/detect-sidecar.sh" ]; then
    source "$BOUNCER_DIR/detect-sidecar.sh"
fi

if [ -n "$SIDECAR_MODE" ]; then
    echo "Upstream: $SIDECAR_MODE"
    if [ "$SIDECAR_MODE" = "lapi" ]; then
        echo "WARNING: Bouncer connects directly to LAPI. If your LAPI has more decisions"
        echo "  than maxelem ($MAXELEM), excess decisions will be silently dropped."
        echo "  Consider deploying the sidecar proxy — see README.md."
    fi
fi

# Ensure ipset kernel modules are loaded
modprobe ip_set 2>/dev/null || true
modprobe ip_set_hash_net 2>/dev/null || true

# Ensure log directory exists
mkdir -p "$BOUNCER_DIR/log"

# Create ipset if it doesn't exist (with timeout support for ban durations)
if ! ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    ipset create "$IPSET_NAME" hash:net maxelem "$MAXELEM" timeout 2147483
    echo "Created ipset: $IPSET_NAME (maxelem=$MAXELEM)"
fi

# Add iptables rules at position 1 (or move them back if displaced)
ensure_drop_at_top iptables INPUT "$IPSET_NAME"
ensure_drop_at_top iptables FORWARD "$IPSET_NAME"

# --- IPv6 -------------------------------------------------------------------
# Enabled when the bouncer config has `disable_ipv6: false` (the default in the
# v2.6+ config template). The v6 set is independent: its own name
# (blacklists_ipv6 in the bouncer config), its own maxelem, its own capacity.
# MAXELEM_V6_OVERRIDE sets a different v6 ceiling; without it the v6 set uses
# the same limit as the v4 set for this device.
CONFIG_FILE="$BOUNCER_DIR/crowdsec-firewall-bouncer.yaml"
IPV6_ENABLED=false
if [ -f "$CONFIG_FILE" ] && grep -Eq '^[[:space:]]*disable_ipv6:[[:space:]]*false' "$CONFIG_FILE"; then
    IPV6_ENABLED=true
fi

if [ "$IPV6_ENABLED" = "true" ]; then
    if ! command -v ip6tables >/dev/null 2>&1; then
        echo "[WARN] disable_ipv6 is false but ip6tables was not found - skipping IPv6 setup"
    else
        MAXELEM_V6="${MAXELEM_V6_OVERRIDE:-$MAXELEM}"
        if ! ipset list "$IPSET_V6_NAME" >/dev/null 2>&1; then
            ipset create "$IPSET_V6_NAME" hash:net family inet6 maxelem "$MAXELEM_V6" timeout 2147483
            echo "Created ipset: $IPSET_V6_NAME (family inet6, maxelem=$MAXELEM_V6)"
        fi
        ensure_drop_at_top ip6tables INPUT "$IPSET_V6_NAME"
        ensure_drop_at_top ip6tables FORWARD "$IPSET_V6_NAME"
    fi
fi

# Ensure systemd service is properly linked (recovery after firmware update)
if [ ! -L /etc/systemd/system/crowdsec-firewall-bouncer.service ]; then
    ln -sf "$BOUNCER_DIR/crowdsec-firewall-bouncer.service" /etc/systemd/system/crowdsec-firewall-bouncer.service
    systemctl daemon-reload
fi

# Deploy iptables LOG rules for CrowdSec detection visibility
if [ -x "$BOUNCER_DIR/log-rules.sh" ]; then
    echo "Deploying iptables LOG rules..."
    "$BOUNCER_DIR/log-rules.sh" || echo "[WARN] LOG rule deployment failed (non-fatal)"
fi

echo "CrowdSec bouncer ready"
