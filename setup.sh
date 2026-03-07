#!/bin/bash
# CrowdSec Firewall Bouncer - Setup/Recovery Script
# Ensures ipset, iptables rules, and systemd service persist across firmware updates
# Run as ExecStartPre in systemd service

set -e

BOUNCER_DIR="/data/crowdsec-bouncer"
IPSET_NAME="crowdsec-blacklists"

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

# Add iptables rules if not present
if ! iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    iptables -I INPUT 1 -m set --match-set "$IPSET_NAME" src -j DROP
    echo "Added INPUT DROP rule"
fi

if ! iptables -C FORWARD -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    iptables -I FORWARD 1 -m set --match-set "$IPSET_NAME" src -j DROP
    echo "Added FORWARD DROP rule"
fi

# Ensure systemd service is properly linked (recovery after firmware update)
if [ ! -L /etc/systemd/system/crowdsec-firewall-bouncer.service ]; then
    ln -sf "$BOUNCER_DIR/crowdsec-firewall-bouncer.service" /etc/systemd/system/crowdsec-firewall-bouncer.service
    systemctl daemon-reload
fi

echo "CrowdSec bouncer ready"
