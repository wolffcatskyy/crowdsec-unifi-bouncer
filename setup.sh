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

# Use MAXELEM from environment, or fall back to detected safe limit
if [ -z "$MAXELEM" ]; then
    MAXELEM="${SAFE_MAXELEM:-30000}"
    echo "Auto-detected device: ${DETECTED_MODEL:-Unknown}"
    echo "Using safe maxelem: $MAXELEM"
else
    # Validate user-configured MAXELEM against safe limit
    if [ -n "$SAFE_MAXELEM" ] && [ "$MAXELEM" -gt "$SAFE_MAXELEM" ]; then
        echo "WARNING: Configured MAXELEM ($MAXELEM) exceeds safe limit ($SAFE_MAXELEM) for ${DETECTED_MODEL:-this device}"
        echo "This may cause memory issues. Consider reducing to $SAFE_MAXELEM or lower."
    fi
    echo "Using configured maxelem: $MAXELEM"
fi

# Ensure ipset kernel modules are loaded
modprobe ip_set 2>/dev/null || true
modprobe ip_set_hash_net 2>/dev/null || true

# Ensure log directory exists
mkdir -p "$BOUNCER_DIR/log"

# Create ipset if it doesn't exist
if ! ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    ipset create "$IPSET_NAME" hash:net maxelem "$MAXELEM" timeout 0
    echo "Created $IPSET_NAME ipset with maxelem=$MAXELEM"
fi

# Add iptables rules if not present
if ! iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    iptables -I INPUT 1 -m set --match-set "$IPSET_NAME" src -j DROP
    echo 'Added INPUT DROP rule'
fi

if ! iptables -C FORWARD -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    iptables -I FORWARD 1 -m set --match-set "$IPSET_NAME" src -j DROP
    echo 'Added FORWARD DROP rule'
fi

# Ensure systemd service is properly linked (recovery after firmware update)
if [ ! -L /etc/systemd/system/crowdsec-firewall-bouncer.service ]; then
    ln -sf "$BOUNCER_DIR/crowdsec-firewall-bouncer.service" /etc/systemd/system/crowdsec-firewall-bouncer.service
    systemctl daemon-reload
fi

echo 'CrowdSec bouncer setup complete'
