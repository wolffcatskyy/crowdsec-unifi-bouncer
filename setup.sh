#!/bin/bash
# CrowdSec Firewall Bouncer - Setup/Recovery Script
# Ensures ipset, iptables rules, and systemd service persist across firmware updates
# Run as ExecStartPre in systemd service

set -e

BOUNCER_DIR="/data/crowdsec-bouncer"
IPSET_NAME="crowdsec-blacklists"

# Source device detection for conservative maxelem defaults
SCRIPT_DIR="$(dirname "$0")"
if [ -f "$SCRIPT_DIR/detect-device.sh" ]; then
    source "$SCRIPT_DIR/detect-device.sh"
elif [ -f "$BOUNCER_DIR/detect-device.sh" ]; then
    source "$BOUNCER_DIR/detect-device.sh"
fi

# =============================================================================
# WARNING: ipset LIMITS ARE UNTESTED ESTIMATES
# =============================================================================
echo ""
echo "=========================================================================="
echo "WARNING: ipset LIMITS ARE UNTESTED ESTIMATES"
echo "=========================================================================="
echo "The default maxelem values in this bouncer are CONSERVATIVE GUESSES"
echo "based on device RAM specs, NOT verified through stability testing."
echo ""
echo "Monitor your device's memory while running:"
echo "  cat /proc/meminfo | grep MemAvailable"
echo ""
echo "If you find a stable limit for your device, please report it:"
echo "  https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/issues"
echo "=========================================================================="
echo ""

# Maxelem selection priority:
# 1. MAXELEM environment variable (explicit override)
# 2. AUTO_MAXELEM=true -> calculate from available RAM
# 3. Fall back to conservative default (SAFE_MAXELEM)
if [ -n "$MAXELEM" ]; then
    # Explicit override takes precedence
    if [ -n "$SAFE_MAXELEM" ] && [ "$MAXELEM" -gt "$SAFE_MAXELEM" ]; then
        echo "NOTE: Configured MAXELEM ($MAXELEM) exceeds conservative default ($SAFE_MAXELEM)"
        echo "This may be fine - monitor memory: cat /proc/meminfo | grep MemAvailable"
    fi
    echo "Using configured maxelem: $MAXELEM"
elif [ "${AUTO_MAXELEM:-false}" = "true" ]; then
    # Auto-calculate from available RAM
    MAXELEM="${AUTO_CALCULATED_MAXELEM:-20000}"
    echo "Auto-detected device: ${DETECTED_MODEL:-Unknown}"
    echo "AUTO_MAXELEM=true: Calculated maxelem from available RAM: $MAXELEM"
    echo "(Conservative: 10% of available memory budget, max 200,000)"
else
    # Conservative default
    MAXELEM="${SAFE_MAXELEM:-20000}"
    echo "Auto-detected device: ${DETECTED_MODEL:-Unknown}"
    echo "Using conservative default maxelem: $MAXELEM (UNTESTED - monitor memory!)"
    echo "Tip: Set AUTO_MAXELEM=true to auto-detect from available RAM."
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
echo ""
echo "REMINDER: Monitor memory with: cat /proc/meminfo | grep MemAvailable"
echo "If MemAvailable drops below 300MB, reduce maxelem and restart."
