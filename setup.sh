#!/bin/bash
# CrowdSec Firewall Bouncer - Setup/Recovery Script
# Ensures ipset, iptables rules, and systemd service persist across firmware updates
# Run as ExecStartPre in systemd service

set -e

BOUNCER_DIR="/data/crowdsec-bouncer"
IPSET_NAME="crowdsec-blacklists"

# Ensure ipset kernel modules are loaded
modprobe ip_set 2>/dev/null || true
modprobe ip_set_hash_net 2>/dev/null || true

# Ensure log directory exists
mkdir -p "$BOUNCER_DIR/log"

# Create ipset if it doesn't exist
if ! ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    ipset create "$IPSET_NAME" hash:net maxelem 131072 timeout 0
    echo "Created $IPSET_NAME ipset"
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
