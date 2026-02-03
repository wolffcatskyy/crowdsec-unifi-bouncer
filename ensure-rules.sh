#!/bin/bash
# Ensures CrowdSec iptables rules are in place
# Run via cron every 5 minutes to survive controller reprovisioning
#
# Add to crontab:
#   */5 * * * * /data/crowdsec-bouncer/ensure-rules.sh

IPSET_NAME="crowdsec-blacklists"

# Only act if bouncer is running
if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
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
fi

if ! iptables -C FORWARD -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    iptables -I FORWARD 1 -m set --match-set "$IPSET_NAME" src -j DROP
    logger -t crowdsec-bouncer "Re-added FORWARD DROP rule"
fi
