#!/bin/bash
# CrowdSec UniFi Bouncer - Uninstaller for UniFi OS devices
#
# Removes everything install.sh / bootstrap.sh put in place:
#   - systemd services (bouncer + metrics)
#   - cron jobs (ensure-rules, log-rules, capacity monitor)
#   - the on_boot.d firmware-update hook
#   - iptables DROP rules and CROWDSEC_LOG rules
#   - the crowdsec-blacklists ipset
#   - /data/crowdsec-bouncer (unless --keep-config)
#
# Usage:
#   /data/crowdsec-bouncer/uninstall.sh                Full removal
#   /data/crowdsec-bouncer/uninstall.sh --keep-config  Keep /data/crowdsec-bouncer
#                                                       (config, logs, scripts)
#   /data/crowdsec-bouncer/uninstall.sh --dry-run      Print actions, change nothing
#
# Note: your CrowdSec LAPI still lists this bouncer until you remove it there:
#   cscli bouncers delete <name>

set -e

BOUNCER_DIR="/data/crowdsec-bouncer"
SYSTEMD_DIR="/etc/systemd/system"
IPSET_NAME="crowdsec-blacklists"
LOG_COMMENT="CROWDSEC_LOG"
ON_BOOT_HOOK="/data/on_boot.d/99-crowdsec-bouncer.sh"
KEEP_CONFIG=0
DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --keep-config) KEEP_CONFIG=1 ;;
        --dry-run) DRY_RUN=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

# cron/systemd hand us a minimal PATH; ipset/iptables live in /usr/sbin
export PATH="$PATH:/usr/sbin"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1" >&2; }
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[dry-run] $*"
    else
        "$@"
    fi
}

echo ""
echo "=================================================="
echo "  CrowdSec UniFi Bouncer - Uninstaller"
echo "=================================================="
[ "$DRY_RUN" -eq 1 ] && warn "DRY RUN - no changes will be made"
[ "$KEEP_CONFIG" -eq 1 ] && log "Keeping $BOUNCER_DIR (config, logs, scripts)"
echo ""

if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    error "Must run as root"
    exit 1
fi

# 1. Stop and disable services
for svc in crowdsec-firewall-bouncer crowdsec-unifi-metrics; do
    if systemctl list-unit-files "$svc.service" >/dev/null 2>&1; then
        log "Stopping and disabling $svc..."
        run systemctl stop "$svc" 2>/dev/null || true
        run systemctl disable "$svc" 2>/dev/null || true
        run rm -f "$SYSTEMD_DIR/$svc.service"
    fi
done
run systemctl daemon-reload

# 2. Remove cron jobs (match the markers boot-restore.sh installs)
if crontab -l 2>/dev/null | grep -qE 'ensure-rules\.sh|log-rules\.sh|ipset-capacity-monitor'; then
    log "Removing cron jobs..."
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[dry-run] crontab -l | grep -vE 'ensure-rules.sh|log-rules.sh|ipset-capacity-monitor' | crontab -"
    else
        crontab -l 2>/dev/null | grep -vE 'ensure-rules\.sh|log-rules\.sh|ipset-capacity-monitor' | crontab - || true
    fi
fi

# 3. Remove the firmware-update hook
if [ -f "$ON_BOOT_HOOK" ]; then
    log "Removing on_boot.d hook..."
    run rm -f "$ON_BOOT_HOOK"
fi

# 4. Remove iptables rules that reference the ipset, then the LOG rules
log "Removing iptables rules..."
for chain in INPUT FORWARD; do
    while iptables -C "$chain" -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; do
        run iptables -D "$chain" -m set --match-set "$IPSET_NAME" src -j DROP
    done
done
# LOG rules deployed by log-rules.sh carry the CROWDSEC_LOG comment
for chain in $(iptables -S 2>/dev/null | awk '/^-A /{print $2}' | sort -u); do
    while true; do
        rule_num=$(iptables -L "$chain" --line-numbers -n 2>/dev/null \
            | awk -v m="$LOG_COMMENT" '$0 ~ m {print $1; exit}')
        [ -z "$rule_num" ] && break
        run iptables -D "$chain" "$rule_num"
    done
done

# 5. Flush and destroy the ipset
if ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    log "Destroying ipset $IPSET_NAME..."
    run ipset flush "$IPSET_NAME"
    run ipset destroy "$IPSET_NAME"
fi

# 6. Remove /data/crowdsec-bouncer unless asked to keep it
if [ "$KEEP_CONFIG" -eq 0 ]; then
    log "Removing $BOUNCER_DIR..."
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[dry-run] rm -rf $BOUNCER_DIR"
    else
        cd /
        rm -rf "$BOUNCER_DIR"
    fi
else
    warn "Kept $BOUNCER_DIR - delete it manually when you no longer need the config/logs."
fi

echo ""
log "Uninstall complete."
echo ""
echo "Reminder: remove this bouncer from your CrowdSec LAPI:"
echo "  cscli bouncers list"
echo "  cscli bouncers delete <name>"
echo ""
