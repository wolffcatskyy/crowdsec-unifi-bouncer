#!/bin/bash
# CrowdSec Firewall Bouncer - Boot/Firmware-Update Restore
#
# UniFi OS firmware updates keep /data/ but reset /etc/ and root's crontab.
# That removes the systemd unit link, the "enabled" (multi-user.target.wants)
# link, and the cron jobs - so after an update the bouncer silently never
# starts, and ensure-rules.sh can't help because it only acts while the
# bouncer is running. See discussion #46.
#
# This script puts all of that back. It is idempotent: safe to run any time.
#
# Usage:
#   boot-restore.sh           Re-link, enable, restore cron jobs (no start)
#   boot-restore.sh --boot    Same, then start the bouncer if it isn't running
#
# install.sh runs it once and, if unifios-utilities on-boot-script-2.x is
# installed (/data/on_boot.d exists), hooks it to run on every boot:
#   /data/on_boot.d/99-crowdsec-bouncer.sh

BOUNCER_DIR="${BOUNCER_DIR:-/data/crowdsec-bouncer}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE="crowdsec-firewall-bouncer"

# 1. Unit file link (firmware updates remove it)
if [ ! -e "$SYSTEMD_DIR/$SERVICE.service" ]; then
    ln -sf "$BOUNCER_DIR/$SERVICE.service" "$SYSTEMD_DIR/$SERVICE.service"
    logger -t crowdsec-bouncer "boot-restore: re-linked $SERVICE.service" 2>/dev/null || true
fi
systemctl daemon-reload

# 2. Enable on boot (firmware updates remove the wants/ link)
if ! systemctl is-enabled --quiet "$SERVICE" 2>/dev/null; then
    systemctl enable "$SERVICE" >/dev/null 2>&1
    logger -t crowdsec-bouncer "boot-restore: re-enabled $SERVICE" 2>/dev/null || true
fi

# 3. Cron jobs (root's crontab is outside /data and is reset by updates)
CRON_JOBS=(
    "*/5 * * * * $BOUNCER_DIR/ensure-rules.sh"
    "*/5 * * * * $BOUNCER_DIR/log-rules.sh --quiet"
    "*/5 * * * * $BOUNCER_DIR/ipset-capacity-monitor.sh --check >/dev/null 2>&1"
)
CRON_MARKERS=(ensure-rules.sh log-rules.sh ipset-capacity-monitor)
for i in "${!CRON_JOBS[@]}"; do
    if ! crontab -l 2>/dev/null | grep -q "${CRON_MARKERS[$i]}"; then
        (crontab -l 2>/dev/null; echo "${CRON_JOBS[$i]}") | crontab -
        logger -t crowdsec-bouncer "boot-restore: restored cron job for ${CRON_MARKERS[$i]}" 2>/dev/null || true
    fi
done

# 4. On boot, start the bouncer if it isn't running (needs a config)
if [ "${1:-}" = "--boot" ]; then
    if [ -f "$BOUNCER_DIR/$SERVICE.yaml" ] && ! systemctl is-active --quiet "$SERVICE"; then
        systemctl start "$SERVICE"
        logger -t crowdsec-bouncer "boot-restore: started $SERVICE" 2>/dev/null || true
    fi
fi

exit 0
