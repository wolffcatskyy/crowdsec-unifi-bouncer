#!/bin/bash
# CrowdSec Firewall Bouncer - Installer for UniFi OS devices
# Tested on: UDM SE, UDR (UniFi OS 4.x)
#
# Usage: ssh root@<unifi-device> 'bash -s' < install.sh
#    or: scp install.sh root@<unifi-device>:/tmp/ && ssh root@<unifi-device> bash /tmp/install.sh
#
# Environment variables:
#   ONBOOT_AUTO_INSTALL  1 (default) installs the pinned on-boot-script-2.x if it is
#                        missing; 0 skips that and only prints the manual steps.

set -e

# ============================================================================
# ON-BOOT DEPENDENCY PIN - on-boot-script-2.x (udm-boot) from unifi-utilities
# ----------------------------------------------------------------------------
# The firmware-update hook needs unifi-utilities' on-boot-script-2.x (the
# udm-boot systemd unit that runs /data/on_boot.d/* at boot). It is now
# maintained in unifi-utilities/unifi-common (moved from unifios-utilities).
#
#   - Already installed?  Left alone. Nothing is downloaded or changed.
#   - Missing?            udm-boot.service is downloaded from the commit
#                         pinned below, checked against ONBOOT_SHA256, and
#                         installed. A checksum mismatch aborts the install
#                         before anything on the device is changed.
#
# Nothing from upstream is copied into this repo. To bump the pin: choose a
# unifi-common commit, download udm-boot.service at that commit, run
# sha256sum on it, and update both values below together.
ONBOOT_REPO="unifi-utilities/unifi-common"
ONBOOT_COMMIT="f3a02becc3051b59e50d39c218d34f88369762ad"
ONBOOT_SHA256="19d900a0cb3e5a1f632a2d5a8373b3ac9d0542f89acb1eb451eb1c475fecf5a1"
# ============================================================================
ONBOOT_URL="https://raw.githubusercontent.com/${ONBOOT_REPO}/${ONBOOT_COMMIT}/udm-boot.service"
ONBOOT_UNIT="/etc/systemd/system/udm-boot.service"
ONBOOT_AUTO_INSTALL="${ONBOOT_AUTO_INSTALL:-1}"

BOUNCER_DIR="/data/crowdsec-bouncer"
ARCH="${ARCH:-$(dpkg --print-architecture 2>/dev/null || echo amd64)}"

# Fetch latest version from GitHub API if not explicitly set
if [ -z "$BOUNCER_VERSION" ]; then
    BOUNCER_VERSION=$(wget -q -O- https://api.github.com/repos/crowdsecurity/cs-firewall-bouncer/releases/latest 2>/dev/null \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    if [ -z "$BOUNCER_VERSION" ]; then
        echo "Warning: Could not fetch latest version from GitHub API, falling back to v0.0.41"
        BOUNCER_VERSION="v0.0.41"
    fi
fi

DOWNLOAD_URL="https://github.com/crowdsecurity/cs-firewall-bouncer/releases/download/${BOUNCER_VERSION}/crowdsec-firewall-bouncer-linux-${ARCH}.tgz"

echo "=== CrowdSec Firewall Bouncer Installer ==="
echo "Version: $BOUNCER_VERSION"
echo "Arch: $ARCH"
echo "Target: $BOUNCER_DIR"
echo ""

# Check prerequisites
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Must run as root" >&2
    exit 1
fi

if ! command -v ipset >/dev/null 2>&1; then
    echo "Error: ipset not found" >&2
    exit 1
fi

# Resolve the on-boot dependency before changing anything, so a failed
# download or checksum mismatch leaves the device untouched.
#   ONBOOT_STATE=present  on-boot-script-2.x already installed (left alone)
#   ONBOOT_STATE=install  missing; verified unit staged in $ONBOOT_TMP
#   ONBOOT_STATE=skip     not installing it (opted out or no systemd)
onboot_installed() {
    [ -f "$ONBOOT_UNIT" ] || systemctl cat udm-boot.service >/dev/null 2>&1
}

onboot_fetch() {
    if command -v wget >/dev/null 2>&1; then
        wget -q "$ONBOOT_URL" -O "$1"
    elif command -v curl >/dev/null 2>&1; then
        curl -fsSL "$ONBOOT_URL" -o "$1"
    else
        return 1
    fi
}

ONBOOT_TMP=""
if onboot_installed; then
    ONBOOT_STATE="present"
    echo "on-boot-script-2.x: already installed, leaving it as is."
elif [ "$ONBOOT_AUTO_INSTALL" = "0" ]; then
    ONBOOT_STATE="skip"
    echo "on-boot-script-2.x: not installed (ONBOOT_AUTO_INSTALL=0, skipping)."
elif ! command -v systemctl >/dev/null 2>&1; then
    ONBOOT_STATE="skip"
    echo "on-boot-script-2.x: not installed, and this device has no systemd (UniFi OS 4.x+ required). Skipping."
else
    ONBOOT_STATE="install"
    echo "on-boot-script-2.x: not installed. Fetching pinned version (${ONBOOT_REPO}@${ONBOOT_COMMIT:0:7})..."
    if ! command -v sha256sum >/dev/null 2>&1; then
        echo "Error: sha256sum not found, so on-boot-script-2.x can't be verified." >&2
        echo "Nothing was changed. Install it yourself (https://github.com/${ONBOOT_REPO})" >&2
        echo "or re-run with ONBOOT_AUTO_INSTALL=0." >&2
        exit 1
    fi
    ONBOOT_TMP="$(mktemp /tmp/udm-boot.service.XXXXXX)"
    if ! onboot_fetch "$ONBOOT_TMP"; then
        rm -f "$ONBOOT_TMP"
        echo "Error: could not download on-boot-script-2.x from:" >&2
        echo "  $ONBOOT_URL" >&2
        echo "Nothing was changed. Check network access, or re-run with ONBOOT_AUTO_INSTALL=0." >&2
        exit 1
    fi
    ONBOOT_ACTUAL="$(sha256sum "$ONBOOT_TMP" | awk '{print $1}')"
    if [ "$ONBOOT_ACTUAL" != "$ONBOOT_SHA256" ]; then
        rm -f "$ONBOOT_TMP"
        echo "" >&2
        echo "Error: CHECKSUM MISMATCH for on-boot-script-2.x (udm-boot.service)." >&2
        echo "  URL:      $ONBOOT_URL" >&2
        echo "  Expected: $ONBOOT_SHA256" >&2
        echo "  Got:      $ONBOOT_ACTUAL" >&2
        echo "The downloaded file does not match the pinned version, so it was discarded." >&2
        echo "Install aborted. Nothing was changed on this device." >&2
        echo "Please report this at https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/issues" >&2
        exit 1
    fi
    echo "on-boot-script-2.x: checksum verified."
fi

# Create directory
mkdir -p "$BOUNCER_DIR/log"

# Download bouncer binary
echo "Downloading bouncer..."
cd /tmp
wget -q "$DOWNLOAD_URL" -O crowdsec-firewall-bouncer.tgz || {
    echo "Download failed. You can manually download from:"
    echo "  $DOWNLOAD_URL"
    echo "Then extract the binary to $BOUNCER_DIR/crowdsec-firewall-bouncer"
    exit 1
}

tar xzf crowdsec-firewall-bouncer.tgz
cp crowdsec-firewall-bouncer-*/crowdsec-firewall-bouncer "$BOUNCER_DIR/"
chmod +x "$BOUNCER_DIR/crowdsec-firewall-bouncer"
rm -rf crowdsec-firewall-bouncer.tgz crowdsec-firewall-bouncer-*/
echo "Binary installed."

# Check if config exists
if [ ! -f "$BOUNCER_DIR/crowdsec-firewall-bouncer.yaml" ]; then
    echo ""
    echo "No config found. Creating from template..."
    echo "You MUST edit $BOUNCER_DIR/crowdsec-firewall-bouncer.yaml with your:"
    echo "  - api_url: Your CrowdSec LAPI address"
    echo "  - api_key: Your bouncer API key (from 'cscli bouncers add <name>')"
    cp "$BOUNCER_DIR/../crowdsec-firewall-bouncer.yaml.example" "$BOUNCER_DIR/crowdsec-firewall-bouncer.yaml" 2>/dev/null || {
        # Download from repo if not available locally
        wget -q "https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-bouncer/main/crowdsec-firewall-bouncer.yaml.example" \
            -O "$BOUNCER_DIR/crowdsec-firewall-bouncer.yaml"
    }
fi

# Install scripts and service files
for script in setup.sh boot-restore.sh detect-device.sh detect-sidecar.sh ensure-rules.sh log-rules.sh ipset-capacity-monitor.sh metrics.sh crowdsec-firewall-bouncer.service crowdsec-unifi-metrics.service; do
    if [ -f "/tmp/$script" ] || [ -f "$(dirname "$0")/$script" ]; then
        cp "$(dirname "$0")/$script" "$BOUNCER_DIR/" 2>/dev/null || true
    fi
done
chmod +x "$BOUNCER_DIR/setup.sh" "$BOUNCER_DIR/boot-restore.sh" "$BOUNCER_DIR/detect-device.sh" "$BOUNCER_DIR/detect-sidecar.sh" "$BOUNCER_DIR/ensure-rules.sh" "$BOUNCER_DIR/log-rules.sh" "$BOUNCER_DIR/ipset-capacity-monitor.sh" "$BOUNCER_DIR/metrics.sh" 2>/dev/null || true

# Install systemd service, enable it on boot, and install cron jobs
# (rule persistence + capacity monitoring). boot-restore.sh is idempotent and
# is the same script that restores all of this after a firmware update.
cp "$BOUNCER_DIR/crowdsec-firewall-bouncer.service" /etc/systemd/system/ 2>/dev/null || \
    ln -sf "$BOUNCER_DIR/crowdsec-firewall-bouncer.service" /etc/systemd/system/crowdsec-firewall-bouncer.service
bash "$BOUNCER_DIR/boot-restore.sh"
echo "Service enabled on boot. Cron jobs installed."

# Survive firmware updates: UniFi OS resets /etc and root's crontab on update.
# With unifios-utilities on-boot-script-2.x installed, hook boot-restore.sh
# into /data/on_boot.d so everything is put back on every boot.
ON_BOOT_DIR="/data/on_boot.d"
ON_BOOT_HOOK="$ON_BOOT_DIR/99-crowdsec-bouncer.sh"
if [ "$ONBOOT_STATE" = "install" ] && [ "${DRY_RUN:-0}" = "1" ]; then
    echo "[dry-run] Would install verified udm-boot.service to $ONBOOT_UNIT and enable it"
    rm -f "$ONBOOT_TMP"
elif [ "$ONBOOT_STATE" = "install" ]; then
    # Install the verified unit. Enabled only (not started now): this installer
    # already ran boot-restore.sh, and starting udm-boot would run every script
    # in /data/on_boot.d immediately.
    install -m 0644 "$ONBOOT_TMP" "$ONBOOT_UNIT"
    rm -f "$ONBOOT_TMP"
    mkdir -p "$ON_BOOT_DIR"
    systemctl daemon-reload
    systemctl enable udm-boot.service
    echo "Installed on-boot-script-2.x (${ONBOOT_REPO}@${ONBOOT_COMMIT:0:7}): runs $ON_BOOT_DIR at every boot."
fi
if [ -d "$ON_BOOT_DIR" ]; then
    cat > "$ON_BOOT_HOOK" <<HOOK
#!/bin/bash
# Installed by crowdsec-unifi-bouncer - restores the bouncer after firmware updates
$BOUNCER_DIR/boot-restore.sh --boot
HOOK
    chmod +x "$ON_BOOT_HOOK"
    echo "Firmware-update hook installed: $ON_BOOT_HOOK"
else
    echo ""
    echo "WARNING: on-boot-script-2.x is not installed. A firmware update will reset the"
    echo "systemd service and cron jobs, and the bouncer will stay stopped until"
    echo "you run: $BOUNCER_DIR/boot-restore.sh --boot"
    echo "To make this automatic, re-run install.sh without ONBOOT_AUTO_INSTALL=0,"
    echo "or install it from https://github.com/${ONBOOT_REPO} and re-run install.sh."
fi

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit config:    \$EDITOR $BOUNCER_DIR/crowdsec-firewall-bouncer.yaml"
echo "  2. Set api_url and api_key"
echo "  3. Start bouncer:  systemctl start crowdsec-firewall-bouncer"
echo "  4. Check status:   systemctl status crowdsec-firewall-bouncer"
echo "  5. Check logs:     tail -f $BOUNCER_DIR/log/crowdsec-firewall-bouncer.log"
echo ""
echo "Optional: Enable Prometheus metrics endpoint"
echo "  ln -sf $BOUNCER_DIR/crowdsec-unifi-metrics.service /etc/systemd/system/"
echo "  systemctl daemon-reload && systemctl enable --now crowdsec-unifi-metrics"
echo "  curl http://localhost:9101/metrics"
echo ""
echo "Capacity monitoring is enabled by default (cron job)."
echo "Check capacity status: $BOUNCER_DIR/ipset-capacity-monitor.sh --status"
