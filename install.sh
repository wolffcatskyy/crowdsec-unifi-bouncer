#!/bin/bash
# CrowdSec Firewall Bouncer - Installer for UniFi OS devices
# Tested on: UDM SE, UDR (UniFi OS 4.x)
#
# Usage: ssh root@<unifi-device> 'bash -s' < install.sh
#    or: scp install.sh root@<unifi-device>:/tmp/ && ssh root@<unifi-device> bash /tmp/install.sh

set -e

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
    echo "WARNING: /data/on_boot.d not found. A firmware update will reset the"
    echo "systemd service and cron jobs, and the bouncer will stay stopped until"
    echo "you run: $BOUNCER_DIR/boot-restore.sh --boot"
    echo "To make this automatic, install on-boot-script-2.x from"
    echo "https://github.com/unifi-utilities/unifios-utilities and re-run install.sh."
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
