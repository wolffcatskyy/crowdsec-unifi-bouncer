#!/bin/bash
# CrowdSec Firewall Bouncer - Installer for UniFi OS devices
# Tested on: UDM SE, UDR (UniFi OS 4.x)
#
# Usage: ssh root@<unifi-device> 'bash -s' < install.sh
#    or: scp install.sh root@<unifi-device>:/tmp/ && ssh root@<unifi-device> bash /tmp/install.sh
#
# Options:
#   --dry-run            Print what would be installed and verify downloads/checksums,
#                        without changing anything on the device.
#
# Environment variables:
#   BOUNCER_VERSION      Upstream cs-firewall-bouncer version (default: pinned, see below).
#                        Overriding disables SHA-256 verification unless you also supply
#                        BOUNCER_SHA256 for the tarball.
#   BOUNCER_SHA256       Expected SHA-256 of the downloaded tarball (optional).
#   ARCH                 Target architecture (default: auto-detected via dpkg).

set -e

BOUNCER_DIR="/data/crowdsec-bouncer"
ARCH="${ARCH:-$(dpkg --print-architecture 2>/dev/null || echo amd64)}"
DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

# Pinned upstream version. The default install verifies the downloaded tarball
# against these known-good SHA-256 hashes (computed from the upstream release
# assets; crowdsecurity does not publish a checksum file, so they are embedded
# here and bumped with the pin).
PINNED_VERSION="v0.0.36"
PINNED_SHA256_AMD64="f86e4b72693549d99f40a9402abefb894108f047a3fbe6e72fada25ee17ce88b"
PINNED_SHA256_ARM64="ce184d3b1ae5888189d237bb0ff1d2414be2ef12729750a7321a4abd2d253de6"

BOUNCER_VERSION="${BOUNCER_VERSION:-$PINNED_VERSION}"

DOWNLOAD_URL="https://github.com/crowdsecurity/cs-firewall-bouncer/releases/download/${BOUNCER_VERSION}/crowdsec-firewall-bouncer-linux-${ARCH}.tgz"

echo "=== CrowdSec Firewall Bouncer Installer ==="
echo "Version: $BOUNCER_VERSION"
echo "Arch: $ARCH"
echo "Target: $BOUNCER_DIR"
[ "$DRY_RUN" -eq 1 ] && echo "Mode: DRY RUN (no changes will be made)"
echo ""

# Check prerequisites
if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    echo "Error: Must run as root" >&2
    exit 1
fi

if ! command -v ipset >/dev/null 2>&1 && [ "$DRY_RUN" -eq 0 ]; then
    echo "Error: ipset not found - is this a UniFi OS device?" >&2
    exit 1
fi

# Resolve the expected checksum for this download.
EXPECTED_SHA256="${BOUNCER_SHA256:-}"
if [ -z "$EXPECTED_SHA256" ] && [ "$BOUNCER_VERSION" = "$PINNED_VERSION" ]; then
    case "$ARCH" in
        amd64) EXPECTED_SHA256="$PINNED_SHA256_AMD64" ;;
        arm64) EXPECTED_SHA256="$PINNED_SHA256_ARM64" ;;
    esac
fi

# Create directory
if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$BOUNCER_DIR/log"
else
    echo "[dry-run] Would create $BOUNCER_DIR/log"
fi

# Download bouncer binary
echo "Downloading bouncer from $DOWNLOAD_URL ..."
cd /tmp
wget -q "$DOWNLOAD_URL" -O crowdsec-firewall-bouncer.tgz || {
    echo "Download failed. You can manually download from:"
    echo "  $DOWNLOAD_URL"
    echo "Then extract the binary to $BOUNCER_DIR/crowdsec-firewall-bouncer"
    exit 1
}

# Verify integrity of the downloaded tarball.
if [ -n "$EXPECTED_SHA256" ]; then
    echo "Verifying SHA-256 checksum..."
    ACTUAL_SHA256=$(sha256sum crowdsec-firewall-bouncer.tgz | awk '{print $1}')
    if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
        echo "ERROR: checksum mismatch for $DOWNLOAD_URL" >&2
        echo "  expected: $EXPECTED_SHA256" >&2
        echo "  actual:   $ACTUAL_SHA256" >&2
        echo "The tarball will NOT be installed. This can indicate a corrupted" >&2
        echo "download or a tampered release asset - do not bypass this check." >&2
        rm -f crowdsec-firewall-bouncer.tgz
        exit 1
    fi
    echo "Checksum OK ($ACTUAL_SHA256)"
else
    echo "WARNING: no known-good checksum for ${BOUNCER_VERSION}/linux-${ARCH}." >&2
    echo "The tarball will be installed WITHOUT integrity verification." >&2
    echo "Use the pinned default version, or pass BOUNCER_SHA256=<hash>, to verify." >&2
fi

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] Would extract and install the binary to $BOUNCER_DIR/crowdsec-firewall-bouncer"
    echo "[dry-run] Would install scripts, service files, cron jobs, and (if present) the on_boot.d hook"
    rm -f crowdsec-firewall-bouncer.tgz
    echo "[dry-run] Done. Re-run without --dry-run to install."
    exit 0
fi

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
for script in setup.sh boot-restore.sh detect-device.sh detect-sidecar.sh ensure-rules.sh log-rules.sh ipset-capacity-monitor.sh metrics.sh uninstall.sh crowdsec-firewall-bouncer.service crowdsec-unifi-metrics.service; do
    if [ -f "/tmp/$script" ] || [ -f "$(dirname "$0")/$script" ]; then
        cp "$(dirname "$0")/$script" "$BOUNCER_DIR/" 2>/dev/null || true
    fi
done
chmod +x "$BOUNCER_DIR/setup.sh" "$BOUNCER_DIR/boot-restore.sh" "$BOUNCER_DIR/detect-device.sh" "$BOUNCER_DIR/detect-sidecar.sh" "$BOUNCER_DIR/ensure-rules.sh" "$BOUNCER_DIR/log-rules.sh" "$BOUNCER_DIR/ipset-capacity-monitor.sh" "$BOUNCER_DIR/metrics.sh" "$BOUNCER_DIR/uninstall.sh" 2>/dev/null || true

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
echo ""
echo "To remove the bouncer later: $BOUNCER_DIR/uninstall.sh"
