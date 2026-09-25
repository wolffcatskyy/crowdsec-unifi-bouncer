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
    echo "[dry-run] Would install scripts, service files, cron jobs, and the on_boot.d hook"
    case "$ONBOOT_STATE" in
        install) echo "[dry-run] Would install verified udm-boot.service (${ONBOOT_REPO}@${ONBOOT_COMMIT:0:7}) to $ONBOOT_UNIT and enable it"
                 rm -f "$ONBOOT_TMP" ;;
        present) echo "[dry-run] on-boot-script-2.x already installed, would leave it alone" ;;
        *)       echo "[dry-run] Would skip on-boot-script-2.x (not installed)" ;;
    esac
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
# on-boot-script-2.x (resolved near the top: left alone if present, installed
# from the pinned commit if missing) runs /data/on_boot.d at every boot; hook
# boot-restore.sh there so everything is put back.
ON_BOOT_DIR="/data/on_boot.d"
ON_BOOT_HOOK="$ON_BOOT_DIR/99-crowdsec-bouncer.sh"
if [ "$ONBOOT_STATE" = "install" ]; then
    # Install the verified unit. Enabled only (not started now): this installer
    # already ran boot-restore.sh, and starting udm-boot would run every script
    # in /data/on_boot.d immediately.
    install -m 0644 "$ONBOOT_TMP" "$ONBOOT_UNIT"
    rm -f "$ONBOOT_TMP"
    mkdir -p "$ON_BOOT_DIR"
    systemctl daemon-reload
    systemctl enable udm-boot.service
    echo "Installed on-boot-script-2.x (${ONBOOT_REPO}@${ONBOOT_COMMIT:0:7}): runs $ON_BOOT_DIR at every boot."
elif [ "$ONBOOT_STATE" = "present" ]; then
    # udm-boot creates this at boot; make sure the hook has somewhere to go now.
    mkdir -p "$ON_BOOT_DIR"
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
echo ""
echo "To remove the bouncer later: $BOUNCER_DIR/uninstall.sh"
