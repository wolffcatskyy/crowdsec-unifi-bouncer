#!/bin/bash
# CrowdSec UniFi Bouncer - One-line Bootstrap Installer
# Downloads all required files and runs setup automatically
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-bouncer/main/bootstrap.sh | bash
#
# Or with custom options:
#   curl -sSL .../bootstrap.sh | bash -s -- --dry-run
#   curl -sSL .../bootstrap.sh | BOUNCER_VERSION=v0.0.36 bash
#
# Options:
#   --dry-run   Download and verify everything, print the install plan,
#               but make no changes to the device.
#
# Environment variables:
#   BOOTSTRAP_REF     Git ref of THIS repo to install from (default: pinned
#                     release tag below). Set to "main" for bleeding edge.
#   BOUNCER_VERSION   Upstream cs-firewall-bouncer version (see install.sh).
#   ONBOOT_AUTO_INSTALL Passed through to install.sh: 1 (default) installs a pinned,
#                     SHA-256-verified on-boot-script-2.x if missing; 0 skips it.

set -e

# Pinned to a release tag so the bootstrap can't silently drift with main.
# Bumped with each release.
BOOTSTRAP_REF="${BOOTSTRAP_REF:-v2.5.4}"
REPO_URL="https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-bouncer/${BOOTSTRAP_REF}"
BOUNCER_DIR="/data/crowdsec-bouncer"
BOUNCER_VERSION="${BOUNCER_VERSION:-}"
DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1" >&2; }

echo ""
echo "=================================================="
echo "  CrowdSec UniFi Bouncer - Bootstrap Installer"
echo "=================================================="
echo ""
log "Installing from repo ref: $BOOTSTRAP_REF"
[ "$DRY_RUN" -eq 1 ] && warn "DRY RUN - no changes will be made"
echo ""

# Check prerequisites
if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    error "Must run as root"
    exit 1
fi

if ! command -v ipset >/dev/null 2>&1 && [ "$DRY_RUN" -eq 0 ]; then
    error "ipset not found - is this a UniFi OS device?"
    exit 1
fi

if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
    error "Neither wget nor curl found"
    exit 1
fi

# Create directory
if [ "$DRY_RUN" -eq 0 ]; then
    log "Creating $BOUNCER_DIR..."
    mkdir -p "$BOUNCER_DIR/log"
else
    log "[dry-run] Would create $BOUNCER_DIR"
fi

# Download function that works with either wget or curl
download() {
    local url="$1"
    local dest="$2"
    if command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$dest"
    else
        curl -sSL "$url" -o "$dest"
    fi
}

# Files to download from repo
FILES=(
    "install.sh"
    "setup.sh"
    "boot-restore.sh"
    "detect-device.sh"
    "detect-sidecar.sh"
    "ensure-rules.sh"
    "log-rules.sh"
    "ipset-capacity-monitor.sh"
    "metrics.sh"
    "crowdsec-firewall-bouncer.service"
    "crowdsec-unifi-metrics.service"
    "crowdsec-firewall-bouncer.yaml.example"
)

DOWNLOAD_DIR="$BOUNCER_DIR"
if [ "$DRY_RUN" -eq 1 ]; then
    DOWNLOAD_DIR="$(mktemp -d)"
fi

log "Downloading files from repository..."
cd "$DOWNLOAD_DIR"

for file in "${FILES[@]}"; do
    log "  Downloading $file..."
    download "$REPO_URL/$file" "$DOWNLOAD_DIR/$file" || {
        error "Failed to download $file (ref: $BOOTSTRAP_REF)"
        [ "$DRY_RUN" -eq 1 ] && rm -rf "$DOWNLOAD_DIR"
        exit 1
    }
done

# uninstall.sh ships from v2.5.5 onward; best-effort so bootstrap from older
# pinned refs still works.
if download "$REPO_URL/uninstall.sh" "$DOWNLOAD_DIR/uninstall.sh" 2>/dev/null; then
    chmod +x "$DOWNLOAD_DIR/uninstall.sh"
else
    warn "uninstall.sh not present at ref $BOOTSTRAP_REF (added after v2.5.4) - skipping"
    rm -f "$DOWNLOAD_DIR/uninstall.sh"
fi

# Make scripts executable
chmod +x "$DOWNLOAD_DIR/install.sh" \
         "$DOWNLOAD_DIR/setup.sh" \
         "$DOWNLOAD_DIR/boot-restore.sh" \
         "$DOWNLOAD_DIR/detect-device.sh" \
         "$DOWNLOAD_DIR/detect-sidecar.sh" \
         "$DOWNLOAD_DIR/ensure-rules.sh" \
         "$DOWNLOAD_DIR/log-rules.sh" \
         "$DOWNLOAD_DIR/ipset-capacity-monitor.sh" \
         "$DOWNLOAD_DIR/metrics.sh" \
         "$DOWNLOAD_DIR/uninstall.sh"

# Run the installer
if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] Files verified. Would now run: install.sh (downloads and"
    log "[dry-run] checksum-verifies the upstream bouncer, installs services,"
    log "[dry-run] cron jobs, and the firmware-update hook)"
    bash "$DOWNLOAD_DIR/install.sh" --dry-run || warn "[dry-run] upstream download check failed (continuing)"
    rm -rf "$DOWNLOAD_DIR"
    echo ""
    log "[dry-run] Done. Re-run without --dry-run to install."
    exit 0
fi

log "Running installer..."
export BOUNCER_VERSION
cd "$BOUNCER_DIR"
bash "$BOUNCER_DIR/install.sh"

echo ""
log "Bootstrap complete!"
echo ""
echo "=================================================="
echo "  Next Steps"
echo "=================================================="
echo ""
echo "1. Edit config with your CrowdSec LAPI details:"
echo "   \$EDITOR $BOUNCER_DIR/crowdsec-firewall-bouncer.yaml"
echo ""
echo "2. Set these values:"
echo "   api_url: http://YOUR_CROWDSEC_HOST:8081/"
echo "   api_key: YOUR_BOUNCER_API_KEY"
echo ""
echo "3. Start the bouncer:"
echo "   systemctl start crowdsec-firewall-bouncer"
echo "   systemctl enable crowdsec-firewall-bouncer"
echo ""
echo "4. Verify:"
echo "   systemctl status crowdsec-firewall-bouncer"
echo "   ipset list crowdsec-blacklists | head"
echo ""
echo "To remove the bouncer later: $BOUNCER_DIR/uninstall.sh"
echo ""
