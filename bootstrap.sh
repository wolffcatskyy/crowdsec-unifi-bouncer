#!/bin/bash
# CrowdSec UniFi Bouncer - One-line Bootstrap Installer
# Downloads all required files and runs setup automatically
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-bouncer/main/bootstrap.sh | bash
#
# Or with custom options:
#   curl -sSL https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-bouncer/main/bootstrap.sh | BOUNCER_VERSION=v0.0.34 bash

set -e

REPO_URL="https://raw.githubusercontent.com/wolffcatskyy/crowdsec-unifi-bouncer/main"
BOUNCER_DIR="/data/crowdsec-bouncer"
BOUNCER_VERSION="${BOUNCER_VERSION:-v0.0.34}"

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

# Check prerequisites
if [ "$(id -u)" -ne 0 ]; then
    error "Must run as root"
    exit 1
fi

if ! command -v ipset >/dev/null 2>&1; then
    error "ipset not found - is this a UniFi OS device?"
    exit 1
fi

if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
    error "Neither wget nor curl found"
    exit 1
fi

# Create directory
log "Creating $BOUNCER_DIR..."
mkdir -p "$BOUNCER_DIR/log"

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
    "detect-device.sh"
    "detect-sidecar.sh"
    "ensure-rules.sh"
    "ipset-capacity-monitor.sh"
    "metrics.sh"
    "crowdsec-firewall-bouncer.service"
    "crowdsec-unifi-metrics.service"
    "crowdsec-firewall-bouncer.yaml.example"
)

log "Downloading files from repository..."
cd "$BOUNCER_DIR"

for file in "${FILES[@]}"; do
    log "  Downloading $file..."
    download "$REPO_URL/$file" "$BOUNCER_DIR/$file" || {
        error "Failed to download $file"
        exit 1
    }
done

# Make scripts executable
chmod +x "$BOUNCER_DIR/install.sh" \
         "$BOUNCER_DIR/setup.sh" \
         "$BOUNCER_DIR/detect-device.sh" \
         "$BOUNCER_DIR/detect-sidecar.sh" \
         "$BOUNCER_DIR/ensure-rules.sh" \
         "$BOUNCER_DIR/ipset-capacity-monitor.sh" \
         "$BOUNCER_DIR/metrics.sh"

# Run the installer
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
echo "   nano $BOUNCER_DIR/crowdsec-firewall-bouncer.yaml"
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
