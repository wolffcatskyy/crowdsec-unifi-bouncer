#!/bin/bash
# CrowdSec Firewall Bouncer - Sidecar Detection Helper
# Detects whether the bouncer is configured to use a sidecar proxy or direct LAPI.
#
# Usage: source detect-sidecar.sh   # Sets BOUNCER_UPSTREAM and SIDECAR_MODE
#    or: ./detect-sidecar.sh        # Prints detection info

BOUNCER_DIR="${BOUNCER_DIR:-/data/crowdsec-bouncer}"
BOUNCER_CONFIG="$BOUNCER_DIR/crowdsec-firewall-bouncer.yaml"

# Default sidecar port
SIDECAR_PORT="${SIDECAR_PORT:-8084}"

detect_sidecar_mode() {
    local api_url=""

    # Parse api_url from bouncer config
    if [ -f "$BOUNCER_CONFIG" ]; then
        api_url=$(grep -E "^api_url:" "$BOUNCER_CONFIG" 2>/dev/null | awk '{print $2}' | tr -d '"' | tr -d "'")
    fi

    if [ -z "$api_url" ]; then
        echo "unknown"
        return
    fi

    # Extract port from URL
    local port
    port=$(echo "$api_url" | grep -oE ':[0-9]+/' | tr -d ':/')

    case "$port" in
        8080|8081)
            echo "lapi"
            ;;
        "$SIDECAR_PORT")
            echo "sidecar"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Main execution when run directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SIDECAR_MODE=$(detect_sidecar_mode)
    echo "Upstream mode: $SIDECAR_MODE"

    if [ -f "$BOUNCER_CONFIG" ]; then
        api_url=$(grep -E "^api_url:" "$BOUNCER_CONFIG" 2>/dev/null | awk '{print $2}' | tr -d '"' | tr -d "'")
        echo "api_url: ${api_url:-not set}"
    else
        echo "Config not found: $BOUNCER_CONFIG"
    fi

    case "$SIDECAR_MODE" in
        lapi)
            echo ""
            echo "Bouncer connects directly to CrowdSec LAPI."
            echo "If you have more decisions than your ipset can hold,"
            echo "consider deploying the sidecar proxy. See README.md."
            ;;
        sidecar)
            echo ""
            echo "Bouncer connects through the sidecar proxy."
            echo "The sidecar filters and prioritizes decisions to fit ipset capacity."
            ;;
    esac
fi

# Export variables when sourced
SIDECAR_MODE=$(detect_sidecar_mode)
export SIDECAR_MODE
BOUNCER_UPSTREAM=""
if [ -f "$BOUNCER_CONFIG" ]; then
    BOUNCER_UPSTREAM=$(grep -E "^api_url:" "$BOUNCER_CONFIG" 2>/dev/null | awk '{print $2}' | tr -d '"' | tr -d "'")
fi
export BOUNCER_UPSTREAM
