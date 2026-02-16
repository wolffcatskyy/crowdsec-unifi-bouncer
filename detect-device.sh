#!/bin/bash
# CrowdSec Firewall Bouncer - UniFi Device Detection
# Detects UniFi device model and suggests CONSERVATIVE ipset maxelem defaults
#
# IMPORTANT: These limits are ESTIMATES, NOT empirically tested values.
# Start low, monitor memory, and increase gradually if stable.
#
# Usage: source detect-device.sh   # Sets DETECTED_MODEL and SAFE_MAXELEM
#    or: ./detect-device.sh        # Prints detection info

# =============================================================================
# WARNING: THESE ARE UNTESTED ESTIMATES
# =============================================================================
# The maxelem values below are CONSERVATIVE GUESSES based on device RAM specs,
# NOT actual stability testing on each device model. Real-world limits depend on:
# - What UniFi applications are running (Protect, Talk, Access consume RAM)
# - Current system load and memory pressure
# - Firmware version and kernel behavior
# - Network traffic patterns
#
# RECOMMENDED APPROACH:
# 1. Start with 20,000 entries (the default below)
# 2. Monitor MemAvailable: cat /proc/meminfo | grep MemAvailable
# 3. Watch memory over 24-48 hours under typical load
# 4. If stable with >500MB available, increase by 5,000 and repeat
# 5. Report your findings via GitHub issues to help others
# =============================================================================

# Conservative defaults - ALL devices start at 20,000
# These are intentionally low to avoid crashes on untested configurations
declare -A DEVICE_MAXELEM=(
    ["UniFi Dream Machine Pro"]=20000       # UDM-Pro: 4GB RAM - UNTESTED, start here
    ["UniFi Dream Machine SE"]=20000        # UDM-SE: 4GB RAM - UNTESTED, start here
    ["UniFi Dream Machine Pro Max"]=20000   # UDM-Pro-Max: 8GB RAM - UNTESTED, start here
    ["UniFi Dream Router"]=20000            # UDR: 2GB RAM - UNTESTED, start here
    ["UniFi Cloud Gateway Fiber"]=20000     # UCG-Fiber: 2GB RAM - UNTESTED, start here
    ["UniFi Cloud Gateway Ultra"]=20000     # UCG-Ultra: 2GB RAM - UNTESTED, start here
    ["UniFi Express"]=20000                 # UX: 1GB RAM - UNTESTED, start here
    ["UniFi Dream Machine"]=20000           # UDM (original): 2GB RAM - UNTESTED, start here
)

# Default for unknown devices - same conservative value
DEFAULT_MAXELEM=20000

detect_device_model() {
    local model=""

    # Method 1: ubnt-device-info (most reliable)
    if command -v ubnt-device-info >/dev/null 2>&1; then
        model=$(ubnt-device-info model 2>/dev/null)
    fi

    # Method 2: /etc/unifi-os/unifi_version (older firmware)
    if [ -z "$model" ] && [ -f /etc/unifi-os/unifi_version ]; then
        # Parse device info from version file
        model=$(grep -i "model" /etc/unifi-os/unifi_version 2>/dev/null | cut -d'=' -f2)
    fi

    # Method 3: /sys/firmware/devicetree/base/model (ARM devices)
    if [ -z "$model" ] && [ -f /sys/firmware/devicetree/base/model ]; then
        model=$(cat /sys/firmware/devicetree/base/model 2>/dev/null | tr -d '\0')
    fi

    # Method 4: Check for known device identifiers in dmesg
    if [ -z "$model" ]; then
        for pattern in "UDM-SE" "UDM-Pro" "UDMPRO" "UDR" "UCG"; do
            if dmesg 2>/dev/null | grep -qi "$pattern"; then
                case "$pattern" in
                    "UDM-SE") model="UniFi Dream Machine SE" ;;
                    "UDM-Pro"|"UDMPRO") model="UniFi Dream Machine Pro" ;;
                    "UDR") model="UniFi Dream Router" ;;
                    "UCG") model="UniFi Cloud Gateway" ;;
                esac
                break
            fi
        done
    fi

    echo "$model"
}

get_safe_maxelem() {
    local model="$1"
    local maxelem="${DEVICE_MAXELEM[$model]}"

    if [ -z "$maxelem" ]; then
        # Try partial matching for variations
        for key in "${!DEVICE_MAXELEM[@]}"; do
            if [[ "$model" == *"$key"* ]] || [[ "$key" == *"$model"* ]]; then
                maxelem="${DEVICE_MAXELEM[$key]}"
                break
            fi
        done
    fi

    # Fallback to default
    echo "${maxelem:-$DEFAULT_MAXELEM}"
}

get_total_memory_mb() {
    local mem_kb
    mem_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')
    if [ -n "$mem_kb" ]; then
        echo $((mem_kb / 1024))
    else
        echo "0"
    fi
}

print_warning() {
    echo ""
    echo "=========================================================================="
    echo "WARNING: ipset LIMITS ARE UNTESTED ESTIMATES"
    echo "=========================================================================="
    echo "The suggested maxelem value ($1) is a CONSERVATIVE GUESS, not a"
    echo "verified safe limit for your device. Real stability depends on:"
    echo "  - Running UniFi applications (Protect, Talk, Access use RAM)"
    echo "  - Current system load and memory pressure"
    echo "  - Firmware version"
    echo ""
    echo "RECOMMENDED:"
    echo "  1. Start with this conservative default (20,000)"
    echo "  2. Monitor memory: cat /proc/meminfo | grep MemAvailable"
    echo "  3. Run for 24-48 hours under typical load"
    echo "  4. If stable with >500MB free, increase by 5,000 and repeat"
    echo "  5. Report your tested limits via GitHub issues!"
    echo "=========================================================================="
    echo ""
}

validate_maxelem() {
    local configured="$1"
    local suggested="$2"
    local model="$3"

    if [ "$configured" -gt "$suggested" ]; then
        echo "NOTE: Configured maxelem ($configured) exceeds suggested conservative default ($suggested)" >&2
        echo "This MAY be fine on your device - monitor memory closely." >&2
        echo "Watch: cat /proc/meminfo | grep MemAvailable" >&2
        echo "If MemAvailable drops below 300MB, reduce maxelem." >&2
        return 1
    fi
    return 0
}

# Main execution when run directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    DETECTED_MODEL=$(detect_device_model)
    SAFE_MAXELEM=$(get_safe_maxelem "$DETECTED_MODEL")
    TOTAL_MEM=$(get_total_memory_mb)

    echo "=== UniFi Device Detection ==="
    echo "Detected model: ${DETECTED_MODEL:-Unknown}"
    echo "Total memory: ${TOTAL_MEM}MB"
    echo "Suggested maxelem: $SAFE_MAXELEM (CONSERVATIVE DEFAULT)"

    print_warning "$SAFE_MAXELEM"

    if [ -n "$MAXELEM" ]; then
        echo "Configured MAXELEM: $MAXELEM"
        validate_maxelem "$MAXELEM" "$SAFE_MAXELEM" "$DETECTED_MODEL"
    else
        echo "MAXELEM not set, will use conservative default: $SAFE_MAXELEM"
    fi
fi

# Export variables when sourced
DETECTED_MODEL=$(detect_device_model)
SAFE_MAXELEM=$(get_safe_maxelem "$DETECTED_MODEL")
