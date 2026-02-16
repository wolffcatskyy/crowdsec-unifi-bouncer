#!/bin/bash
# CrowdSec Firewall Bouncer - UniFi Device Detection
# Detects UniFi device model and recommends safe ipset maxelem limits
#
# Usage: source detect-device.sh   # Sets DETECTED_MODEL and SAFE_MAXELEM
#    or: ./detect-device.sh        # Prints detection info

# Safe maxelem defaults based on device memory and stability testing
# These are conservative values to avoid OOM conditions and kernel instability
# Memory isn't the only bottleneck - ipset operations can cause issues at high counts
# ipset uses ~100 bytes per entry, so 50000 entries ≈ 5MB
declare -A DEVICE_MAXELEM=(
    ["UniFi Dream Machine Pro"]=50000      # UDM-Pro: 4GB RAM, reduced from 60K for safety
    ["UniFi Dream Machine SE"]=50000       # UDM-SE: 4GB RAM, reduced from 60K for safety
    ["UniFi Dream Machine Pro Max"]=60000  # UDM-Pro-Max: 8GB RAM, memory isn't the only bottleneck
    ["UniFi Dream Router"]=35000           # UDR: 2GB RAM, reduced from 40K
    ["UniFi Cloud Gateway Fiber"]=35000    # UCG-Fiber: 2GB RAM, reduced from 40K
    ["UniFi Cloud Gateway Ultra"]=35000    # UCG-Ultra: 2GB RAM, reduced from 40K
    ["UniFi Express"]=15000                # UX: 1GB RAM, reduced from 20K
    ["UniFi Dream Machine"]=35000          # UDM (original): 2GB RAM, reduced from 40K
)

DEFAULT_MAXELEM=25000

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

validate_maxelem() {
    local configured="$1"
    local safe_limit="$2"
    local model="$3"

    if [ "$configured" -gt "$safe_limit" ]; then
        echo "WARNING: Configured maxelem ($configured) exceeds safe limit ($safe_limit) for $model" >&2
        echo "This may cause memory issues or kernel instability." >&2
        echo "Recommended: Set MAXELEM=$safe_limit or lower in your environment." >&2
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
    echo "Safe maxelem: $SAFE_MAXELEM"
    echo ""

    if [ -n "$MAXELEM" ]; then
        echo "Configured MAXELEM: $MAXELEM"
        validate_maxelem "$MAXELEM" "$SAFE_MAXELEM" "$DETECTED_MODEL"
    else
        echo "MAXELEM not set, will use safe default: $SAFE_MAXELEM"
    fi
fi

# Export variables when sourced
DETECTED_MODEL=$(detect_device_model)
SAFE_MAXELEM=$(get_safe_maxelem "$DETECTED_MODEL")
