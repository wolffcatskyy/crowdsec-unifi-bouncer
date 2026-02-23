#!/bin/bash
# CrowdSec Firewall Bouncer - UniFi Device Detection
# Detects device model and sets safe ipset maxelem defaults
#
# Usage: source detect-device.sh   # Sets DETECTED_MODEL and SAFE_MAXELEM
#    or: ./detect-device.sh        # Prints detection info

# Safe defaults that work reliably on each device type
# Override with ipset_size in config for custom values
declare -A DEVICE_MAXELEM=(
    ["UniFi Dream Machine Pro"]=20000
    ["UniFi Dream Machine SE"]=20000
    ["UniFi Dream Machine Pro Max"]=30000
    ["UniFi Dream Router"]=15000
    ["UniFi Cloud Gateway Fiber"]=15000
    ["UniFi Cloud Gateway Ultra"]=15000
    ["UniFi Express"]=10000
    ["UniFi Dream Machine"]=15000
)

DEFAULT_MAXELEM=20000

detect_device_model() {
    local model=""

    # Method 1: ubnt-device-info (most reliable)
    if command -v ubnt-device-info >/dev/null 2>&1; then
        model=$(ubnt-device-info model 2>/dev/null)
    fi

    # Method 2: /etc/unifi-os/unifi_version
    if [ -z "$model" ] && [ -f /etc/unifi-os/unifi_version ]; then
        model=$(grep -i "model" /etc/unifi-os/unifi_version 2>/dev/null | cut -d'=' -f2)
    fi

    # Method 3: /sys/firmware/devicetree/base/model
    if [ -z "$model" ] && [ -f /sys/firmware/devicetree/base/model ]; then
        model=$(cat /sys/firmware/devicetree/base/model 2>/dev/null | tr -d '\0')
    fi

    # Method 4: Check dmesg for device identifiers
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

# Main execution when run directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    DETECTED_MODEL=$(detect_device_model)
    SAFE_MAXELEM=$(get_safe_maxelem "$DETECTED_MODEL")
    TOTAL_MEM=$(get_total_memory_mb)

    echo "Device: ${DETECTED_MODEL:-Unknown}"
    echo "RAM: ${TOTAL_MEM}MB"
    echo "Default maxelem: $SAFE_MAXELEM"
    echo "Recommended sidecar max_decisions: $((SAFE_MAXELEM - 2000))"

    if [ -n "$MAXELEM" ]; then
        echo "Configured maxelem: $MAXELEM"
    fi
fi

# Export variables when sourced
DETECTED_MODEL=$(detect_device_model)
SAFE_MAXELEM=$(get_safe_maxelem "$DETECTED_MODEL")
# Recommended sidecar max_decisions: leave 2000 entries headroom for manual bans
RECOMMENDED_SIDECAR_CAP=$((SAFE_MAXELEM - 2000))
