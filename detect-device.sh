#!/bin/bash
# CrowdSec Firewall Bouncer - UniFi Device Detection
# Detects device model and sets safe ipset maxelem defaults
# Based on Ubiquiti CyberSecure IPS signature capacity specifications
#
# Usage: source detect-device.sh   # Sets DETECTED_MODEL, SAFE_MAXELEM, etc.
#    or: ./detect-device.sh        # Prints detection info
#
# Environment variables:
#   MAXELEM_OVERRIDE   - Manual override for ipset maxelem (bypasses auto-detection)
#   MEMORY_OPTIMIZED   - Set to "true" for reduced limits on memory-constrained devices

# Device limits based on Ubiquiti CyberSecure IPS signature capacities
# Source: https://help.ui.com/hc/en-us/articles/25930305913751
#
# Device model shortnames -> recommended ipset maxelem
# These are conservative values (below max signatures) for stability
declare -A DEVICE_MAXELEM=(
    # Enterprise tier (95k+ signatures)
    ["EFG"]=80000
    ["UXG-Enterprise"]=80000

    # Pro tier (55k+ signatures)
    ["UDM-Pro-Max"]=50000
    ["UDMPRO-Max"]=50000
    ["UDM-SE"]=50000
    ["UDMSE"]=50000
    ["UDM-Pro"]=50000
    ["UDMPRO"]=50000
    ["UDW"]=50000
    ["UCG-Max"]=50000
    ["UCG-Ultra"]=50000
    ["UCG-Fiber"]=50000
    ["UXG-Max"]=50000
    ["UXG-Pro"]=50000
    ["UXG-Fiber"]=50000

    # Consumer tier (20k+ signatures)
    ["UDM"]=15000
    ["UDR"]=15000
    ["UDR7"]=15000
    ["UX7"]=15000

    # Unsupported (no firewall group/ipset support)
    ["UX"]=0
    ["UXG-Lite"]=0
)

# Memory optimized limits for devices running BGP, ad-blocking,
# content filtering, or multiple UniFi applications
declare -A MEMORY_OPTIMIZED_LIMITS=(
    ["UDM-Pro-Max"]=30000
    ["UDMPRO-Max"]=30000
    ["UDM-SE"]=30000
    ["UDMSE"]=30000
    ["UDM-Pro"]=30000
    ["UDMPRO"]=30000
    ["UDW"]=30000
    ["UCG-Max"]=30000
    ["UCG-Ultra"]=30000
    ["UCG-Fiber"]=30000
    ["UXG-Max"]=30000
    ["UXG-Pro"]=30000
    ["UXG-Fiber"]=30000
)

# Conservative fallback for unknown devices
DEFAULT_MAXELEM=10000

# Device tier names for logging
declare -A DEVICE_TIER=(
    ["EFG"]="enterprise"
    ["UXG-Enterprise"]="enterprise"
    ["UDM-Pro-Max"]="pro"
    ["UDMPRO-Max"]="pro"
    ["UDM-SE"]="pro"
    ["UDMSE"]="pro"
    ["UDM-Pro"]="pro"
    ["UDMPRO"]="pro"
    ["UDW"]="pro"
    ["UCG-Max"]="pro"
    ["UCG-Ultra"]="pro"
    ["UCG-Fiber"]="pro"
    ["UXG-Max"]="pro"
    ["UXG-Pro"]="pro"
    ["UXG-Fiber"]="pro"
    ["UDM"]="consumer"
    ["UDR"]="consumer"
    ["UDR7"]="consumer"
    ["UX7"]="consumer"
    ["UX"]="unsupported"
    ["UXG-Lite"]="unsupported"
)

detect_device_model() {
    local model=""

    # Method 1: ubnt-device-info (most reliable on UniFi OS 3+)
    if command -v ubnt-device-info >/dev/null 2>&1; then
        model=$(ubnt-device-info model 2>/dev/null)
    fi

    # Method 2: /proc/ubnthal/system.info (available on most UniFi OS devices)
    if [ -z "$model" ] && [ -f /proc/ubnthal/system.info ]; then
        model=$(grep -i "shortname" /proc/ubnthal/system.info 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    fi

    # Method 3: /etc/unifi-os/unifi_version
    if [ -z "$model" ] && [ -f /etc/unifi-os/unifi_version ]; then
        model=$(grep -i "model" /etc/unifi-os/unifi_version 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    fi

    # Method 4: /sys/firmware/devicetree/base/model
    if [ -z "$model" ] && [ -f /sys/firmware/devicetree/base/model ]; then
        model=$(cat /sys/firmware/devicetree/base/model 2>/dev/null | tr -d '\0')
    fi

    # Method 5: Check dmesg for device identifiers (last resort)
    if [ -z "$model" ]; then
        for pattern in "EFG" "UXG-Enterprise" "UDM-Pro-Max" "UDMPRO-Max" "UDM-SE" "UDMSE" "UDM-Pro" "UDMPRO" "UDW" "UCG-Max" "UCG-Ultra" "UCG-Fiber" "UXG-Max" "UXG-Pro" "UXG-Fiber" "UDR7" "UDR" "UDM" "UX7" "UXG-Lite" "UX"; do
            if dmesg 2>/dev/null | grep -qi "\b${pattern}\b"; then
                model="$pattern"
                break
            fi
        done
    fi

    echo "$model"
}

# Normalize model name to a known key
# Handles variations like "UniFi Dream Machine SE" -> "UDM-SE"
normalize_model() {
    local model="$1"

    # If it already matches a known key, return it
    if [ -n "${DEVICE_MAXELEM[$model]+x}" ]; then
        echo "$model"
        return
    fi

    # Try matching against known keys (case-insensitive partial match)
    for key in "${!DEVICE_MAXELEM[@]}"; do
        # Check if model contains the key or key contains the model
        if [[ "${model^^}" == *"${key^^}"* ]]; then
            echo "$key"
            return
        fi
    done

    # Try common long-name to short-name mappings
    case "$model" in
        *"Dream Machine SE"*|*"Dream Machine Special"*)   echo "UDM-SE" ;;
        *"Dream Machine Pro Max"*)                         echo "UDM-Pro-Max" ;;
        *"Dream Machine Pro"*)                             echo "UDM-Pro" ;;
        *"Dream Machine"*)                                 echo "UDM" ;;
        *"Dream Router 7"*|*"Dream Router7"*)              echo "UDR7" ;;
        *"Dream Router"*)                                  echo "UDR" ;;
        *"Dream Wall"*)                                    echo "UDW" ;;
        *"Cloud Gateway Max"*)                             echo "UCG-Max" ;;
        *"Cloud Gateway Ultra"*)                           echo "UCG-Ultra" ;;
        *"Cloud Gateway Fiber"*)                           echo "UCG-Fiber" ;;
        *"Express 7"*|*"Express7"*)                        echo "UX7" ;;
        *"Express"*)                                       echo "UX" ;;
        *"Enterprise Fortress"*)                           echo "EFG" ;;
        *)                                                 echo "$model" ;;
    esac
}

get_safe_maxelem() {
    local model="$1"
    local normalized
    normalized=$(normalize_model "$model")

    local maxelem="${DEVICE_MAXELEM[$normalized]}"

    # Check memory optimized mode
    if [ "${MEMORY_OPTIMIZED:-false}" = "true" ]; then
        local mem_limit="${MEMORY_OPTIMIZED_LIMITS[$normalized]}"
        if [ -n "$mem_limit" ]; then
            maxelem="$mem_limit"
        fi
    fi

    echo "${maxelem:-$DEFAULT_MAXELEM}"
}

get_device_tier() {
    local model="$1"
    local normalized
    normalized=$(normalize_model "$model")
    echo "${DEVICE_TIER[$normalized]:-unknown}"
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

# Resolve the final maxelem value considering overrides and device detection
resolve_maxelem() {
    local model="$1"
    local normalized
    normalized=$(normalize_model "$model")
    local recommended
    recommended=$(get_safe_maxelem "$model")
    local tier
    tier=$(get_device_tier "$model")

    # Check for unsupported device
    if [ "$tier" = "unsupported" ]; then
        echo "ERROR" "0" "$recommended" "$normalized"
        return
    fi

    # MAXELEM_OVERRIDE takes precedence
    if [ -n "${MAXELEM_OVERRIDE:-}" ]; then
        if [ "$MAXELEM_OVERRIDE" -gt "$recommended" ] 2>/dev/null; then
            echo "OVERRIDE_HIGH" "$MAXELEM_OVERRIDE" "$recommended" "$normalized"
        else
            echo "OVERRIDE" "$MAXELEM_OVERRIDE" "$recommended" "$normalized"
        fi
        return
    fi

    echo "AUTO" "$recommended" "$recommended" "$normalized"
}

# Print startup log messages (called by setup.sh or standalone)
print_startup_info() {
    local model="$1"
    local normalized
    normalized=$(normalize_model "$model")
    local tier
    tier=$(get_device_tier "$model")
    local recommended
    recommended=$(get_safe_maxelem "$model")
    local mem_optimized="${MEMORY_OPTIMIZED:-false}"

    # Resolve final value
    local result
    result=$(resolve_maxelem "$model")
    local status final_value rec_value norm_model
    read -r status final_value rec_value norm_model <<< "$result"

    case "$status" in
        ERROR)
            echo "[ERROR] Detected device model: ${norm_model}"
            echo "[ERROR] This device does not support firewall groups/ipsets"
            echo "[ERROR] crowdsec-unifi-bouncer cannot run on this device"
            return 1
            ;;
        OVERRIDE_HIGH)
            echo "[INFO] Detected device model: ${norm_model:-Unknown} (${tier} tier)"
            echo "[INFO] Recommended ipset limit: $rec_value"
            echo "[WARNING] MAXELEM_OVERRIDE=$final_value exceeds recommended limit of $rec_value for ${norm_model:-Unknown}. This may cause instability."
            echo "[INFO] Memory optimized mode: $mem_optimized"
            echo "[INFO] Using ipset maxelem: $final_value (manual override)"
            ;;
        OVERRIDE)
            echo "[INFO] Detected device model: ${norm_model:-Unknown} (${tier} tier)"
            echo "[INFO] Recommended ipset limit: $rec_value"
            echo "[INFO] Memory optimized mode: $mem_optimized"
            echo "[INFO] Using ipset maxelem: $final_value (manual override)"
            ;;
        AUTO)
            if [ -z "$model" ]; then
                echo "[WARNING] Could not detect device model, using conservative limit of $DEFAULT_MAXELEM"
                echo "[INFO] Set MAXELEM_OVERRIDE to specify a higher limit if needed"
            else
                echo "[INFO] Detected device model: ${norm_model} (${tier} tier)"
                echo "[INFO] Recommended ipset limit: $rec_value"
                echo "[INFO] Memory optimized mode: $mem_optimized"
            fi
            echo "[INFO] Using ipset maxelem: $final_value"
            ;;
    esac
}

# Main execution when run directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    DETECTED_MODEL=$(detect_device_model)
    DETECTED_NORMALIZED=$(normalize_model "$DETECTED_MODEL")
    TOTAL_MEM=$(get_total_memory_mb)

    echo "=== CrowdSec UniFi Bouncer - Device Detection ==="
    echo ""
    echo "Raw model string: ${DETECTED_MODEL:-<not detected>}"
    echo "Normalized model: ${DETECTED_NORMALIZED:-Unknown}"
    echo "Device tier:      $(get_device_tier "$DETECTED_MODEL")"
    echo "RAM:              ${TOTAL_MEM}MB"
    echo ""

    # Show what would happen at startup
    echo "--- Startup Output ---"
    print_startup_info "$DETECTED_MODEL"
    echo ""

    SAFE_MAXELEM=$(get_safe_maxelem "$DETECTED_MODEL")
    echo "--- Configuration ---"
    echo "Recommended maxelem:      $SAFE_MAXELEM"
    echo "Recommended max_decisions: $((SAFE_MAXELEM > 2000 ? SAFE_MAXELEM - 2000 : 0))"

    if [ -n "${MAXELEM_OVERRIDE:-}" ]; then
        echo "MAXELEM_OVERRIDE:         $MAXELEM_OVERRIDE"
    fi
    if [ "${MEMORY_OPTIMIZED:-false}" = "true" ]; then
        echo "MEMORY_OPTIMIZED:         true"
    fi

    echo ""
    echo "--- All Known Devices ---"
    printf "%-20s %-12s %-10s %-10s\n" "Model" "Tier" "Default" "Mem Opt"
    printf "%-20s %-12s %-10s %-10s\n" "-----" "----" "-------" "-------"
    for key in $(echo "${!DEVICE_MAXELEM[@]}" | tr ' ' '\n' | sort); do
        local_tier="${DEVICE_TIER[$key]:-unknown}"
        local_limit="${DEVICE_MAXELEM[$key]}"
        local_mem="${MEMORY_OPTIMIZED_LIMITS[$key]:-—}"
        printf "%-20s %-12s %-10s %-10s\n" "$key" "$local_tier" "$local_limit" "$local_mem"
    done
fi

# Export variables when sourced
DETECTED_MODEL=$(detect_device_model)
DETECTED_NORMALIZED=$(normalize_model "$DETECTED_MODEL")
SAFE_MAXELEM=$(get_safe_maxelem "$DETECTED_MODEL")
DEVICE_TIER_NAME=$(get_device_tier "$DETECTED_MODEL")

# Resolve final maxelem (considers MAXELEM_OVERRIDE and MEMORY_OPTIMIZED)
_resolve_result=$(resolve_maxelem "$DETECTED_MODEL")
read -r _resolve_status FINAL_MAXELEM _resolve_rec _resolve_norm <<< "$_resolve_result"

# For backward compatibility: if MAXELEM_OVERRIDE is set, use it; otherwise use auto-detected
if [ "$_resolve_status" = "ERROR" ]; then
    UNSUPPORTED_DEVICE=true
    FINAL_MAXELEM=0
else
    UNSUPPORTED_DEVICE=false
fi

# Legacy variable name compatibility
RECOMMENDED_SIDECAR_CAP=$((FINAL_MAXELEM > 2000 ? FINAL_MAXELEM - 2000 : 0))

export DETECTED_MODEL DETECTED_NORMALIZED SAFE_MAXELEM DEVICE_TIER_NAME
export FINAL_MAXELEM UNSUPPORTED_DEVICE RECOMMENDED_SIDECAR_CAP
