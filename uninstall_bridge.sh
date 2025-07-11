#!/bin/bash

# Exit on error, undefined variable, or pipe failure
set -euo pipefail

# Suppress perl locale warnings
export LC_ALL=C

BRIDGE_NAME="aibr0"
FIREWALL_STATUS_FILE="/tmp/aibr0_firewall_status"

# Ensure sudo is available
command -v sudo >/dev/null 2>&1 || {
    echo "[ERROR] command -v sudo failed. Install sudo and run as non-root user."
    exit 1
}

# Get primary interface from bridge
get_primary_interface() {
    local primary_if
    primary_if=$(nmcli connection show | grep "${BRIDGE_NAME}" | grep ethernet | awk '{print $1}' | cut -d'-' -f1)
    if [[ -z "$primary_if" ]]; then
        echo "[WARNING] No enslaved Ethernet interface found for bridge '$BRIDGE_NAME'"
        return 1
    fi
    echo "$primary_if"
}

# Remove firewall rules
remove_firewall_rules() {
    local primary_if="$1"
    if [[ ! -f "$FIREWALL_STATUS_FILE" ]]; then
        echo "[*] No firewall status file found. Assuming no firewall rules were added."
        return 0
    fi

    local firewall_type
    firewall_type=$(cat "$FIREWALL_STATUS_FILE") || {
        echo "[WARNING] Failed to read firewall status file. Assuming no rules to remove."
        return 0
    }

    if [[ "$firewall_type" == "ufw" ]]; then
        echo "[*] Removing ufw rules for $BRIDGE_NAME and $primary_if..."
        sudo ufw delete allow in on "$BRIDGE_NAME" 2>/dev/null || {
            echo "[WARNING] Failed to remove ufw rule for $BRIDGE_NAME (may not exist)"
        }
        sudo ufw delete allow in on "$primary_if" 2>/dev/null || {
            echo "[WARNING] Failed to remove ufw rule for $primary_if (may not exist)"
        }
        echo "[+] ufw rules removed"
    elif [[ "$firewall_type" == "firewalld" ]]; then
        echo "[*] Removing firewalld rules for $BRIDGE_NAME and $primary_if..."
        sudo firewall-cmd --permanent --zone=trusted --remove-interface="$BRIDGE_NAME" 2>/dev/null || {
            echo "[WARNING] Failed to remove firewalld rule for $BRIDGE_NAME (may not exist)"
        }
        sudo firewall-cmd --permanent --zone=trusted --remove-interface="$primary_if" 2>/dev/null || {
            echo "[WARNING] Failed to remove firewalld rule for $primary_if (may not exist)"
        }
        sudo firewall-cmd --reload || {
            echo "[ERROR] Failed to reload firewalld"
            exit 1
        }
        echo "[+] firewalld rules removed"
    else
        echo "[*] No firewall rules were added during setup (type: $firewall_type)"
    fi

    # Clean up status file
    rm -f "$FIREWALL_STATUS_FILE"
}

uninstall_network() {
    echo "==============================================="
    echo "    UNINSTALLING NETWORK BRIDGE"
    echo "==============================================="
    echo ""

    # Check if bridge exists
    if ! nmcli connection show "$BRIDGE_NAME" &>/dev/null; then
        echo "[*] No bridge '$BRIDGE_NAME' found. Nothing to uninstall."
        # Clean up firewall status file if it exists
        if [[ -f "$FIREWALL_STATUS_FILE" ]]; then
            echo "[*] Cleaning up firewall status file..."
            rm -f "$FIREWALL_STATUS_FILE"
        fi
        echo ""
        echo "[+] Uninstallation complete!"
        return
    fi

    # Get primary interface
    local primary_if
    primary_if=$(get_primary_interface) || primary_if="unknown"

    # Remove bridge and slave connection
    echo "[*] Removing bridge '$BRIDGE_NAME'..."
    sudo nmcli connection delete "$BRIDGE_NAME" || {
        echo "[ERROR] Failed to delete bridge '$BRIDGE_NAME'"
        exit 1
    }

    if [[ "$primary_if" != "unknown" ]]; then
        echo "[*] Removing slave connection '${primary_if}-slave'..."
        sudo nmcli connection delete "${primary_if}-slave" 2>/dev/null || {
            echo "[WARNING] Failed to delete slave connection '${primary_if}-slave' (may not exist)"
        }
    fi

    # Remove firewall rules
    if [[ "$primary_if" != "unknown" ]]; then
        remove_firewall_rules "$primary_if"
    else
        echo "[WARNING] Skipping firewall rule removal due to unknown primary interface"
    fi

    echo ""
    echo "==============================================="
    echo "    UNINSTALLATION COMPLETE"
    echo "==============================================="
    echo "[+] Bridge '$BRIDGE_NAME' and associated configurations removed."
}

# Main execution
uninstall_network