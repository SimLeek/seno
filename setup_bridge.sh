#!/bin/bash

# Exit on error, undefined variable, or pipe failure
set -euo pipefail

# Suppress perl locale warnings
export LC_ALL=C

BRIDGE_NAME="aibr0"
PRIMARY_IF=""
FIREWALL_STATUS_FILE="/tmp/aibr0_firewall_status"

trap "echo 'Script failed. Run uninstall_bridge.sh to remove the bridge.'" ERR EXIT

command -v sudo >/dev/null 2>&1 || {
    echo "[ERROR] command -v sudo failed. Install sudo and run as non-root user."
    exit 1
}

get_primary_interface() {
    local primary_if
    primary_if=$(nmcli device status | awk '$3 == "connected" && $2 == "ethernet" { print $1; exit }')
    if [[ -z "$primary_if" ]]; then
        echo "[ERROR] No connected Ethernet interface found"
        exit 1
    fi
    PRIMARY_IF="$primary_if"
    echo "[*] Primary interface: $PRIMARY_IF"
}

generate_ip_from_mac() {
    local mac
    mac=$(cat /sys/class/net/"$PRIMARY_IF"/address) || {
        echo "[ERROR] Failed to read MAC address from /sys/class/net/$PRIMARY_IF/address"
        exit 1
    }
    local ip_suffix
    ip_suffix=$(echo "$mac" | md5sum | cut -c1-2) || {
        echo "[ERROR] Failed to generate IP suffix from MAC address"
        exit 1
    }
    ip_suffix=$((16#$ip_suffix % 200 + 10))  # Range 10-209
    echo "192.168.200.$ip_suffix"
}

bridge_exists() {
    nmcli connection show "$BRIDGE_NAME" &>/dev/null
}

configure_firewall() {
    echo "[*] Configuring firewall for bridge '$BRIDGE_NAME' and interface '$PRIMARY_IF'..."

    # Initialize firewall status file
    echo "none" > "$FIREWALL_STATUS_FILE"

    # Check for ufw
    if command -v ufw &>/dev/null; then
        echo "[*] Detected ufw firewall"
        sudo ufw allow in on "$BRIDGE_NAME" || {
            echo "[ERROR] Failed to configure ufw rules for $BRIDGE_NAME"
            exit 1
        }
        sudo ufw allow in on "$PRIMARY_IF" || {
            echo "[ERROR] Failed to configure ufw rules for $PRIMARY_IF"
            exit 1
        }
        echo "ufw" > "$FIREWALL_STATUS_FILE"
        echo "[+] ufw rules added to allow all traffic on $BRIDGE_NAME and $PRIMARY_IF"
    # Check for firewalld
    elif command -v firewall-cmd &>/dev/null; then
        echo "[*] Detected firewalld"
        sudo firewall-cmd --permanent --zone=trusted --add-interface="$BRIDGE_NAME" || {
            echo "[ERROR] Failed to add $BRIDGE_NAME to trusted zone"
            exit 1
        }
        sudo firewall-cmd --permanent --zone=trusted --add-interface="$PRIMARY_IF" || {
            echo "[ERROR] Failed to add $PRIMARY_IF to trusted zone"
            exit 1
        }
        sudo firewall-cmd --reload || {
            echo "[ERROR] Failed to reload firewalld"
            exit 1
        }
        echo "firewalld" > "$FIREWALL_STATUS_FILE"
        echo "[+] firewalld rules added to allow all traffic on $BRIDGE_NAME and $PRIMARY_IF"
    else
        echo "[WARNING] No supported firewall (ufw or firewalld) detected. If you have a manual configuration, you may need to allow traffic through $BRIDGE_NAME and $PRIMARY_IF."
    fi
}

check_networkmanager() {
  if ! command -v nmcli &>/dev/null; then
    echo "[*] NetworkManager not found. Installing..."
    if command -v pacman &>/dev/null; then
        echo "[*] Detected pacman-based system"
        if ! pacman -Q networkmanager &>/dev/null; then
            # Check internet before installing
            sudo pacman -S --noconfirm networkmanager || {
                echo "[ERROR] Failed to install networkmanager via pacman."
                exit 1
            }
        else
            echo "[+] networkmanager already installed."
        fi

    elif command -v apt-get &>/dev/null; then
        echo "[*] Detected apt-based system"
        if ! dpkg -s network-manager &>/dev/null; then
            sudo apt-get install -y network-manager || {
                echo "[ERROR] Failed to install network-manager via apt-get."
                exit 1
            }
        else
            echo "[+] network-manager already installed."
        fi

    else
        echo "[ERROR] Unsupported package manager. Only pacman and apt-get are supported."
        exit 1
    fi
  fi

  systemctl is-active --quiet NetworkManager || {
      sudo systemctl start NetworkManager || {
          echo "[ERROR] sudo systemctl start NetworkManager failed."
          exit 1
      }
      sleep 2
  }
}

scan_network() {
    echo "[*] Scanning network for other computers..."

    local network_base="192.168.200"
    local detected_ips=()

    echo -n "[*] Scanning"
    for i in {10..250}; do
        local test_ip="${network_base}.$i"
        if ping -c1 -W1 "$test_ip" &>/dev/null; then
            detected_ips+=("$test_ip")
        fi
        # Show progress
        if (( i % 30 == 0 )); then
            echo -n "."
        fi
    done
    echo ""

    echo "${detected_ips[@]}"
}

find_available_ip() {
    local detected_ips=("$@")
    local proposed_ip
    proposed_ip=$(generate_ip_from_mac) || {
            echo "[ERROR] Failed to generate proposed IP"
            exit 1
        }
    local network_base="192.168.200"

    # Check if proposed IP conflicts
    local ip_conflict=false
    for detected_ip in "${detected_ips[@]}"; do
        if [[ "$detected_ip" == "$proposed_ip" ]]; then
            ip_conflict=true
            break
        fi
    done

    if [[ "$ip_conflict" == true ]]; then
        echo "[!] IP conflict detected with $proposed_ip. Finding alternative..."

        # Find next available IP
        for i in {10..250}; do
            local test_ip="${network_base}.$i"
            local ip_taken=false

            for detected_ip in "${detected_ips[@]}"; do
                if [[ "$test_ip" == "$detected_ip" ]]; then
                    ip_taken=true
                    break
                fi
            done

            if [[ "$ip_taken" == false ]]; then
                echo "$test_ip"
                return
            fi
        done

        echo "[ERROR] No available IP addresses found!"
        exit 1
    else
        echo "$proposed_ip"
    fi
}

verify_and_retry_ip() {
    local assigned_ip="$1"
    local max_retries=3
    local attempt=1
    local network_base="192.168.200"

    while [[ $attempt -le $max_retries ]]; do
        echo "[*] Verifying IP $assigned_ip (attempt $attempt of $max_retries)..."

        # Re-scan network to check for conflicts
        local detected_ips
        mapfile -t detected_ips < <(scan_network)

        local ip_conflict=false
        for detected_ip in "${detected_ips[@]}"; do
            if [[ "$detected_ip" == "$assigned_ip" ]]; then
                ip_conflict=true
                break
            fi
        done

        if [[ "$ip_conflict" == false ]]; then
            echo "[+] IP $assigned_ip verified as unique"
            echo "$assigned_ip"
            return
        fi

        echo "[!] IP conflict detected with $assigned_ip. Selecting new IP..."

        # Find new IP
        local new_ip=""
        for i in {10..250}; do
            local test_ip="${network_base}.$i"
            local ip_taken=false

            for detected_ip in "${detected_ips[@]}"; do
                if [[ "$test_ip" == "$detected_ip" ]]; then
                    ip_taken=true
                    break
                fi
            done

            if [[ "$ip_taken" == false ]]; then
                new_ip="$test_ip"
                break
            fi
        done

        if [[ -z "$new_ip" ]]; then
            echo "[ERROR] No available IP addresses found on attempt $attempt!"
            if [[ $attempt -eq $max_retries ]]; then
                echo "[ERROR] Max retries reached. Aborting."
                exit 1
            fi
            ((attempt++))
            continue
        fi

        echo "[*] Assigning new IP: $new_ip"

        # Update bridge IP
        sudo nmcli connection modify "$BRIDGE_NAME" ipv4.addresses "$new_ip/24" || {
            echo "[ERROR] Failed to update bridge IP to $new_ip"
            exit 1
        }
        sudo nmcli connection up "$BRIDGE_NAME" || {
            echo "[ERROR] Failed to re-activate bridge '$BRIDGE_NAME'"
            exit 1
        }

        # Wait for bridge to stabilize
        sleep $((RANDOM % 1501 + 500))e-3  # Random delay 0.5-2 seconds
        assigned_ip="$new_ip"
        ((attempt++))
    done

    echo "[ERROR] Failed to find a unique IP after $max_retries attempts!"
    exit 1
}

setup_network() {
    echo "==============================================="
    echo "    MULTI-COMPUTER NETWORK SETUP"
    echo "==============================================="
    echo ""

    # Check if bridge already exists
    if bridge_exists; then
        echo "[+] Network bridge '$BRIDGE_NAME' already exists!"

        # Get current bridge IP
        local current_ip
        current_ip=$(ip addr show "$BRIDGE_NAME" | grep -o 'inet [0-9.]*' | cut -d' ' -f2) || {
            echo "[ERROR] Failed to retrieve current bridge IP"
            exit 1
        }
        echo "[*] Current IP: $current_ip"

        # Scan for remote computers
        local remote_ips
        mapfile -t remote_ips < <(scan_network)

        # Filter out our own IP
        local filtered_ips=()
        for ip in "${remote_ips[@]}"; do
            if [[ "$ip" != "$current_ip" ]]; then
                filtered_ips+=("$ip")
            fi
        done

        if [[ ${#filtered_ips[@]} -gt 0 ]]; then
            echo "[+] Found ${#filtered_ips[@]} remote computer(s): ${filtered_ips[*]}"

            # Test connectivity
            echo "[*] Testing connectivity..."
            local reachable=0
            for remote_ip in "${filtered_ips[@]}"; do
                echo -n "    Testing $remote_ip... "
                if ping -c1 -W2 "$remote_ip" &>/dev/null; then
                    echo "CONNECTED"
                    ((reachable++))
                else
                    echo "NOT REACHABLE"
                fi
            done

            echo ""
            echo "[+] Network ready! Connected to $reachable remote computer(s)"
        else
            echo "[!] No remote computers detected"
        fi

        echo ""
        echo "Network is ready for use!"
        return
    fi

    echo "Setting up network configuration..."
    echo ""

    check_networkmanager

    get_primary_interface

    configure_firewall

    # Scan network for existing hosts
    local detected_ips
    mapfile -t detected_ips < <(scan_network)

    if [[ ${#detected_ips[@]} -gt 0 ]]; then
        echo "[+] Found ${#detected_ips[@]} existing host(s): ${detected_ips[*]}"
    else
        echo "[!] No other hosts detected (they may not be configured yet)"
    fi

    # Find available IP
    local local_ip
    local_ip=$(find_available_ip "${detected_ips[@]}") || {
        echo "[ERROR] Failed to find available IP"
        exit 1
    }
    echo "[*] Assigned IP: $local_ip"

    echo ""
    echo "[*] Network configuration:"
    echo "    Local IP: $local_ip"
    echo "    Bridge: $BRIDGE_NAME"
    echo "    Interface: $PRIMARY_IF"
    echo ""

    read -r -p "Apply this network configuration? [Y/n]: " confirm
    if [[ "${confirm,,}" == "n" ]]; then
        echo "Aborted."
        exit 0
    fi

    echo "[*] Creating network bridge..."

    # Create bridge
    echo "[*] Creating bridge '$BRIDGE_NAME'..."
    sudo nmcli connection add type bridge ifname "$BRIDGE_NAME" con-name "$BRIDGE_NAME" \
        ipv4.method manual ipv4.addresses "$local_ip/24" autoconnect yes

    # Add slave
    echo "[*] Adding interface '$PRIMARY_IF' to bridge..."
    sudo nmcli connection add type ethernet ifname "$PRIMARY_IF" master "$BRIDGE_NAME" \
        con-name "${PRIMARY_IF}-slave" autoconnect yes

    # Activate bridge
    echo "[*] Activating bridge..."
    sudo nmcli connection up "$BRIDGE_NAME"

    # Wait for bridge to initialize
    echo "[*] Waiting for bridge to initialize..."
    sleep 3

    # Verify IP and retry if necessary
    local verified_ip
    verified_ip=$(verify_and_retry_ip "$local_ip") || {
        echo "[ERROR] Failed to verify or assign a unique IP"
        exit 1
    }
    local_ip="$verified_ip"

    # Verify bridge
    if ! ip addr show "$BRIDGE_NAME" | grep -q "$local_ip/24"; then
        echo "[ERROR] Bridge verification failed"
        exit 1
    fi

    echo "[+] Bridge created successfully!"

    # Test connectivity to existing hosts
    if [[ ${#detected_ips[@]} -gt 0 ]]; then
        echo ""
        echo "[*] Testing connectivity to existing computers..."
        local reachable=0
        for remote_ip in "${detected_ips[@]}"; do
            echo -n "    Testing $remote_ip... "
            if ping -c1 -W2 "$remote_ip" &>/dev/null; then
                echo "CONNECTED"
                ((reachable++))
            else
                echo "NOT REACHABLE (may still be configuring)"
            fi
        done

        echo ""
        if [[ $reachable -gt 0 ]]; then
            echo "[+] Successfully connected to $reachable remote computer(s)"
        else
            echo "[!] No remote computers reachable yet"
        fi
    fi

    echo ""
    echo "==============================================="
    echo "    NETWORK SETUP COMPLETE!"
    echo "==============================================="
    echo ""
    echo "[+] Your computer is configured with:"
    echo "    • IP Address: $local_ip"
    echo "    • Bridge Interface: $BRIDGE_NAME"
    echo "    • Primary Interface: $PRIMARY_IF"
    if [[ ${#detected_ips[@]} -gt 0 ]]; then
        echo "    • Detected Computers: ${detected_ips[*]}"
    fi
    echo ""
    echo "Network is ready for use!"
}

# Main execution
setup_network