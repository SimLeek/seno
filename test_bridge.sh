#!/bin/bash

# Exit on error, undefined variable, or pipe failure
set -euo pipefail

# Suppress perl locale warnings
export LC_ALL=C

BRIDGE_NAME="aibr0"
PORT=12345

# Ensure netcat is available
command -v nc >/dev/null 2>&1 || {
    echo "[ERROR] netcat (nc) not found. Installing..."
    if command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm nmap || {
            echo "[ERROR] Failed to install nmap (netcat) via pacman."
            exit 1
        }
    elif command -v apt-get &>/dev/null; then
        sudo apt-get install -y netcat-openbsd || {
            echo "[ERROR] Failed to install netcat-openbsd via apt-get."
            exit 1
        }
    else
        echo "[ERROR] Unsupported package manager. Only pacman and apt-get are supported."
        exit 1
    fi
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
        if (( i % 30 == 0 )); then
            echo -n "."
        fi
    done
    echo ""

    printf '%s\n' "${detected_ips[@]}"
}

test_network() {
    echo "==============================================="
    echo "    NETWORK COMMUNICATION TEST"
    echo "==============================================="
    echo ""

    # Get current bridge IP
    local current_ip
    current_ip=$(ip addr show "$BRIDGE_NAME" | grep -o 'inet [0-9.]*' | cut -d' ' -f2) || {
        echo "[ERROR] Failed to retrieve current bridge IP. Ensure bridge '$BRIDGE_NAME' is configured."
        exit 1
    }
    echo "[*] Current IP: $current_ip"

    # Start listener in the background
    echo "[*] Starting listener on port $PORT..."
    nc -l -p "$PORT" -q 1 | while read -r message; do
        if [[ -n "$message" ]]; then
            echo "[+] Received random number '$message' from an IP address"
        fi
    done &
    local listener_pid=$!
    sleep 1  # Give listener time to start

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

        # Generate random number
        local random_number=$((RANDOM % 10000))
        echo "[*] Sending random number '$random_number' to all other IPs on bridge..."

        # Send random number to each remote IP
        for remote_ip in "${filtered_ips[@]}"; do
            echo -n "    Sending to $remote_ip... "
            if echo "$random_number" | nc -w 2 "$remote_ip" "$PORT" >/dev/null 2>&1; then
                echo "SENT"
            else
                echo "FAILED"
            fi
        done
    else
        echo "[!] No remote computers detected"
    fi

    # Wait briefly to allow receiving messages
    echo "[*] Waiting for incoming messages (5 seconds)..."
    sleep 5

    # Clean up listener
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    echo ""
    echo "==============================================="
    echo "    NETWORK TEST COMPLETE"
    echo "==============================================="
}

# Main execution
test_network