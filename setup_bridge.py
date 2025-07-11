#!/usr/bin/env python3

import subprocess
import sys
import os
import hashlib
import time
import random
import concurrent.futures
import getpass
from pathlib import Path

BRIDGE_NAME = "aibr0"
FIREWALL_STATUS_FILE = "/tmp/aibr0_firewall_status"


class NetworkSetup:
    def __init__(self):
        self.primary_if = ""
        self.bridge_name = BRIDGE_NAME
        self.sudo_password = None

    def check_sudo(self):
        """Check if sudo is available and get password"""
        try:
            subprocess.run(["sudo", "--version"], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[ERROR] sudo not available. Install sudo and run as non-root user.")
            sys.exit(1)

        # Check if we can run sudo without password
        try:
            subprocess.run(["sudo", "-n", "true"], check=True, capture_output=True)
            print("[*] Passwordless sudo detected")
            return
        except subprocess.CalledProcessError:
            pass

        # Get password for sudo
        print("[*] This script requires sudo privileges.")
        self.sudo_password = getpass.getpass("Enter sudo password: ")

    def run_command(self, cmd, check=True, capture_output=True):
        """Run a command and return the result"""
        try:
            # If it's a sudo command and we have a password, use it
            if cmd.startswith("sudo ") and self.sudo_password:
                # Use echo to pipe password to sudo -S
                full_cmd = f"echo '{self.sudo_password}' | sudo -S {cmd[5:]}"
                result = subprocess.run(full_cmd, shell=True, check=check,
                                        capture_output=capture_output, text=True)
            else:
                result = subprocess.run(cmd, shell=True, check=check,
                                        capture_output=capture_output, text=True)
            return result
        except subprocess.CalledProcessError as e:
            if check:
                print(f"[ERROR] Command failed: {cmd}")
                print(f"Error: {e.stderr if e.stderr else str(e)}")
                raise
            return e

    def get_primary_interface(self):
        """Get the primary connected ethernet interface"""
        try:
            result = self.run_command("nmcli device status")
            lines = result.stdout.strip().split('\n')[1:]  # Skip header

            for line in lines:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "connected" and parts[1] == "ethernet":
                    self.primary_if = parts[0]
                    print(f"[*] Primary interface: {self.primary_if}")
                    return

            print("[ERROR] No connected Ethernet interface found")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Failed to get primary interface: {e}")
            sys.exit(1)

    def generate_ip_from_mac(self):
        """Generate IP address based on MAC address"""
        try:
            mac_file = f"/sys/class/net/{self.primary_if}/address"
            with open(mac_file, 'r') as f:
                mac = f.read().strip()

            # Generate IP suffix from MAC
            ip_suffix = int(hashlib.md5(mac.encode()).hexdigest()[:2], 16) % 200 + 10
            return f"192.168.200.{ip_suffix}"
        except Exception as e:
            print(f"[ERROR] Failed to generate IP from MAC: {e}")
            sys.exit(1)

    def bridge_exists(self):
        """Check if bridge connection exists"""
        try:
            self.run_command(f"nmcli connection show {self.bridge_name}")
            return True
        except subprocess.CalledProcessError:
            return False

    def ping_ip(self, ip, timeout=0.1):
        """Ping a single IP address"""
        try:
            subprocess.run(f"ping -c1 -W{timeout} {ip}",
                           shell=True, check=True, capture_output=True)
            return ip
        except subprocess.CalledProcessError:
            return None

    def scan_network(self, show_progress=True):
        """Scan network for existing hosts using parallel ping"""
        if show_progress:
            print("[*] Scanning network for other computers...")

        network_base = "192.168.200"
        ips_to_scan = [f"{network_base}.{i}" for i in range(10, 251)]
        found_ips = []

        # Use ThreadPoolExecutor for parallel pinging
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            if show_progress:
                print("[*] Starting parallel scan...")

            # Submit all ping tasks
            future_to_ip = {executor.submit(self.ping_ip, ip): ip for ip in ips_to_scan}

            completed = 0
            total = len(ips_to_scan)

            for future in concurrent.futures.as_completed(future_to_ip):
                completed += 1
                result = future.result()

                if result:
                    found_ips.append(result)
                    if show_progress:
                        print(f"\r[*] Scanning... {completed}/{total} - Found: {len(found_ips)}",
                              end="", flush=True)
                elif show_progress and completed % 20 == 0:
                    print(f"\r[*] Scanning... {completed}/{total} - Found: {len(found_ips)}",
                          end="", flush=True)

        if show_progress:
            print()  # New line

        print (f"FOUND IPs {found_ips}")
        return sorted(found_ips)

    def find_available_ip(self, detected_ips):
        """Find an available IP address"""
        proposed_ip = self.generate_ip_from_mac()

        if proposed_ip not in detected_ips:
            return proposed_ip

        print(f"[!] IP conflict detected with {proposed_ip}. Finding alternative...")

        # Find next available IP
        for i in range(10, 251):
            test_ip = f"192.168.200.{i}"
            if test_ip not in detected_ips:
                return test_ip

        print("[ERROR] No available IP addresses found!")
        sys.exit(1)

    def configure_firewall(self):
        """Configure firewall rules"""
        print(f"[*] Configuring firewall for bridge '{self.bridge_name}' and interface '{self.primary_if}'...")

        # Initialize firewall status file
        with open(FIREWALL_STATUS_FILE, 'w') as f:
            f.write("none")

        # Check for ufw
        try:
            self.run_command("ufw --version")
            print("[*] Detected ufw firewall")

            self.run_command(f"sudo ufw allow in on {self.bridge_name}")
            self.run_command(f"sudo ufw allow in on {self.primary_if}")

            with open(FIREWALL_STATUS_FILE, 'w') as f:
                f.write("ufw")

            print(f"[+] ufw rules added to allow all traffic on {self.bridge_name} and {self.primary_if}")
            return
        except subprocess.CalledProcessError:
            pass

        # Check for firewalld
        try:
            self.run_command("firewall-cmd --version")
            print("[*] Detected firewalld")

            self.run_command(f"sudo firewall-cmd --permanent --zone=trusted --add-interface={self.bridge_name}")
            self.run_command(f"sudo firewall-cmd --permanent --zone=trusted --add-interface={self.primary_if}")
            self.run_command("sudo firewall-cmd --reload")

            with open(FIREWALL_STATUS_FILE, 'w') as f:
                f.write("firewalld")

            print(f"[+] firewalld rules added to allow all traffic on {self.bridge_name} and {self.primary_if}")
            return
        except subprocess.CalledProcessError:
            pass

        print(f"[WARNING] No supported firewall (ufw or firewalld) detected. "
              f"If you have a manual configuration, you may need to allow traffic through "
              f"{self.bridge_name} and {self.primary_if}.")

    def check_networkmanager(self):
        """Check and install NetworkManager if needed"""
        try:
            self.run_command("nmcli --version")
            return
        except subprocess.CalledProcessError:
            pass

        print("[*] NetworkManager not found. Installing...")

        # Check for pacman
        try:
            self.run_command("pacman --version")
            print("[*] Detected pacman-based system")

            try:
                self.run_command("pacman -Q networkmanager")
                print("[+] networkmanager already installed.")
            except subprocess.CalledProcessError:
                self.run_command("sudo pacman -S --noconfirm networkmanager")
        except subprocess.CalledProcessError:
            pass

        # Check for apt-get
        try:
            self.run_command("apt-get --version")
            print("[*] Detected apt-based system")

            try:
                self.run_command("dpkg -s network-manager")
                print("[+] network-manager already installed.")
            except subprocess.CalledProcessError:
                self.run_command("sudo apt-get install -y network-manager")
        except subprocess.CalledProcessError:
            print("[ERROR] Unsupported package manager. Only pacman and apt-get are supported.")
            sys.exit(1)

        # Start NetworkManager
        try:
            self.run_command("systemctl is-active --quiet NetworkManager")
        except subprocess.CalledProcessError:
            self.run_command("sudo systemctl start NetworkManager")
            time.sleep(2)

    def test_connectivity(self, ips):
        """Test connectivity to remote IPs"""
        if not ips:
            return 0

        print("[*] Testing connectivity...")
        reachable = 0

        for remote_ip in ips:
            print(f"    Testing {remote_ip}... ", end="", flush=True)
            if self.ping_ip(remote_ip, timeout=2):
                print("CONNECTED")
                reachable += 1
            else:
                print("NOT REACHABLE")

        return reachable

    def setup_network(self):
        """Main network setup function"""
        print("===============================================")
        print("    MULTI-COMPUTER NETWORK SETUP")
        print("===============================================")
        print()

        self.check_sudo()

        # Check if bridge already exists
        if self.bridge_exists():
            print(f"[+] Network bridge '{self.bridge_name}' already exists!")

            # Get current bridge IP
            try:
                result = self.run_command(f"ip addr show {self.bridge_name}")
                current_ip = None
                for line in result.stdout.split('\n'):
                    if 'inet ' in line:
                        current_ip = line.split()[1].split('/')[0]
                        break

                if current_ip:
                    print(f"[*] Current IP: {current_ip}")

                    # Scan for remote computers
                    remote_ips = self.scan_network()

                    # Filter out our own IP
                    filtered_ips = [ip for ip in remote_ips if ip != current_ip]

                    if filtered_ips:
                        print(f"[+] Found {len(filtered_ips)} remote computer(s): {', '.join(filtered_ips)}")
                        reachable = self.test_connectivity(filtered_ips)
                        print(f"[+] Network ready! Connected to {reachable} remote computer(s)")
                    else:
                        print("[!] No remote computers detected")
                else:
                    print("[ERROR] Could not determine current bridge IP")
            except Exception as e:
                print(f"[ERROR] Failed to get bridge info: {e}")

            self.configure_firewall()

            print("\nNetwork is ready for use!")
            return

        print("Setting up network configuration...")
        print()

        self.check_networkmanager()
        self.get_primary_interface()
        self.configure_firewall()

        # Scan network for existing hosts
        detected_ips = self.scan_network()

        if detected_ips:
            print(f"[+] Found {len(detected_ips)} existing host(s): {', '.join(detected_ips)}")
        else:
            print("[!] No other hosts detected (they may not be configured yet)")

        # Find available IP
        local_ip = self.find_available_ip(detected_ips)
        print(f"[*] Assigned IP: {local_ip}")

        print()
        print("[*] Network configuration:")
        print(f"    Local IP: {local_ip}")
        print(f"    Bridge: {self.bridge_name}")
        print(f"    Interface: {self.primary_if}")
        print()

        confirm = input("Apply this network configuration? [Y/n]: ").lower()
        if confirm == 'n':
            print("Aborted.")
            return

        print("[*] Creating network bridge...")

        # Create bridge
        print(f"[*] Creating bridge '{self.bridge_name}'...")
        self.run_command(f"sudo nmcli connection add type bridge ifname {self.bridge_name} "
                         f"con-name {self.bridge_name} ipv4.method manual "
                         f"ipv4.addresses {local_ip}/24 autoconnect yes")

        # Add slave
        print(f"[*] Adding interface '{self.primary_if}' to bridge...")
        self.run_command(f"sudo nmcli connection add type ethernet ifname {self.primary_if} "
                         f"master {self.bridge_name} con-name {self.primary_if}-slave autoconnect yes")

        # Activate bridge
        print("[*] Activating bridge...")
        self.run_command(f"sudo nmcli connection up {self.bridge_name}")

        # Wait for bridge to initialize
        print("[*] Waiting for bridge to initialize...")
        time.sleep(3)

        # Verify bridge
        try:
            result = self.run_command(f"ip addr show {self.bridge_name}")
            if f"{local_ip}/24" not in result.stdout:
                print("[ERROR] Bridge verification failed")
                sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Bridge verification failed: {e}")
            sys.exit(1)

        print("[+] Bridge created successfully!")

        # Test connectivity to existing hosts
        if detected_ips:
            reachable = self.test_connectivity(detected_ips)

            if reachable > 0:
                print(f"[+] Successfully connected to {reachable} remote computer(s)")
            else:
                print("[!] No remote computers reachable yet")

        print()
        print("===============================================")
        print("    NETWORK SETUP COMPLETE!")
        print("===============================================")
        print()
        print("[+] Your computer is configured with:")
        print(f"    • IP Address: {local_ip}")
        print(f"    • Bridge Interface: {self.bridge_name}")
        print(f"    • Primary Interface: {self.primary_if}")
        if detected_ips:
            print(f"    • Detected Computers: {', '.join(detected_ips)}")
        print()
        print("Network is ready for use!")


def main():
    try:
        setup = NetworkSetup()
        setup.setup_network()
    except KeyboardInterrupt:
        print("\n[!] Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Setup failed: {e}")
        print("Run uninstall_bridge.sh to remove the bridge.")
        sys.exit(1)


if __name__ == "__main__":
    main()