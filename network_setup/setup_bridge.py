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
                result = subprocess.run(
                    full_cmd,
                    shell=True,
                    check=check,
                    capture_output=capture_output,
                    text=True,
                )
            else:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    check=check,
                    capture_output=capture_output,
                    text=True,
                )
            return result
        except subprocess.CalledProcessError as e:
            if check:
                print(f"[ERROR] Command failed: {cmd}")
                print(f"Error: {e.stderr if e.stderr else str(e)}")
                raise
            return e

    def get_ethernet_interface(self):
        """Get the ethernet interface (connected or disconnected)"""
        try:
            result = self.run_command("nmcli device status")
            lines = result.stdout.strip().split("\n")[1:]  # Skip header

            ethernet_interfaces = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "ethernet":
                    ethernet_interfaces.append(
                        {
                            "device": parts[0],
                            "state": parts[2] if len(parts) > 2 else "unknown",
                            "connection": parts[3] if len(parts) > 3 else "--",
                        }
                    )

            if not ethernet_interfaces:
                print("[ERROR] No ethernet interface found")
                sys.exit(1)

            # Print available interfaces
            print("\nAvailable ethernet interfaces:")
            for i, iface in enumerate(ethernet_interfaces):
                print(
                    f"  {i + 1}. {iface['device']} - {iface['state']} ({iface['connection']})"
                )

            if len(ethernet_interfaces) == 1:
                self.primary_if = ethernet_interfaces[0]["device"]
                print(f"[*] Using ethernet interface: {self.primary_if}")
            else:
                while True:
                    try:
                        choice = input(
                            f"\nSelect interface (1-{len(ethernet_interfaces)}): "
                        ).strip()
                        idx = int(choice) - 1
                        if 0 <= idx < len(ethernet_interfaces):
                            self.primary_if = ethernet_interfaces[idx]["device"]
                            print(f"[*] Selected interface: {self.primary_if}")
                            break
                        else:
                            print("Invalid choice. Please try again.")
                    except ValueError:
                        print("Please enter a number.")

        except Exception as e:
            print(f"[ERROR] Failed to get ethernet interface: {e}")
            sys.exit(1)

    def cleanup_existing_connections(self):
        """Clean up any existing connections on the ethernet interface"""
        try:
            # Get all connections for this interface
            result = self.run_command(f"nmcli connection show")
            connections_to_remove = []

            for line in result.stdout.strip().split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 4 and parts[-1] == self.primary_if:
                    conn_name = " ".join(
                        parts[:-3]
                    )  # Connection name might have spaces
                    connections_to_remove.append(conn_name)

            # Remove old connections
            for conn_name in connections_to_remove:
                try:
                    print(f"[*] Removing existing connection: {conn_name}")
                    self.run_command(f"sudo nmcli connection delete '{conn_name}'")
                except subprocess.CalledProcessError:
                    pass  # Connection might not exist

        except Exception as e:
            print(f"[WARNING] Failed to cleanup existing connections: {e}")

    def detect_network_type(self):
        """Detect if we're in a LAN environment or direct connection"""
        print("\n[*] Detecting network environment...")

        # First try to see if there's an existing DHCP server
        print("[*] Checking for existing DHCP server...")

        # Create a temporary connection to test DHCP
        temp_conn_name = f"temp-dhcp-test-{random.randint(1000, 9999)}"
        try:
            self.run_command(
                f"sudo nmcli connection add type ethernet ifname {self.primary_if} "
                f"con-name {temp_conn_name} ipv4.method auto autoconnect no"
            )

            # Try to connect and get DHCP
            print("[*] Testing DHCP connection...")
            self.run_command(f"sudo nmcli connection up {temp_conn_name}")

            # Wait a bit for DHCP
            time.sleep(5)

            # Check if we got an IP
            result = self.run_command(f"ip addr show {self.primary_if}")
            has_dhcp_ip = False
            dhcp_ip = None

            for line in result.stdout.split("\n"):
                if "inet " in line and "127.0.0.1" not in line:
                    ip_info = line.strip().split()[1]
                    if not ip_info.startswith("169.254"):  # Not link-local
                        has_dhcp_ip = True
                        dhcp_ip = ip_info.split("/")[0]
                        break

            # Clean up temp connection
            self.run_command(f"sudo nmcli connection delete {temp_conn_name}")

            if has_dhcp_ip:
                print(f"[+] DHCP detected! Got IP: {dhcp_ip}")
                return "lan", dhcp_ip
            else:
                print("[*] No DHCP server detected")
                return "direct", None

        except subprocess.CalledProcessError:
            # Clean up temp connection if it exists
            try:
                self.run_command(
                    f"sudo nmcli connection delete {temp_conn_name}", check=False
                )
            except:
                pass
            print("[*] DHCP test failed - assuming direct connection")
            return "direct", None

    def setup_lan_bridge(self, dhcp_ip):
        """Set up bridge for LAN environment with DHCP"""
        print("\n[*] Setting up LAN bridge configuration...")

        # Extract network info from DHCP IP
        ip_parts = dhcp_ip.split(".")
        network_base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"

        # Create bridge with DHCP
        print(f"[*] Creating bridge '{self.bridge_name}' with DHCP...")
        self.run_command(
            f"sudo nmcli connection add type bridge ifname {self.bridge_name} "
            f"con-name {self.bridge_name} ipv4.method auto autoconnect yes"
        )

        # Add ethernet as slave
        print(f"[*] Adding interface '{self.primary_if}' to bridge...")
        self.run_command(
            f"sudo nmcli connection add type ethernet ifname {self.primary_if} "
            f"master {self.bridge_name} con-name {self.primary_if}-bridge-slave autoconnect yes"
        )

        # Activate bridge
        print("[*] Activating bridge...")
        self.run_command(f"sudo nmcli connection up {self.bridge_name}")

        # Wait for DHCP
        print("[*] Waiting for DHCP assignment...")
        time.sleep(8)

        # Get the actual IP assigned to bridge
        result = self.run_command(f"ip addr show {self.bridge_name}")
        bridge_ip = None

        for line in result.stdout.split("\n"):
            if "inet " in line and "127.0.0.1" not in line:
                ip_info = line.strip().split()[1]
                if not ip_info.startswith("169.254"):  # Not link-local
                    bridge_ip = ip_info.split("/")[0]
                    break

        if bridge_ip:
            print(f"[+] Bridge IP assigned: {bridge_ip}")
            return bridge_ip, network_base
        else:
            print("[ERROR] Failed to get bridge IP from DHCP")
            sys.exit(1)

    def setup_direct_bridge(self):
        """Set up bridge for direct connection between computers"""
        print("\n[*] Setting up direct connection bridge...")

        # Generate IP from MAC
        local_ip = self.generate_ip_from_mac()

        # Scan for existing hosts first
        print("[*] Scanning for other computers on direct connection...")
        detected_ips = self.scan_network_direct()

        if detected_ips:
            print(
                f"[+] Found {len(detected_ips)} existing computer(s): {', '.join(detected_ips)}"
            )
            # Check if our proposed IP conflicts
            if local_ip in detected_ips:
                local_ip = self.find_available_ip(detected_ips)
                print(f"[*] IP conflict resolved, using: {local_ip}")
        else:
            print("[*] No other computers detected yet")

        # Create bridge with static IP
        print(f"[*] Creating bridge '{self.bridge_name}' with static IP {local_ip}...")
        self.run_command(
            f"sudo nmcli connection add type bridge ifname {self.bridge_name} "
            f"con-name {self.bridge_name} ipv4.method manual "
            f"ipv4.addresses {local_ip}/24 autoconnect yes"
        )

        # Add ethernet as slave
        print(f"[*] Adding interface '{self.primary_if}' to bridge...")
        self.run_command(
            f"sudo nmcli connection add type ethernet ifname {self.primary_if} "
            f"master {self.bridge_name} con-name {self.primary_if}-bridge-slave autoconnect yes"
        )

        # Activate bridge
        print("[*] Activating bridge...")
        self.run_command(f"sudo nmcli connection up {self.bridge_name}")

        # Wait for bridge to initialize
        print("[*] Waiting for bridge to initialize...")
        time.sleep(3)

        return local_ip, "192.168.200"

    def generate_ip_from_mac(self):
        """Generate IP address based on MAC address"""
        try:
            mac_file = f"/sys/class/net/{self.primary_if}/address"
            with open(mac_file, "r") as f:
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

    def ping_ip(self, ip, timeout=0.5):
        """Ping a single IP address"""
        try:
            subprocess.run(
                f"ping -c1 -W{timeout} {ip}",
                shell=True,
                check=True,
                capture_output=True,
            )
            return ip
        except subprocess.CalledProcessError:
            return None

    def scan_network_direct(self):
        """Scan direct connection network (192.168.200.x)"""
        print("[*] Scanning for other computers on direct connection...")
        network_base = "192.168.200"
        ips_to_scan = [f"{network_base}.{i}" for i in range(10, 251)]

        return self.parallel_ping_scan(ips_to_scan)

    def scan_network_lan(self, network_base):
        """Scan LAN network"""
        print(f"[*] Scanning LAN network {network_base}.x...")
        ips_to_scan = [f"{network_base}.{i}" for i in range(1, 255)]

        return self.parallel_ping_scan(ips_to_scan)

    def parallel_ping_scan(self, ips_to_scan):
        """Perform parallel ping scan"""
        found_ips = []

        # Use ThreadPoolExecutor for parallel pinging
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            # Submit all ping tasks
            future_to_ip = {executor.submit(self.ping_ip, ip): ip for ip in ips_to_scan}

            completed = 0
            total = len(ips_to_scan)

            for future in concurrent.futures.as_completed(future_to_ip):
                completed += 1
                result = future.result()

                if result:
                    found_ips.append(result)
                    print(
                        f"\r[*] Scanning... {completed}/{total} - Found: {len(found_ips)}",
                        end="",
                        flush=True,
                    )
                elif completed % 50 == 0:
                    print(
                        f"\r[*] Scanning... {completed}/{total} - Found: {len(found_ips)}",
                        end="",
                        flush=True,
                    )

        print()  # New line
        return sorted(found_ips)

    def find_available_ip(self, detected_ips):
        """Find an available IP address"""
        # Find next available IP
        for i in range(10, 251):
            test_ip = f"192.168.200.{i}"
            if test_ip not in detected_ips:
                return test_ip

        print("[ERROR] No available IP addresses found!")
        sys.exit(1)

    def configure_firewall(self):
        """Configure firewall rules"""
        print(
            f"[*] Configuring firewall for bridge '{self.bridge_name}' and interface '{self.primary_if}'..."
        )

        # Initialize firewall status file
        with open(FIREWALL_STATUS_FILE, "w") as f:
            f.write("none")

        # Check for ufw
        try:
            self.run_command("ufw --version")
            print("[*] Detected ufw firewall")

            self.run_command(f"sudo ufw allow in on {self.bridge_name}")
            self.run_command(f"sudo ufw allow out on {self.bridge_name}")

            with open(FIREWALL_STATUS_FILE, "w") as f:
                f.write("ufw")

            print(f"[+] ufw rules added to allow all traffic on {self.bridge_name}")
            return
        except subprocess.CalledProcessError:
            pass

        # Check for firewalld
        try:
            self.run_command("firewall-cmd --version")
            print("[*] Detected firewalld")

            self.run_command(
                f"sudo firewall-cmd --permanent --zone=trusted --add-interface={self.bridge_name}"
            )
            self.run_command("sudo firewall-cmd --reload")

            with open(FIREWALL_STATUS_FILE, "w") as f:
                f.write("firewalld")

            print(
                f"[+] firewalld rules added to allow all traffic on {self.bridge_name}"
            )
            return
        except subprocess.CalledProcessError:
            pass

        print(
            f"[WARNING] No supported firewall (ufw or firewalld) detected. "
            f"If you have a manual configuration, you may need to allow traffic through "
            f"{self.bridge_name}."
        )

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
            self.run_command("sudo pacman -S --noconfirm networkmanager")
        except subprocess.CalledProcessError:
            pass

        # Check for apt-get
        try:
            self.run_command("apt-get --version")
            print("[*] Detected apt-based system")
            self.run_command(
                "sudo apt-get update && sudo apt-get install -y network-manager"
            )
        except subprocess.CalledProcessError:
            print(
                "[ERROR] Unsupported package manager. Only pacman and apt-get are supported."
            )
            sys.exit(1)

        # Start NetworkManager
        try:
            self.run_command("systemctl is-active --quiet NetworkManager")
        except subprocess.CalledProcessError:
            self.run_command("sudo systemctl enable NetworkManager")
            self.run_command("sudo systemctl start NetworkManager")
            time.sleep(3)

    def test_connectivity(self, ips, our_ip):
        """Test connectivity to remote IPs"""
        if not ips:
            return 0

        print("[*] Testing connectivity to other computers...")
        reachable = 0

        # Filter out our own IP
        remote_ips = [ip for ip in ips if ip != our_ip]

        if not remote_ips:
            print("[*] No remote computers to test")
            return 0

        for remote_ip in remote_ips:
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
        self.check_networkmanager()

        # Check if bridge already exists
        if self.bridge_exists():
            print(f"[+] Network bridge '{self.bridge_name}' already exists!")

            # Get current bridge IP
            try:
                result = self.run_command(f"ip addr show {self.bridge_name}")
                current_ip = None
                for line in result.stdout.split("\n"):
                    if "inet " in line and "127.0.0.1" not in line:
                        current_ip = line.strip().split()[1].split("/")[0]
                        break

                if current_ip:
                    print(f"[*] Current bridge IP: {current_ip}")

                    # Determine network type and scan accordingly
                    if current_ip.startswith("192.168.200"):
                        # Direct connection
                        remote_ips = self.scan_network_direct()
                        network_type = "direct"
                    else:
                        # LAN connection
                        network_base = ".".join(current_ip.split(".")[:-1])
                        remote_ips = self.scan_network_lan(network_base)
                        network_type = "LAN"

                    if remote_ips:
                        reachable = self.test_connectivity(remote_ips, current_ip)
                        print(
                            f"[+] {network_type} network ready! Connected to {reachable} remote computer(s)"
                        )
                    else:
                        print(
                            f"[!] No remote computers detected on {network_type} network"
                        )
                else:
                    print("[ERROR] Could not determine current bridge IP")
            except Exception as e:
                print(f"[ERROR] Failed to get bridge info: {e}")

            self.configure_firewall()
            print("\nNetwork is ready for use!")
            return

        print("Setting up new network configuration...")
        self.get_ethernet_interface()
        self.cleanup_existing_connections()

        # Detect network environment
        network_type, dhcp_ip = self.detect_network_type()

        if network_type == "lan":
            print(f"\n[+] LAN environment detected with DHCP")
            local_ip, network_base = self.setup_lan_bridge(dhcp_ip)
            # Scan for other computers on LAN
            remote_ips = self.scan_network_lan(network_base)
        else:
            print(f"\n[+] Direct connection environment detected")
            local_ip, network_base = self.setup_direct_bridge()
            # Scan for other computers on direct connection
            remote_ips = self.scan_network_direct()

        # Configure firewall
        self.configure_firewall()

        # Test connectivity
        if remote_ips:
            reachable = self.test_connectivity(remote_ips, local_ip)
            print(f"\n[+] Found {len(remote_ips)} computer(s), {reachable} reachable")
        else:
            print(f"\n[*] No other computers detected (they may not be configured yet)")

        print()
        print("===============================================")
        print("    NETWORK SETUP COMPLETE!")
        print("===============================================")
        print()
        print("[+] Your computer is configured with:")
        print(f"    • Network Type: {network_type.upper()}")
        print(f"    • IP Address: {local_ip}")
        print(f"    • Bridge Interface: {self.bridge_name}")
        print(f"    • Ethernet Interface: {self.primary_if}")
        if remote_ips:
            print(
                f"    • Detected Computers: {', '.join([ip for ip in remote_ips if ip != local_ip])}"
            )
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
        print("You may need to clean up any partial configuration.")
        sys.exit(1)


if __name__ == "__main__":
    main()
