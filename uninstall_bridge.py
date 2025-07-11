#!/usr/bin/env python3

import subprocess
import sys
import os
import getpass
from pathlib import Path

BRIDGE_NAME = "aibr0"
FIREWALL_STATUS_FILE = "/tmp/aibr0_firewall_status"


class NetworkUninstaller:
    def __init__(self):
        self.bridge_name = BRIDGE_NAME
        self.firewall_status_file = FIREWALL_STATUS_FILE
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
        """Get primary interface from bridge"""
        try:
            result = self.run_command("nmcli connection show")
            lines = result.stdout.strip().split('\n')

            for line in lines:
                if self.bridge_name in line and 'ethernet' in line:
                    # Extract interface name (first part before '-slave')
                    parts = line.split()
                    if len(parts) > 0:
                        conn_name = parts[0]
                        if conn_name.endswith('-slave'):
                            primary_if = conn_name.replace('-slave', '')
                            return primary_if

            print(f"[WARNING] No enslaved Ethernet interface found for bridge '{self.bridge_name}'")
            return None
        except Exception as e:
            print(f"[WARNING] Failed to get primary interface: {e}")
            return None

    def remove_firewall_rules(self, primary_if):
        """Remove firewall rules"""
        if not os.path.exists(self.firewall_status_file):
            print("[*] No firewall status file found. Assuming no firewall rules were added.")
            return

        try:
            with open(self.firewall_status_file, 'r') as f:
                firewall_type = f.read().strip()
        except Exception as e:
            print(f"[WARNING] Failed to read firewall status file: {e}. Assuming no rules to remove.")
            return

        if firewall_type == "ufw":
            print(f"[*] Removing ufw rules for {self.bridge_name} and {primary_if}...")

            # Remove ufw rule for bridge
            try:
                self.run_command(f"sudo ufw delete allow in on {self.bridge_name}")
            except subprocess.CalledProcessError:
                print(f"[WARNING] Failed to remove ufw rule for {self.bridge_name} (may not exist)")

            # Remove ufw rule for primary interface
            try:
                self.run_command(f"sudo ufw delete allow in on {primary_if}")
            except subprocess.CalledProcessError:
                print(f"[WARNING] Failed to remove ufw rule for {primary_if} (may not exist)")

            print("[+] ufw rules removed")

        elif firewall_type == "firewalld":
            print(f"[*] Removing firewalld rules for {self.bridge_name} and {primary_if}...")

            # Remove firewalld rule for bridge
            try:
                self.run_command(f"sudo firewall-cmd --permanent --zone=trusted --remove-interface={self.bridge_name}")
            except subprocess.CalledProcessError:
                print(f"[WARNING] Failed to remove firewalld rule for {self.bridge_name} (may not exist)")

            # Remove firewalld rule for primary interface
            try:
                self.run_command(f"sudo firewall-cmd --permanent --zone=trusted --remove-interface={primary_if}")
            except subprocess.CalledProcessError:
                print(f"[WARNING] Failed to remove firewalld rule for {primary_if} (may not exist)")

            # Reload firewalld
            try:
                self.run_command("sudo firewall-cmd --reload")
                print("[+] firewalld rules removed")
            except subprocess.CalledProcessError:
                print("[ERROR] Failed to reload firewalld")
                sys.exit(1)
        else:
            print(f"[*] No firewall rules were added during setup (type: {firewall_type})")

        # Clean up status file
        try:
            os.remove(self.firewall_status_file)
        except OSError:
            pass

    def bridge_exists(self):
        """Check if bridge connection exists"""
        try:
            self.run_command(f"nmcli connection show {self.bridge_name}")
            return True
        except subprocess.CalledProcessError:
            return False

    def uninstall_network(self):
        """Main uninstall function"""
        print("===============================================")
        print("    UNINSTALLING NETWORK BRIDGE")
        print("===============================================")
        print()

        # Check if bridge exists
        if not self.bridge_exists():
            print(f"[*] No bridge '{self.bridge_name}' found. Nothing to uninstall.")
            # Clean up firewall status file if it exists
            if os.path.exists(self.firewall_status_file):
                print("[*] Cleaning up firewall status file...")
                try:
                    os.remove(self.firewall_status_file)
                except OSError:
                    pass
            print()
            print("[+] Uninstallation complete!")
            return

        # Check sudo permissions
        self.check_sudo()

        # Get primary interface
        primary_if = self.get_primary_interface()

        # Remove bridge and slave connection
        print(f"[*] Removing bridge '{self.bridge_name}'...")
        try:
            self.run_command(f"sudo nmcli connection delete {self.bridge_name}")
        except subprocess.CalledProcessError:
            print(f"[ERROR] Failed to delete bridge '{self.bridge_name}'")
            sys.exit(1)

        if primary_if:
            print(f"[*] Removing slave connection '{primary_if}-slave'...")
            try:
                self.run_command(f"sudo nmcli connection delete {primary_if}-slave")
            except subprocess.CalledProcessError:
                print(f"[WARNING] Failed to delete slave connection '{primary_if}-slave' (may not exist)")

        # Remove firewall rules
        if primary_if:
            self.remove_firewall_rules(primary_if)
        else:
            print("[WARNING] Skipping firewall rule removal due to unknown primary interface")

        print()
        print("===============================================")
        print("    UNINSTALLATION COMPLETE")
        print("===============================================")
        print(f"[+] Bridge '{self.bridge_name}' and associated configurations removed.")


def main():
    try:
        uninstaller = NetworkUninstaller()
        uninstaller.uninstall_network()
    except KeyboardInterrupt:
        print("\n[!] Uninstallation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Uninstallation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()