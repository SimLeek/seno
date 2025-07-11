#!/usr/bin/env python3

import subprocess
import sys
import os
import time
import random
import concurrent.futures
import threading
import socket
import signal
import getpass
from pathlib import Path

BRIDGE_NAME = "aibr0"
PORT = 12345


class NetworkTest:
    def __init__(self):
        self.bridge_name = BRIDGE_NAME
        self.port = PORT
        self.current_ip = None
        self.listener_socket = None
        self.listener_thread = None
        self.received_messages = []
        self.running = True
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
        import getpass
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

    def get_current_ip(self):
        """Get current bridge IP"""
        try:
            result = self.run_command(f"ip addr show {self.bridge_name}")
            for line in result.stdout.split('\n'):
                if 'inet ' in line and not line.strip().startswith('inet6'):
                    self.current_ip = line.split()[1].split('/')[0]
                    return self.current_ip

            print(f"[ERROR] Failed to retrieve current bridge IP. Ensure bridge '{self.bridge_name}' is configured.")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Failed to get bridge info: {e}")
            sys.exit(1)

    def ping_ip(self, ip, timeout=1):
        """Ping a single IP address"""
        try:
            subprocess.run(f"ping -c1 -W{timeout} {ip}",
                           shell=True, check=True, capture_output=True)
            return ip
        except subprocess.CalledProcessError:
            return None

    def scan_network(self):
        """Scan network for existing hosts using parallel ping"""
        print("[*] Scanning network for other computers...")

        network_base = "192.168.200"
        ips_to_scan = [f"{network_base}.{i}" for i in range(10, 251)]
        found_ips = []

        # Use ThreadPoolExecutor for parallel pinging
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
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
                    print(f"\r[*] Scanning... {completed}/{total} - Found: {len(found_ips)}",
                          end="", flush=True)
                elif completed % 20 == 0:
                    print(f"\r[*] Scanning... {completed}/{total} - Found: {len(found_ips)}",
                          end="", flush=True)

        print()  # New line
        return sorted(found_ips)

    def message_listener(self):
        """Listen for incoming messages on the specified port"""
        try:
            self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener_socket.bind(('', self.port))
            self.listener_socket.listen(5)
            self.listener_socket.settimeout(1)  # Non-blocking with timeout

            print(f"[*] Listener started on port {self.port}")

            while self.running:
                try:
                    conn, addr = self.listener_socket.accept()
                    with conn:
                        conn.settimeout(5)
                        data = conn.recv(1024).decode().strip()
                        if data:
                            self.received_messages.append(data)
                            print(f"[+] Received random number '{data}' from {addr[0]}")
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[ERROR] Listener error: {e}")
                    break

        except Exception as e:
            print(f"[ERROR] Failed to start listener: {e}")

    def send_message(self, ip, message):
        """Send message to a specific IP"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((ip, self.port))
                sock.sendall(message.encode())
                return True
        except Exception:
            return False

    def test_network(self):
        """Main network test function"""
        print("===============================================")
        print("    NETWORK COMMUNICATION TEST")
        print("===============================================")
        print()

        # Get current bridge IP
        self.get_current_ip()
        print(f"[*] Current IP: {self.current_ip}")

        # Start listener in background thread
        print(f"[*] Starting listener on port {self.port}...")
        self.listener_thread = threading.Thread(target=self.message_listener, daemon=True)
        self.listener_thread.start()
        time.sleep(1)  # Give listener time to start

        # Scan for remote computers
        remote_ips = self.scan_network()

        # Filter out our own IP
        filtered_ips = [ip for ip in remote_ips if ip != self.current_ip]

        if filtered_ips:
            print(f"[+] Found {len(filtered_ips)} remote computer(s): {', '.join(filtered_ips)}")

            # Generate random number
            random_number = random.randint(1, 9999)
            print(f"[*] Sending random number '{random_number}' to all other IPs on bridge...")

            # Send random number to each remote IP
            for remote_ip in filtered_ips:
                print(f"    Sending to {remote_ip}... ", end="", flush=True)
                if self.send_message(remote_ip, str(random_number)):
                    print("SENT")
                else:
                    print("FAILED")
        else:
            print("[!] No remote computers detected")

        # Wait briefly to allow receiving messages
        print("[*] Waiting for incoming messages (5 seconds)...")
        time.sleep(5)

        # Stop listener
        self.running = False
        if self.listener_socket:
            self.listener_socket.close()

        print()
        print("===============================================")
        print("    NETWORK TEST COMPLETE")
        print("===============================================")

    def cleanup(self):
        """Clean up resources"""
        self.running = False
        if self.listener_socket:
            try:
                self.listener_socket.close()
            except:
                pass


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Test interrupted by user")
    sys.exit(0)


def main():
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    try:
        test = NetworkTest()
        test.test_network()
    except KeyboardInterrupt:
        print("\n[!] Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()