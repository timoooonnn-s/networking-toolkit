"""
features/ip_hardware.py
-----------------------
IP Address & Hardware Tools

Tools
-----
    tool_vlan_tracker()   — JSON-backed VLAN planner/tracker
    tool_next_ip()        — Next free IP in a subnet
    tool_bandwidth_mon()  — Real-time RX/TX bandwidth from /proc/net/dev

Reachability sweeps live in features/multiping.py, which uses fping when it
is available and the system ping otherwise.

Two tools were removed from this module rather than repaired:

* The MAC vendor lookup depended on macvendors.co, which now requires an API
  key, so it could only ever print an error.
* The SNMP device discovery tool decoded replies by scanning for printable
  byte runs, which misparsed readily.  features/snmp_assistant.py replaces it
  with a real BER decoder, and its 'sysdescr' preset does the same job.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import sys
import time

from core.colors import C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW
from core.export import offer_export
from core.paths import VLAN_DB_FILE

# ---------------------------------------------------------------------------
# VLAN Planner & Tracker
# ---------------------------------------------------------------------------

def _load_vlans() -> dict:
    if os.path.exists(VLAN_DB_FILE):
        try:
            with open(VLAN_DB_FILE) as handle:
                return json.load(handle)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"{C_YELLOW}Could not read {VLAN_DB_FILE} ({exc}) — "
                  f"starting from an empty database.{C_RESET}")
    return {}


def _save_vlans(vlans: dict) -> None:
    with open(VLAN_DB_FILE, "w") as handle:
        json.dump(vlans, handle, indent=4)


def tool_vlan_tracker() -> None:
    """Manage a persistent JSON VLAN database (add/list/delete VLANs)."""
    print(f"{C_BOLD}--- VLAN Planner & Tracker ---{C_RESET}")
    print(f"{C_CYAN}Database: {VLAN_DB_FILE}{C_RESET}")
    vlans = _load_vlans()
    print(f"Tracking {len(vlans)} VLAN(s).")
    print("  1. List VLANs")
    print("  2. Add / edit VLAN")
    print("  3. Delete VLAN")
    choice = input("Choice: ").strip()

    if choice == "1":
        if not vlans:
            print(f"{C_YELLOW}No VLANs in database yet.{C_RESET}")
            return
        print(f"\n{C_BOLD}{'ID':<6} {'Name':<22} {'Subnet / Description'}{C_RESET}")
        print("─" * 55)
        rows = []
        for vid in sorted(vlans, key=lambda x: int(x)):
            info = vlans[vid]
            print(f"{vid:<6} {C_GREEN}{info.get('name', ''):<22}{C_RESET} "
                  f"{info.get('desc', '')}")
            rows.append({"vlan_id": vid,
                         "name": info.get("name", ""),
                         "description": info.get("desc", "")})
        offer_export(rows, "vlans")

    elif choice == "2":
        vid = input("VLAN ID (number): ").strip()
        if not vid.isdigit() or not 1 <= int(vid) <= 4094:
            print(f"{C_RED}VLAN ID must be a number between 1 and 4094.{C_RESET}")
            return
        name = input("VLAN Name: ").strip()
        desc = input("Subnet / Description: ").strip()
        vlans[vid] = {"name": name, "desc": desc}
        _save_vlans(vlans)
        print(f"{C_GREEN}VLAN {vid} saved.{C_RESET}")

    elif choice == "3":
        vid = input("VLAN ID to delete: ").strip()
        if vid in vlans:
            del vlans[vid]
            _save_vlans(vlans)
            print(f"{C_GREEN}VLAN {vid} deleted.{C_RESET}")
        else:
            print(f"{C_RED}VLAN {vid} not found.{C_RESET}")
    else:
        print(f"{C_RED}Invalid option.{C_RESET}")


# ---------------------------------------------------------------------------
# Next Available IP Finder
# ---------------------------------------------------------------------------

def tool_next_ip() -> None:
    """Find the first free IP address in a subnet given a set of used IPs."""
    print(f"{C_BOLD}--- Next Available IP Finder ---{C_RESET}")
    subnet_str = input("Subnet (e.g. 192.168.10.0/24): ").strip()
    used_raw   = input("Used IPs (comma-separated, blank for none): ").strip()

    try:
        network = ipaddress.IPv4Network(subnet_str, strict=False)
        used: set[ipaddress.IPv4Address] = {
            ipaddress.IPv4Address(ip.strip())
            for ip in used_raw.split(",")
            if ip.strip()
        }
        used.add(network.network_address)
        used.add(network.broadcast_address)

        found = next((ip for ip in network.hosts() if ip not in used), None)
        if found:
            print(f"\n{C_GREEN}Next available IP: {found}{C_RESET}")
        else:
            print(f"\n{C_RED}No free IPs in subnet {subnet_str}.{C_RESET}")

    except ValueError as exc:
        print(f"{C_RED}Invalid input: {exc}{C_RESET}")


# ---------------------------------------------------------------------------
# Real-Time Bandwidth Monitor (Linux only)
# ---------------------------------------------------------------------------

def _read_iface_bytes(iface: str) -> tuple[int, int] | tuple[None, None]:
    """
    Return (rx_bytes, tx_bytes) for *iface* from /proc/net/dev.

    The interface name is matched exactly against the column before the colon.
    Substring matching used to make 'eth0' pick up 'veth0abc' or 'eth0.100'
    counters — and match the header line, which has no numeric columns at all.
    """
    try:
        with open("/proc/net/dev") as handle:
            for line in handle:
                if ":" not in line:
                    continue
                name, _, stats = line.partition(":")
                if name.strip() != iface:
                    continue
                columns = stats.split()
                if len(columns) < 9:
                    return None, None
                return int(columns[0]), int(columns[8])   # RX bytes, TX bytes
    except OSError:
        return None, None
    return None, None


def tool_bandwidth_mon() -> None:
    """Display real-time RX/TX bandwidth by reading /proc/net/dev."""
    print(f"{C_BOLD}--- Real-Time Bandwidth Monitor (Linux only) ---{C_RESET}")

    if platform.system() != "Linux":
        print(f"{C_RED}This tool is Linux-only (/proc/net/dev).{C_RESET}")
        return

    iface = input("Interface (e.g. eth0, wlan0): ").strip()
    if not iface:
        print(f"{C_RED}No interface given.{C_RESET}")
        return

    rx1, tx1 = _read_iface_bytes(iface)
    if rx1 is None:
        print(f"{C_RED}Interface '{iface}' not found in /proc/net/dev.{C_RESET}")
        return

    print(f"Monitoring {iface} … (Ctrl+C to stop)\n")
    try:
        while True:
            time.sleep(1)
            rx2, tx2 = _read_iface_bytes(iface)
            if rx2 is None:
                print(f"\n{C_RED}Interface '{iface}' disappeared.{C_RESET}")
                break
            rx_kbps = (rx2 - rx1) / 1024
            tx_kbps = (tx2 - tx1) / 1024
            sys.stdout.write(
                f"\rDownload: {C_GREEN}{rx_kbps:8.2f} KB/s{C_RESET}"
                f"  |  Upload: {C_CYAN}{tx_kbps:8.2f} KB/s{C_RESET}   "
            )
            sys.stdout.flush()
            rx1, tx1 = rx2, tx2
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}Monitoring stopped.{C_RESET}")
