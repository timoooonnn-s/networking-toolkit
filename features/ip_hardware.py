"""
features/ip_hardware.py
-----------------------
IP Address & Hardware Tools
============================
Refactored from the original monolith's Category E & F.

Tools
-----
    tool_mac_oui()        — MAC vendor lookup via macvendors.co API
    tool_snmp_discovery() — Manual SNMPv2c sysDescr getter (no pysnmp needed)
    tool_vlan_tracker()   — JSON-backed VLAN planner/tracker
    tool_next_ip()        — Next free IP in a subnet
    tool_ping_sweep()     — Threaded LAN ping sweep
    tool_bandwidth_mon()  — Real-time RX/TX bandwidth from /proc/net/dev
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import random
import re
import struct
import socket
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from core.colors import C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW

VLAN_DB_FILE = "sysnet_vlans.json"


# ---------------------------------------------------------------------------
# MAC Vendor Lookup
# ---------------------------------------------------------------------------

def tool_mac_oui() -> None:
    """Look up the vendor for a MAC address via the macvendors.co API."""
    print(f"{C_BOLD}--- MAC Address Vendor Lookup ---{C_RESET}")
    mac       = input("Enter MAC address (any format): ").strip()
    clean_mac = re.sub(r"[.:\-]", "", mac).upper()

    if len(clean_mac) < 6:
        print(f"{C_RED}Invalid MAC — too short.{C_RESET}")
        return

    print("Querying macvendors.co …")
    try:
        url = f"https://macvendors.co/api/{clean_mac}"
        req = urllib.request.Request(url, headers={"User-Agent": "SysNet-Toolkit/2.2"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data   = json.loads(resp.read().decode())
            result = data.get("result", {})

        company = result.get("company")
        if company:
            print(f"\n{C_GREEN}Vendor:    {C_RESET}{company}")
            print(f"{C_GREEN}Address:   {C_RESET}{result.get('address', 'N/A')}")
            print(f"{C_GREEN}MAC Prefix:{C_RESET}{result.get('mac_prefix', 'N/A')}")
        else:
            print(f"{C_YELLOW}Vendor not found for this OUI.{C_RESET}")

    except Exception as exc:
        print(f"{C_RED}API error: {exc}{C_RESET}")


# ---------------------------------------------------------------------------
# SNMP Device Discovery (SNMPv2c, stdlib only)
# ---------------------------------------------------------------------------

def tool_snmp_discovery() -> None:
    """Query a device for sysDescr via a hand-crafted SNMPv2c GET packet."""
    print(f"{C_BOLD}--- SNMP Device Discovery (sysDescr) ---{C_RESET}")
    target_ip = input("Target IP: ").strip()
    community = input("Community string (default: public): ").strip() or "public"
    port      = 161

    def _encode_len(length: int) -> bytes:
        if length < 128:
            return bytes([length])
        parts: list[int] = []
        while length > 0:
            parts.insert(0, length & 0xFF)
            length >>= 8
        return bytes([0x80 | len(parts)] + parts)

    def _build_packet(comm: str, oid: str = "1.3.6.1.2.1.1.1.0") -> bytes:
        # Encode OID
        parts    = [int(x) for x in oid.split(".")]
        oid_bytes = bytearray([parts[0] * 40 + parts[1]])
        for val in parts[2:]:
            if val < 128:
                oid_bytes.append(val)
            else:
                sub: list[int] = [val & 0x7F]
                val >>= 7
                while val:
                    sub.insert(0, (val & 0x7F) | 0x80)
                    val >>= 7
                oid_bytes.extend(sub)

        varbind_val  = b"\x06" + _encode_len(len(oid_bytes)) + bytes(oid_bytes) + b"\x05\x00"
        varbind      = b"\x30" + _encode_len(len(varbind_val)) + varbind_val
        varbind_list = b"\x30" + _encode_len(len(varbind)) + varbind

        req_id      = random.randint(1000, 9999)
        pdu_content = (
            b"\x02\x04" + struct.pack(">I", req_id)
            + b"\x02\x01\x00\x02\x01\x00"
            + varbind_list
        )
        pdu = b"\xa0" + _encode_len(len(pdu_content)) + pdu_content

        comm_enc  = comm.encode()
        msg_body  = (
            b"\x02\x01\x01"
            + b"\x04" + bytes([len(comm_enc)]) + comm_enc
            + pdu
        )
        return b"\x30" + _encode_len(len(msg_body)) + msg_body

    print(f"Sending SNMPv2c GET to {target_ip}:{port} …")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.sendto(_build_packet(community), (target_ip, port))
        data, _ = sock.recvfrom(2048)

        # Crude printable-string extraction
        clean = "".join(chr(b) if 32 <= b <= 126 else "\n" for b in data)
        found = False
        for segment in clean.split("\n"):
            if len(segment) > 5 and segment != community and " " in segment:
                print(f"\n{C_GREEN}Device Info:{C_RESET}\n{C_CYAN}{segment}{C_RESET}")
                found = True
                break
        if not found:
            print(f"{C_YELLOW}Response received but could not decode sysDescr string.{C_RESET}")

    except socket.timeout:
        print(f"{C_RED}Timeout — no response from {target_ip}. (Check IP, community, firewall){C_RESET}")
    except Exception as exc:
        print(f"{C_RED}Error: {exc}{C_RESET}")
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# VLAN Planner & Tracker
# ---------------------------------------------------------------------------

def _load_vlans() -> dict:
    if os.path.exists(VLAN_DB_FILE):
        try:
            with open(VLAN_DB_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_vlans(vlans: dict) -> None:
    with open(VLAN_DB_FILE, "w") as f:
        json.dump(vlans, f, indent=4)


def tool_vlan_tracker() -> None:
    """Manage a persistent JSON VLAN database (add/list/delete VLANs)."""
    print(f"{C_BOLD}--- VLAN Planner & Tracker ---{C_RESET}")
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
        for vid in sorted(vlans, key=lambda x: int(x)):
            info = vlans[vid]
            print(f"{vid:<6} {C_GREEN}{info['name']:<22}{C_RESET} {info['desc']}")

    elif choice == "2":
        vid = input("VLAN ID (number): ").strip()
        if not vid.isdigit():
            print(f"{C_RED}VLAN ID must be numeric.{C_RESET}")
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
# LAN Ping Sweep
# ---------------------------------------------------------------------------

def _ping_once(ip: str) -> bool:
    """Return True if *ip* responds to a single ICMP ping."""
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    return (
        subprocess.call(
            ["ping", flag, "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        == 0
    )


def tool_ping_sweep() -> None:
    """Ping all hosts in a /24 subnet and report which are up."""
    print(f"{C_BOLD}--- LAN Ping Sweep ---{C_RESET}")
    base = input("Base IP prefix (e.g. 192.168.1): ").strip()

    if base.count(".") != 2:
        print(f"{C_RED}Use a three-octet prefix like 192.168.1{C_RESET}")
        return

    print(f"Sweeping {base}.1 – {base}.254 with 20 threads …\n")
    active: list[str] = []

    def check(i: int) -> None:
        ip = f"{base}.{i}"
        if _ping_once(ip):
            print(f"{C_GREEN}[+] {ip}{C_RESET}")
            active.append(ip)

    with ThreadPoolExecutor(max_workers=20) as pool:
        pool.map(check, range(1, 255))

    print(f"\n{C_BOLD}Sweep complete. {len(active)} active host(s) found.{C_RESET}")


# ---------------------------------------------------------------------------
# Real-Time Bandwidth Monitor (Linux only)
# ---------------------------------------------------------------------------

def tool_bandwidth_mon() -> None:
    """Display real-time RX/TX bandwidth by reading /proc/net/dev."""
    print(f"{C_BOLD}--- Real-Time Bandwidth Monitor (Linux only) ---{C_RESET}")

    if platform.system() != "Linux":
        print(f"{C_RED}This tool is Linux-only (/proc/net/dev).{C_RESET}")
        return

    iface = input("Interface (e.g. eth0, wlan0): ").strip()

    def _read_bytes() -> tuple[int, int] | tuple[None, None]:
        with open("/proc/net/dev") as f:
            for line in f:
                if iface in line:
                    cols = line.split(":")[1].split()
                    return int(cols[0]), int(cols[8])   # RX, TX bytes
        return None, None

    rx1, tx1 = _read_bytes()
    if rx1 is None:
        print(f"{C_RED}Interface '{iface}' not found in /proc/net/dev.{C_RESET}")
        return

    print(f"Monitoring {iface} … (Ctrl+C to stop)\n")
    try:
        while True:
            time.sleep(1)
            rx2, tx2 = _read_bytes()
            if rx2 is None:
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
