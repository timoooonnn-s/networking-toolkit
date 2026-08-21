"""
features/napalm_interface.py
----------------------------
Feature B — NAPALM Data Normalization Interface
================================================
Provides a single, vendor-agnostic Python dictionary for:
  • get_interfaces()       — interface state, speed, MAC, counters
  • get_bgp_neighbors()    — BGP peer state, AS, prefixes
  • get_lldp_neighbors()   — LLDP neighbour topology

NAPALM abstracts the underlying CLI differences between:
  Cisco IOS / IOS-XE  ──►  napalm-ios  driver
  Juniper Junos        ──►  napalm-junos driver
  Extreme EXOS         ──►  napalm-eos  driver  (EOS-style API)

The normalized output schema is identical regardless of vendor, so all
downstream consumers (health dashboard, audit reports, etc.) use a single
code path.

Data flow
---------
    inventory.py  ──►  NAPALM_DRIVER_MAP[device_type]
    napalm        ──►  NAPALMDevice.open()
    getters       ──►  normalized dict
    caller        ──►  interface_health.py / CLI display

Usage (programmatic)
--------------------
    from features.napalm_interface import NAPALMSession

    with NAPALMSession("192.168.1.1", "cisco_ios", "admin", "secret") as sess:
        ifaces  = sess.get_interfaces()
        bgp     = sess.get_bgp_neighbors()
        lldp    = sess.get_lldp_neighbors()

Usage (interactive)
-------------------
    from features.napalm_interface import run_interactive
    run_interactive()
"""

from __future__ import annotations

import getpass
import json
from typing import Any

from core.colors import (
    C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW,
)
from core.dependency_check import check_dependency
from core.inventory import NAPALM_DRIVER_MAP, SUPPORTED_OS, build_ad_hoc_profile


# ---------------------------------------------------------------------------
# NAPALMSession — context-manager wrapper
# ---------------------------------------------------------------------------

class NAPALMSession:
    """
    Opens a NAPALM connection to a single device and exposes normalized
    getter methods.

    Parameters
    ----------
    host : str
        IP address or resolvable hostname.
    device_type : str
        Netmiko-style device type ('cisco_ios', 'juniper_junos', etc.).
        Automatically mapped to the correct NAPALM driver.
    username : str
    password : str
    optional_args : dict | None
        Extra NAPALM optional args (e.g. {"port": 830} for NETCONF).
    """

    def __init__(
        self,
        host:          str,
        device_type:   str,
        username:      str,
        password:      str,
        optional_args: dict | None = None,
    ) -> None:
        if not check_dependency("napalm"):
            raise ImportError("napalm is not installed — run: pip install napalm")

        import napalm  # lazy import — validated above

        driver_name = NAPALM_DRIVER_MAP.get(device_type)
        if not driver_name:
            raise ValueError(
                f"No NAPALM driver mapping found for '{device_type}'. "
                f"Supported: {list(NAPALM_DRIVER_MAP.keys())}"
            )

        driver = napalm.get_network_driver(driver_name)
        self._device = driver(
            hostname=host,
            username=username,
            password=password,
            optional_args=optional_args or {},
        )
        self.host        = host
        self.device_type = device_type

    # ------------------------------------------------------------------
    # Context-manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "NAPALMSession":
        self._device.open()
        return self

    def __exit__(self, *_) -> None:
        self._device.close()

    def open(self) -> "NAPALMSession":
        """Explicitly open the connection (alternative to context-manager)."""
        self._device.open()
        return self

    def close(self) -> None:
        """Explicitly close the connection."""
        self._device.close()

    # ------------------------------------------------------------------
    # Normalized getters
    # ------------------------------------------------------------------

    def get_interfaces(self) -> dict[str, dict[str, Any]]:
        """
        Return normalized interface data.

        Normalized schema (per interface key):
        {
            "is_up":           bool,
            "is_enabled":      bool,
            "description":     str,
            "last_flapped":    float,   # seconds since last flap, -1 if unknown
            "speed":           float,   # Mbps
            "mtu":             int,
            "mac_address":     str,
        }
        Identical output for Cisco, Juniper, and Extreme.
        """
        return self._device.get_interfaces()

    def get_interfaces_counters(self) -> dict[str, dict[str, Any]]:
        """
        Return normalized interface error/traffic counters.

        Normalized schema (per interface key):
        {
            "tx_errors":    int,
            "rx_errors":    int,
            "tx_discards":  int,
            "rx_discards":  int,
            "tx_octets":    int,
            "rx_octets":    int,
            "tx_unicast_packets": int,
            "rx_unicast_packets": int,
            "tx_multicast_packets": int,
            "rx_multicast_packets": int,
            "tx_broadcast_packets": int,
            "rx_broadcast_packets": int,
        }
        """
        return self._device.get_interfaces_counters()

    def get_bgp_neighbors(self) -> dict[str, Any]:
        """
        Return normalized BGP neighbour data.

        Normalized schema:
        {
            "global": {
                "router_id": str,
                "peers": {
                    "<peer_ip>": {
                        "local_as":          int,
                        "remote_as":         int,
                        "remote_id":         str,
                        "is_up":             bool,
                        "is_enabled":        bool,
                        "description":       str,
                        "uptime":            int,   # seconds
                        "address_family": {
                            "ipv4": {
                                "sent_prefixes":     int,
                                "accepted_prefixes": int,
                                "received_prefixes": int,
                            }
                        }
                    }
                }
            }
        }
        """
        return self._device.get_bgp_neighbors()

    def get_lldp_neighbors(self) -> dict[str, list[dict[str, str]]]:
        """
        Return normalized LLDP topology data.

        Normalized schema:
        {
            "<local_interface>": [
                {
                    "hostname": str,
                    "port":     str,
                }
            ]
        }
        """
        return self._device.get_lldp_neighbors()

    def get_facts(self) -> dict[str, Any]:
        """
        Return normalized device facts.

        Normalized schema:
        {
            "uptime":          int,    # seconds
            "vendor":          str,
            "model":           str,
            "hostname":        str,
            "fqdn":            str,
            "os_version":      str,
            "serial_number":   str,
            "interface_list":  list[str],
        }
        """
        return self._device.get_facts()


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _print_interfaces(data: dict) -> None:
    print(f"\n{C_BOLD}{'Interface':<22} {'Up':>4} {'Enabled':>8} {'Speed (Mbps)':>13} {'Description'}{C_RESET}")
    print("─" * 75)
    for iface, info in sorted(data.items()):
        up_str  = f"{C_GREEN}YES{C_RESET}"  if info.get("is_up")      else f"{C_RED}NO{C_RESET}"
        en_str  = f"{C_GREEN}YES{C_RESET}"  if info.get("is_enabled")  else f"{C_YELLOW}NO{C_RESET}"
        speed   = info.get("speed", 0)
        desc    = info.get("description", "")[:30]
        print(f"{iface:<22} {up_str:>4} {en_str:>8} {speed:>13.0f} {desc}")


def _print_bgp(data: dict) -> None:
    global_data = data.get("global", {})
    print(f"\n{C_BOLD}Router ID: {global_data.get('router_id', 'N/A')}{C_RESET}")
    peers = global_data.get("peers", {})
    if not peers:
        print(f"{C_YELLOW}No BGP peers found.{C_RESET}")
        return
    print(f"\n{C_BOLD}{'Peer IP':<18} {'Remote AS':>10} {'State':>8} {'Uptime(s)':>10} {'Rx Prefixes':>12}{C_RESET}")
    print("─" * 65)
    for peer_ip, pinfo in peers.items():
        state    = f"{C_GREEN}UP{C_RESET}"   if pinfo.get("is_up") else f"{C_RED}DOWN{C_RESET}"
        rem_as   = pinfo.get("remote_as", "?")
        uptime   = pinfo.get("uptime", 0)
        rx_pfx   = pinfo.get("address_family", {}).get("ipv4", {}).get("received_prefixes", "?")
        print(f"{peer_ip:<18} {rem_as:>10} {state:>8} {uptime:>10} {str(rx_pfx):>12}")


def _print_lldp(data: dict) -> None:
    print(f"\n{C_BOLD}{'Local Port':<22} {'Neighbor Hostname':<25} {'Neighbor Port'}{C_RESET}")
    print("─" * 70)
    for local_port, neighbors in sorted(data.items()):
        for nb in neighbors:
            print(f"{local_port:<22} {C_CYAN}{nb.get('hostname', '?'):<25}{C_RESET} {nb.get('port', '?')}")


# ---------------------------------------------------------------------------
# Interactive CLI entry point
# ---------------------------------------------------------------------------

def run_interactive() -> None:
    """
    Interactive menu-driven NAPALM getter tool used by main_menu.py.
    """
    if not check_dependency("napalm"):
        return

    print(f"{C_BOLD}--- NAPALM Multi-Vendor Data Interface ---{C_RESET}")
    print(f"{C_YELLOW}Outputs normalized data regardless of vendor (Cisco/Juniper/Extreme).{C_RESET}\n")

    host        = input("Device IP/Hostname: ").strip()
    print(f"Device type options: {', '.join(SUPPORTED_OS)}")
    device_type = input("Device type (default: cisco_ios): ").strip() or "cisco_ios"
    username    = input("Username: ").strip()
    password    = getpass.getpass("Password: ")

    print("\nAvailable getters:")
    print("  1. Interfaces")
    print("  2. Interface Counters")
    print("  3. BGP Neighbors")
    print("  4. LLDP Neighbors")
    print("  5. Device Facts")
    print("  6. All (dump as JSON)")
    getter_choice = input("Choice [1-6]: ").strip()

    try:
        with NAPALMSession(host, device_type, username, password) as sess:
            if getter_choice == "1":
                _print_interfaces(sess.get_interfaces())

            elif getter_choice == "2":
                data = sess.get_interfaces_counters()
                print(f"\n{C_CYAN}{json.dumps(data, indent=2)}{C_RESET}")

            elif getter_choice == "3":
                _print_bgp(sess.get_bgp_neighbors())

            elif getter_choice == "4":
                _print_lldp(sess.get_lldp_neighbors())

            elif getter_choice == "5":
                facts = sess.get_facts()
                print(f"\n{C_BOLD}Device Facts:{C_RESET}")
                for k, v in facts.items():
                    print(f"  {C_GREEN}{k:<20}{C_RESET} {v}")

            elif getter_choice == "6":
                all_data = {
                    "facts":               sess.get_facts(),
                    "interfaces":          sess.get_interfaces(),
                    "interface_counters":  sess.get_interfaces_counters(),
                    "bgp_neighbors":       sess.get_bgp_neighbors(),
                    "lldp_neighbors":      sess.get_lldp_neighbors(),
                }
                print(f"\n{C_CYAN}{json.dumps(all_data, indent=2)}{C_RESET}")

            else:
                print(f"{C_RED}Invalid choice.{C_RESET}")

    except Exception as err:
        print(f"{C_RED}Connection/getter error: {err}{C_RESET}")
