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
  Cisco IOS / IOS-XE  ──►  napalm-ios   driver
  Juniper Junos       ──►  napalm-junos driver

Extreme platforms (EXOS, VOSS, ERS) are deliberately *not* here: NAPALM has
no maintained driver for any of them, and the mapping this module used to
carry pointed extreme_exos at 'eos' — Arista's eAPI driver — so every getter
against Extreme gear was broken by construction.  Use the SSH-based tools
(bulk runner, backup, validator) for those instead; core.inventory raises
with that message rather than routing to another vendor's driver.

The normalized output schema is identical regardless of vendor, so all
downstream consumers (health dashboard, audit reports, etc.) use a single
code path.

Data flow
---------
    inventory.py  ──►  napalm_driver_for(device_type)
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

import json
from typing import Any

from core.colors import (
    C_BOLD,
    C_CYAN,
    C_GREEN,
    C_RED,
    C_RESET,
    C_YELLOW,
    pad,
)
from core.dependency_check import check_dependency
from core.export import export_json
from core.inventory import napalm_driver_for
from core.prompts import pick_target

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

        # Raises with an actionable message for platforms NAPALM cannot reach
        # (every Extreme family) rather than routing them to another vendor's
        # driver, which is what the old 'extreme_exos' -> 'eos' mapping did.
        driver_name = napalm_driver_for(device_type)

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

    def __enter__(self) -> NAPALMSession:
        self._device.open()
        return self

    def __exit__(self, *_) -> None:
        self._device.close()

    def open(self) -> NAPALMSession:
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
    """
    Render the normalized interface table.

    Uses pad() rather than f-string widths: an ANSI escape counts toward a
    format spec's width, so a coloured cell padded with '{:>4}' collapsed the
    column.  speed/description are guarded because NAPALM reports them as
    None on interfaces that have neither, and formatting None with ':.0f'
    used to raise mid-table and discard every remaining row.
    """
    print(f"\n{C_BOLD}{pad('Interface', 22)}{pad('Up', 5)}{pad('Enabled', 9)}"
          f"{pad('Speed (Mbps)', 14)}Description{C_RESET}")
    print("─" * 75)
    for iface, info in sorted(data.items()):
        up_str = f"{C_GREEN}YES{C_RESET}" if info.get("is_up") else f"{C_RED}NO{C_RESET}"
        en_str = (f"{C_GREEN}YES{C_RESET}" if info.get("is_enabled")
                  else f"{C_YELLOW}NO{C_RESET}")
        speed  = info.get("speed") or 0
        desc   = (info.get("description") or "")[:30]
        print(f"{pad(iface, 22)}{pad(up_str, 5)}{pad(en_str, 9)}"
              f"{pad(f'{float(speed):.0f}', 14)}{desc}")


def _print_bgp(data: dict) -> None:
    """Render the normalized BGP peer table (ANSI-safe padding, see above)."""
    global_data = data.get("global", {})
    print(f"\n{C_BOLD}Router ID: {global_data.get('router_id', 'N/A')}{C_RESET}")
    peers = global_data.get("peers", {})
    if not peers:
        print(f"{C_YELLOW}No BGP peers found.{C_RESET}")
        return
    print(f"\n{C_BOLD}{pad('Peer IP', 18)}{pad('Remote AS', 11, '>')}"
          f"{pad('State', 9, '>')}{pad('Uptime(s)', 11, '>')}"
          f"{pad('Rx Prefixes', 13, '>')}{C_RESET}")
    print("─" * 65)
    for peer_ip, pinfo in peers.items():
        state  = f"{C_GREEN}UP{C_RESET}" if pinfo.get("is_up") else f"{C_RED}DOWN{C_RESET}"
        rem_as = pinfo.get("remote_as", "?")
        uptime = pinfo.get("uptime", 0)
        rx_pfx = (pinfo.get("address_family", {})
                       .get("ipv4", {})
                       .get("received_prefixes", "?"))
        print(f"{pad(peer_ip, 18)}{pad(str(rem_as), 11, '>')}"
              f"{pad(state, 9, '>')}{pad(str(uptime), 11, '>')}"
              f"{pad(str(rx_pfx), 13, '>')}")


def _print_lldp(data: dict) -> None:
    """Render the normalized LLDP neighbour table."""
    print(f"\n{C_BOLD}{pad('Local Port', 22)}{pad('Neighbor Hostname', 26)}"
          f"Neighbor Port{C_RESET}")
    print("─" * 70)
    for local_port, neighbors in sorted(data.items()):
        for nb in neighbors:
            hostname = f"{C_CYAN}{nb.get('hostname') or '?'}{C_RESET}"
            print(f"{pad(local_port, 22)}{pad(hostname, 26)}{nb.get('port') or '?'}")


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
    print(f"{C_YELLOW}Normalized data for Cisco IOS/IOS-XE and Juniper Junos. "
          f"Extreme platforms have no NAPALM driver — use the SSH tools.{C_RESET}")

    target = pick_target(default_device_type="cisco_ios")
    if target is None:
        return
    name, profile = target
    host        = profile["host"]
    device_type = profile["device_type"]

    print("\nAvailable getters:")
    print("  1. Interfaces")
    print("  2. Interface Counters")
    print("  3. BGP Neighbors")
    print("  4. LLDP Neighbors")
    print("  5. Device Facts")
    print("  6. All (dump as JSON)")
    getter_choice = input("Choice [1-6]: ").strip()

    try:
        with NAPALMSession(host, device_type,
                           profile["username"], profile["password"]) as sess:
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
                for key, value in facts.items():
                    print(f"  {C_GREEN}{key:<20}{C_RESET} {value}")

            elif getter_choice == "6":
                all_data = {
                    "facts":              sess.get_facts(),
                    "interfaces":         sess.get_interfaces(),
                    "interface_counters": sess.get_interfaces_counters(),
                    "bgp_neighbors":      sess.get_bgp_neighbors(),
                    "lldp_neighbors":     sess.get_lldp_neighbors(),
                }
                print(f"\n{C_CYAN}{json.dumps(all_data, indent=2)}{C_RESET}")
                if input(f"\n{C_YELLOW}Save this dump to a file? (y/N): "
                         f"{C_RESET}").strip().lower() == "y":
                    export_json(all_data, f"napalm_{name}")

            else:
                print(f"{C_RED}Invalid choice.{C_RESET}")

    except ValueError as err:
        # Unsupported platform — the message already says what to use instead.
        print(f"{C_RED}{err}{C_RESET}")
    except Exception as err:
        print(f"{C_RED}Connection/getter error: {err}{C_RESET}")
