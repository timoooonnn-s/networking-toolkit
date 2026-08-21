"""
main_menu.py
------------
SysNet Toolkit — Main Entry Point
===================================
Wires together all feature modules into a single interactive menu.
Run with:  python main_menu.py

Module dependency tree
----------------------
main_menu.py
├── core/
│   ├── colors.py            — ANSI constants, print_header(), wait_for_user()
│   ├── inventory.py         — Device inventory, credential helpers, profile builders
│   ├── dependency_check.py  — Optional-dependency detection & install hints
│   └── audit_logger.py      — Per-session SSH audit trail writer → /logs/
└── features/
    ├── diagnostics.py       — CIDR, TCP, Traceroute, SSL, DNS, Public IP
    ├── system_health.py     — Resources, processes, ports, log scanner
    ├── config_tools.py      — Diff, snippets, diagram, Jinja2, interface parser
    ├── ssh_runner.py        — Feature A: Persistent multi-command SSH bulk runner
    ├── napalm_interface.py  — Feature B: NAPALM normalized getters
    ├── rollback.py          — Feature E: Multi-vendor config rollback generator
    ├── interface_health.py  — Feature D: Interface health dashboard
    └── ip_hardware.py       — MAC, SNMP, VLAN, next-IP, ping sweep, bandwidth
"""

import sys
import time

# ---------------------------------------------------------------------------
# Core imports — always available (stdlib only)
# ---------------------------------------------------------------------------
from core.colors import (
    C_BOLD, C_CYAN, C_RED, C_RESET, C_YELLOW,
    print_header, wait_for_user,
)
from core.dependency_check import print_dependency_status

# ---------------------------------------------------------------------------
# Feature imports — each module is self-contained and handles its own
# missing-dependency guard via check_dependency()
# ---------------------------------------------------------------------------
from features.diagnostics import (
    tool_cidr_calc,
    tool_tcp_tester,
    tool_traceroute_analyze,
    tool_ssl_expiry,
    tool_bulk_dns,
    tool_public_ip,
)
from features.system_health import (
    tool_sys_resource,
    tool_top_process,
    tool_port_listener,
    tool_log_scanner,
)
from features.config_tools import (
    tool_config_diff,
    tool_snippet_lib,
    tool_diagram_gen,
    tool_jinja_render,
    tool_intf_parser,
)
from features.ssh_runner       import run_interactive  as tool_ssh_bulk
from features.napalm_interface import run_interactive  as tool_napalm
from features.interface_health import run_interactive  as tool_health_dashboard
from features.rollback         import run_interactive  as tool_rollback
from features.ip_hardware import (
    tool_mac_oui,
    tool_snmp_discovery,
    tool_vlan_tracker,
    tool_next_ip,
    tool_ping_sweep,
    tool_bandwidth_mon,
)


# ---------------------------------------------------------------------------
# Menu definition
# ---------------------------------------------------------------------------

# Each entry: "key": ("Display label", callable)
TOOLS: dict[str, tuple[str, object]] = {

    # --- Diagnostics ---
    "1":  ("CIDR Subnet Calculator",          tool_cidr_calc),
    "2":  ("TCP Port Tester",                  tool_tcp_tester),
    "3":  ("SSL Expiry Checker",               tool_ssl_expiry),
    "4":  ("Bulk DNS Resolver",                tool_bulk_dns),
    "5":  ("Public IP & Geo",                  tool_public_ip),
    "6":  ("Traceroute Path Analyser",         tool_traceroute_analyze),

    # --- System ---
    "7":  ("System Resource Snapshot",         tool_sys_resource),
    "8":  ("Top Process Hogger",               tool_top_process),
    "9":  ("Service Port Listener",            tool_port_listener),
    "10": ("Log Keyword Scanner",              tool_log_scanner),

    # --- Automation & Config ---
    "11": ("Config File Diff",                 tool_config_diff),
    "12": ("Jinja2 Config Renderer",           tool_jinja_render),
    "13": ("Interface Config Parser",          tool_intf_parser),
    "14": ("SSH Bulk Commander  ★ NEW",        tool_ssh_bulk),          # Feature A
    "15": ("Config Rollback Generator  ★ NEW", tool_rollback),          # Feature E
    "16": ("Config Snippet Library",           tool_snippet_lib),
    "17": ("ASCII Network Diagram",            tool_diagram_gen),

    # --- NAPALM & Health (new features) ---
    "18": ("NAPALM Multi-Vendor Getters  ★",   tool_napalm),            # Feature B
    "19": ("Interface Health Dashboard  ★",    tool_health_dashboard),  # Feature D

    # --- IP & Hardware ---
    "20": ("MAC Vendor Lookup",                tool_mac_oui),
    "21": ("Next Available IP",                tool_next_ip),
    "22": ("LAN Ping Sweep",                   tool_ping_sweep),
    "23": ("Bandwidth Monitor",                tool_bandwidth_mon),
    "24": ("VLAN Planner / Tracker",           tool_vlan_tracker),
    "25": ("SNMP Device Discovery",            tool_snmp_discovery),
}

SECTIONS: list[tuple[str, list[str]]] = [
    ("DIAGNOSTICS",         ["1",  "2",  "3",  "4",  "5",  "6"]),
    ("SYSTEM",              ["7",  "8",  "9",  "10"]),
    ("AUTOMATION & CONFIG", ["11", "12", "13", "14", "15", "16", "17"]),
    ("NAPALM & HEALTH",     ["18", "19"]),
    ("IP & HARDWARE",       ["20", "21", "22", "23", "24", "25"]),
]


def _print_menu() -> None:
    """Render the full categorised menu to stdout."""
    print_header()
    for section_title, keys in SECTIONS:
        print(f"{C_BOLD}--- {section_title} ---{C_RESET}")
        for k in keys:
            label = TOOLS[k][0]
            print(f"  [{k:>2}]  {label}")
        print()

    print("─" * 35)
    print(f"  [ d]  Dependency status check")
    print(f"  [ q]  Exit")
    print()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    while True:
        _print_menu()
        choice = input(f"{C_CYAN}Enter choice > {C_RESET}").strip().lower()

        if choice == "q":
            print("Goodbye.")
            sys.exit(0)

        if choice == "d":
            print_dependency_status()
            wait_for_user()
            continue

        if choice in TOOLS:
            print("\n")
            try:
                TOOLS[choice][1]()
            except KeyboardInterrupt:
                print(f"\n{C_YELLOW}Operation cancelled.{C_RESET}")
            wait_for_user()
        else:
            print(f"{C_RED}Invalid selection '{choice}'. Try again.{C_RESET}")
            time.sleep(0.8)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting.")
        sys.exit(0)
