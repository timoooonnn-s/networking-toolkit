"""
main_menu.py
------------
SysNet Toolkit — Interactive Entry Point
========================================
Wires every feature module into a single categorised menu.

    python3 main_menu.py        # interactive menu (this file)
    python3 cli.py --help       # the same tools, unattended

Module dependency tree
----------------------
main_menu.py
├── core/
│   ├── colors.py            — ANSI constants, ANSI-safe padding, banner
│   ├── paths.py             — every on-disk location, anchored to the project
│   ├── inventory.py         — inventory, credentials, platform maps
│   ├── prompts.py           — shared inventory-aware target selection
│   ├── connection.py        — VOSS/ERS-aware SSH session layer
│   ├── export.py            — CSV / JSON export
│   ├── dependency_check.py  — optional-dependency detection & install hints
│   └── audit_logger.py      — per-session SSH audit trail writer → logs/
└── features/
    ├── diagnostics.py       — CIDR, TCP, traceroute, SSL, DNS, public IP
    ├── system_health.py     — resources, processes, ports, log scanner
    ├── config_tools.py      — diff, snippets, diagram, Jinja2, interface parser
    ├── multiping.py         — multi-host reachability (fping / ping)
    ├── ssh_runner.py        — persistent multi-command SSH bulk runner
    ├── backup.py            — configuration backup + change detection
    ├── validator.py         — pre/post change validation
    ├── voss_parsers.py      — VOSS CLI output parsers (used by the validator)
    ├── napalm_interface.py  — NAPALM normalized getters
    ├── rollback.py          — multi-vendor config rollback generator
    ├── interface_health.py  — interface health dashboard
    └── ip_hardware.py       — SNMP, VLAN tracker, next-IP, bandwidth
"""

import sys
import time
import traceback

from core.colors import (
    C_BOLD,
    C_CYAN,
    C_RED,
    C_RESET,
    C_YELLOW,
    print_header,
    wait_for_user,
)
from core.dependency_check import print_dependency_status
from features.backup import run_interactive as tool_backup
from features.config_tools import (
    tool_config_diff,
    tool_diagram_gen,
    tool_intf_parser,
    tool_jinja_render,
    tool_snippet_lib,
)
from features.diagnostics import (
    tool_bulk_dns,
    tool_cidr_calc,
    tool_public_ip,
    tool_ssl_expiry,
    tool_tcp_tester,
    tool_traceroute_analyze,
)
from features.interface_health import run_interactive as tool_health_dashboard
from features.ip_hardware import (
    tool_bandwidth_mon,
    tool_next_ip,
    tool_snmp_discovery,
    tool_vlan_tracker,
)
from features.multiping import run_interactive as tool_multiping
from features.napalm_interface import run_interactive as tool_napalm
from features.rollback import run_interactive as tool_rollback
from features.ssh_runner import run_interactive as tool_ssh_bulk
from features.system_health import (
    tool_log_scanner,
    tool_port_listener,
    tool_sys_resource,
    tool_top_process,
)
from features.validator import run_interactive as tool_validator

# ---------------------------------------------------------------------------
# Menu definition
# ---------------------------------------------------------------------------

# Each entry: "key": ("Display label", callable)
TOOLS: dict[str, tuple[str, object]] = {

    # --- Diagnostics ---
    "1":  ("CIDR Subnet Calculator",           tool_cidr_calc),
    "2":  ("TCP Port Tester",                  tool_tcp_tester),
    "3":  ("SSL Expiry Checker",               tool_ssl_expiry),
    "4":  ("Bulk DNS Resolver",                tool_bulk_dns),
    "5":  ("Public IP & Geo",                  tool_public_ip),
    "6":  ("Traceroute Path Analyser",         tool_traceroute_analyze),
    "7":  ("Multi-Host Reachability Check",    tool_multiping),

    # --- System ---
    "8":  ("System Resource Snapshot",         tool_sys_resource),
    "9":  ("Top Process Hogger",               tool_top_process),
    "10": ("Service Port Listener",            tool_port_listener),
    "11": ("Log Keyword Scanner",              tool_log_scanner),

    # --- Automation & Config ---
    "12": ("Config File Diff",                 tool_config_diff),
    "13": ("Jinja2 Config Renderer",           tool_jinja_render),
    "14": ("Interface Config Parser",          tool_intf_parser),
    "15": ("SSH Bulk Commander",               tool_ssh_bulk),
    "16": ("Config Rollback Generator",        tool_rollback),
    "17": ("Config Snippet Library",           tool_snippet_lib),
    "18": ("ASCII Network Diagram",            tool_diagram_gen),

    # --- Change management ---
    "19": ("Configuration Backup",             tool_backup),
    "20": ("Pre / Post Change Validator",      tool_validator),

    # --- NAPALM & Health ---
    "21": ("NAPALM Multi-Vendor Getters",      tool_napalm),
    "22": ("Interface Health Dashboard",       tool_health_dashboard),

    # --- IP & Hardware ---
    "23": ("Next Available IP",                tool_next_ip),
    "24": ("Bandwidth Monitor",                tool_bandwidth_mon),
    "25": ("VLAN Planner / Tracker",           tool_vlan_tracker),
    "26": ("SNMP Device Discovery",            tool_snmp_discovery),
}

SECTIONS: list[tuple[str, list[str]]] = [
    ("DIAGNOSTICS",         ["1", "2", "3", "4", "5", "6", "7"]),
    ("SYSTEM",              ["8", "9", "10", "11"]),
    ("AUTOMATION & CONFIG", ["12", "13", "14", "15", "16", "17", "18"]),
    ("CHANGE MANAGEMENT",   ["19", "20"]),
    ("NAPALM & HEALTH",     ["21", "22"]),
    ("IP & HARDWARE",       ["23", "24", "25", "26"]),
]


def _print_menu() -> None:
    """Render the full categorised menu to stdout."""
    print_header()
    for section_title, keys in SECTIONS:
        print(f"{C_BOLD}--- {section_title} ---{C_RESET}")
        for key in keys:
            print(f"  [{key:>2}]  {TOOLS[key][0]}")
        print()

    print("─" * 40)
    print("  [ d]  Dependency status check")
    print("  [ q]  Exit")
    print(f"{C_CYAN}  Unattended equivalents: python3 cli.py --help{C_RESET}")
    print()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    while True:
        _print_menu()
        try:
            choice = input(f"{C_CYAN}Enter choice > {C_RESET}").strip().lower()
        except EOFError:
            print("\nGoodbye.")
            return

        if choice == "q":
            print("Goodbye.")
            return

        if choice == "d":
            print_dependency_status()
            wait_for_user()
            continue

        if choice not in TOOLS:
            print(f"{C_RED}Invalid selection '{choice}'. Try again.{C_RESET}")
            time.sleep(0.8)
            continue

        print("\n")
        try:
            TOOLS[choice][1]()
        except KeyboardInterrupt:
            print(f"\n{C_YELLOW}Operation cancelled.{C_RESET}")
        except EOFError:
            print(f"\n{C_YELLOW}Input ended — returning to the menu.{C_RESET}")
        except Exception:
            # A tool that raises must not take the whole session down with it.
            # Only KeyboardInterrupt used to be caught here, so any unexpected
            # error inside a tool ended the process and lost the operator's
            # place — the single change that turned two parsing bugs into
            # full crashes.
            print(f"\n{C_RED}'{TOOLS[choice][0]}' failed with an "
                  f"unexpected error:{C_RESET}")
            traceback.print_exc()
            print(f"{C_YELLOW}The toolkit is still running — this is a bug "
                  f"worth reporting.{C_RESET}")
        wait_for_user()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting.")
    sys.exit(0)
