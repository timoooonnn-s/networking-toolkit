"""
core/prompts.py
---------------
Shared interactive target selection.

Every device-facing tool used to re-implement the same four prompts (host,
device type, username, password) and every one of them made the operator
retype an IP that was already sitting in the inventory.  This module is the
one place that turns "which device(s)?" into ready-to-use Netmiko profiles,
so the inventory is usable from any tool and the prompts stay consistent.

    from core.prompts import pick_targets

    targets = pick_targets(default_device_type="extreme_vsp")
    for name, profile in targets:
        ...
"""

from __future__ import annotations

import getpass
from typing import Any

from core.colors import C_BOLD, C_CYAN, C_RED, C_RESET, C_YELLOW
from core.inventory import (
    NEEDS_ENABLE_SECRET,
    SUPPORTED_OS,
    build_ad_hoc_profile,
    get_credentials,
    load_inventory,
    resolve_targets,
)


def _print_inventory_hint() -> None:
    inventory = load_inventory()
    if not inventory:
        print(f"{C_YELLOW}Inventory is empty — enter host details manually.{C_RESET}")
        return
    print(f"{C_CYAN}Inventory ({len(inventory)} device(s)):{C_RESET}")
    for name, entry in sorted(inventory.items()):
        tags = ",".join(str(t) for t in entry.get("tags", []))
        print(f"  {name:<24} {entry.get('host', ''):<16} "
              f"{entry.get('device_type', ''):<14} {tags}")


def pick_targets(
    default_device_type: str = "cisco_ios",
    allow_multiple: bool = True,
) -> list[tuple[str, dict[str, Any]]]:
    """
    Ask the operator for one or more targets and return (name, profile) pairs.

    Offers the inventory first — a selector accepts a device name, an IP, a
    ``tag:<tag>`` group or ``all`` — and falls back to manual entry.
    Credentials are resolved through core.inventory.get_credentials(), which
    caches them, so selecting 20 devices prompts for the password once.

    Returns an empty list when nothing was selected; callers just check that.
    """
    print(f"\n{C_BOLD}Target selection{C_RESET}")
    print("  1. Pick from inventory")
    print("  2. Enter host details manually")
    choice = input("Choice [1]: ").strip() or "1"

    if choice == "1":
        _print_inventory_hint()
        prompt = ("Device name / IP / tag:<tag> / all: " if allow_multiple
                  else "Device name or IP: ")
        selector = input(prompt).strip()
        if not selector:
            print(f"{C_RED}No target given.{C_RESET}")
            return []

        entries = resolve_targets(selector)
        if not entries:
            print(f"{C_RED}No matching inventory device.{C_RESET}")
            return []
        if not allow_multiple and len(entries) > 1:
            print(f"{C_YELLOW}This tool handles one device at a time; "
                  f"using '{entries[0][0]}'.{C_RESET}")
            entries = entries[:1]

        username, password = get_credentials()
        targets: list[tuple[str, dict[str, Any]]] = []
        for name, entry in entries:
            try:
                targets.append((name, build_ad_hoc_profile(
                    host        = entry["host"],
                    device_type = entry.get("device_type", default_device_type),
                    username    = username,
                    password    = password,
                    port        = int(entry.get("port", 22)),
                    secret      = entry.get("secret", ""),
                )))
            except ValueError as exc:
                print(f"{C_YELLOW}Skipping {name}: {exc}{C_RESET}")
        return targets

    # --- manual entry ---
    raw_hosts = input("Target IP(s) / hostname(s), comma-separated: ").strip()
    hosts = [h.strip() for h in raw_hosts.split(",") if h.strip()]
    if not hosts:
        print(f"{C_RED}No targets specified.{C_RESET}")
        return []
    if not allow_multiple:
        hosts = hosts[:1]

    print(f"Device type options: {', '.join(SUPPORTED_OS)}")
    device_type = (input(f"Device type [{default_device_type}]: ").strip()
                   or default_device_type)
    if device_type not in SUPPORTED_OS:
        print(f"{C_RED}Unsupported device type '{device_type}'. "
              f"Choose from: {', '.join(SUPPORTED_OS)}{C_RESET}")
        return []

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    secret   = ""
    if device_type in NEEDS_ENABLE_SECRET:
        secret = getpass.getpass("Enable secret (blank if none): ")

    return [
        (host, build_ad_hoc_profile(
            host=host, device_type=device_type,
            username=username, password=password, secret=secret,
        ))
        for host in hosts
    ]


def pick_target(default_device_type: str = "cisco_ios"):
    """Single-target convenience wrapper. Returns (name, profile) or None."""
    targets = pick_targets(default_device_type, allow_multiple=False)
    return targets[0] if targets else None
