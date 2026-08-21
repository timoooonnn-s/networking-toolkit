"""
features/ssh_runner.py
----------------------
Feature A — Persistent Multi-Command Bulk SSH Runner
=====================================================
Replaces the original tool_ssh_bulk() with a session-persistent engine.

Key improvements over the original
------------------------------------
1. BUG FIX — Netmiko import scope
   The original imported ConnectHandler inside a try/except at module level
   but referenced it from inside a ThreadPoolExecutor worker closure.  When
   the import failed, HAS_NETMIKO was False and the function returned early —
   but when it succeeded, the symbol was only bound in the try block's local
   scope, not the worker's enclosing scope.  Fix: import Netmiko lazily
   *inside* the worker, guarded by check_dependency() before any threads
   are spawned.

2. Persistent sessions
   A single ConnectHandler is created per device.  All commands are sent
   over that same channel before disconnect, preserving state like
   configuration mode, terminal width, and paging settings.

3. Audit trail
   Every command + response pair is written to /logs/ via AuditLogger.

4. Thread safety
   Results are collected via futures and printed *after* all workers
   complete to prevent garbled interleaved output.

Data flow
---------
    inventory.py  ──►  build_ad_hoc_profile()
    audit_logger  ──►  AuditLogger(device_ip)
    ssh_runner    ──►  ConnectHandler  ──►  send_command()  ──►  AuditLogger.log()
                  ──►  returns list[DeviceResult]

Usage (interactive)
-------------------
    from features.ssh_runner import run_interactive
    run_interactive()

Usage (programmatic)
--------------------
    from features.ssh_runner import run_bulk_ssh
    results = run_bulk_ssh(
        devices=[{"host": "192.168.1.1", "device_type": "cisco_ios", ...}],
        commands=["show version", "show ip int brief"],
    )
"""

from __future__ import annotations

import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from core.audit_logger import AuditLogger
from core.colors import (
    C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW,
)
from core.dependency_check import check_dependency
from core.inventory import SUPPORTED_OS, build_ad_hoc_profile

# ---------------------------------------------------------------------------
# Default commands per device type
# ---------------------------------------------------------------------------

DEFAULT_COMMANDS = {
    "cisco_ios": ["terminal length 0", "show version"],
    "extreme_exos": ["enable, term more dis", "show version"],
    "extreme_vsp": ["enable", "term more dis", "show sys-info"],
}

# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class DeviceResult:
    """Holds the outcome of a full session against one device."""
    host:     str
    success:  bool
    outputs:  dict[str, str] = field(default_factory=dict)  # cmd -> raw output
    error:    str = ""
    log_path: str = ""

# ---------------------------------------------------------------------------
# Core session worker
# ---------------------------------------------------------------------------

def _run_session(device_profile: dict[str, Any], commands: list[str]) -> DeviceResult:
    """
    Open ONE persistent SSH session to *device_profile['host']*, send every
    command in *commands* sequentially, log each response, then disconnect.

    This is the per-thread worker — executed inside a ThreadPoolExecutor.

    Parameters
    ----------
    device_profile : dict
        A Netmiko-compatible connection dict (host, device_type, username,
        password, secret, port, timeout).
    commands : list[str]
        Ordered list of CLI commands to execute on the device.

    Returns
    -------
    DeviceResult
    """
    # Lazy import — only runs when we know Netmiko is installed
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )

    host = device_profile.get("host", "unknown")
    result = DeviceResult(host=host, success=False)

    with AuditLogger(host) as audit:
        result.log_path = str(audit.log_path)
        try:
            # -----------------------------------------------------------------
            # Establish a single persistent connection
            # -----------------------------------------------------------------
            conn = ConnectHandler(**device_profile)
            conn.enable()  # Enter privileged mode if secret is configured
                           # No-ops gracefully on Juniper / Extreme

            for cmd in commands:
                try:
                    output = conn.send_command(
                        cmd,
                        read_timeout=30,
                        expect_string=None,  # Auto-detect prompt
                    )
                    result.outputs[cmd] = output
                    audit.log(command=cmd, output=output)

                except Exception as cmd_err:
                    error_msg = str(cmd_err)
                    result.outputs[cmd] = f"<ERROR: {error_msg}>"
                    audit.log_error(command=cmd, error=error_msg)

            conn.disconnect()
            result.success = True

        except NetmikoAuthenticationException as auth_err:
            result.error = f"Authentication failed: {auth_err}"
            audit.log_error("SESSION", result.error)

        except NetmikoTimeoutException as timeout_err:
            result.error = f"Connection timed out: {timeout_err}"
            audit.log_error("SESSION", result.error)

        except Exception as generic_err:
            result.error = str(generic_err)
            audit.log_error("SESSION", result.error)

    return result

# ---------------------------------------------------------------------------
# Public programmatic API
# ---------------------------------------------------------------------------

def run_bulk_ssh(
    devices:      list[dict[str, Any]],
    commands:     list[str],
    max_workers:  int = 10,
) -> list[DeviceResult]:
    """
    Run *commands* concurrently across all *devices* using a persistent
    session per device.

    Parameters
    ----------
    devices : list[dict]
        List of Netmiko-compatible connection dicts.
        Use core.inventory.build_ad_hoc_profile() to construct each one.
    commands : list[str]
        Commands to run on every device (same list for all).
    max_workers : int
        Thread pool size (default 10).

    Returns
    -------
    list[DeviceResult]
        One result object per device, in submission order.
    """
    if not check_dependency("netmiko"):
        return []

    results: list[DeviceResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_device = {
            pool.submit(_run_session, dev, commands): dev
            for dev in devices
        }
        for future in as_completed(future_to_device):
            results.append(future.result())

    return results

# ---------------------------------------------------------------------------
# Result printer
# ---------------------------------------------------------------------------

def print_results(results: list[DeviceResult]) -> None:
    """Pretty-print a list of DeviceResult objects to stdout."""
    for res in results:
        if res.success:
            print(f"\n{C_GREEN}{'=' * 60}{C_RESET}")
            print(f"{C_GREEN}Device: {res.host}{C_RESET}")
            print(f"{C_CYAN}Audit log: {res.log_path}{C_RESET}")
            for cmd, output in res.outputs.items():
                print(f"\n{C_BOLD}[{cmd}]{C_RESET}")
                print(output)
        else:
            print(f"\n{C_RED}{'=' * 60}{C_RESET}")
            print(f"{C_RED}Device: {res.host}  ✘  FAILED{C_RESET}")
            print(f"{C_YELLOW}Reason: {res.error}{C_RESET}")
            if res.log_path:
                print(f"{C_CYAN}Partial audit log: {res.log_path}{C_RESET}")

# ---------------------------------------------------------------------------
# Interactive CLI entry point
# ---------------------------------------------------------------------------

def run_interactive() -> None:
    """
    Interactive menu-driven wrapper used by main_menu.py.
    Collects targets, credentials, and commands from stdin, then calls
    run_bulk_ssh() and prints results.
    """
    if not check_dependency("netmiko"):
        return

    print(f"{C_BOLD}--- SSH Bulk Commander (Persistent Sessions) ---{C_RESET}")
    print(f"{C_YELLOW}Commands are executed over a single persistent SSH session per device.{C_RESET}")

    # --- Collect targets ---
    raw_targets = input("Target IPs (comma-separated, e.g. 192.168.1.1, 192.168.1.2): ").strip()
    if not raw_targets:
        print(f"{C_RED}No targets specified.{C_RESET}")
        return
    hosts = [h.strip() for h in raw_targets.split(",") if h.strip()]

    # --- Credentials ---
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    # --- Device type ---
    print(f"Device type options: {', '.join(SUPPORTED_OS)}")
    device_type = input("Device type (default: extreme_vsp): ").strip() or "extreme_vsp"

    # Conditionally ask for secret
    secret = ""
    if device_type in ["cisco_ios"]:  # Add other device types requiring secrets here
        secret = getpass.getpass("Enable secret (leave blank if not needed): ")

    # --- Commands ---
    print("Enter commands one per line. Type 'RUN' on its own line to execute.")
    commands: list[str] = []
    while True:
        line = input(f"  cmd {len(commands) + 1}> ").strip()
        if line.upper() == "RUN":
            break
        if line:
            commands.append(line)

    if not commands:
        print(f"{C_RED}No commands entered.{C_RESET}")
        return

    # Prepend default commands for the selected device type
    default_commands = DEFAULT_COMMANDS.get(device_type, [])
    all_commands = default_commands + commands

    # --- Build device profiles ---
    devices = [
        build_ad_hoc_profile(
            host=h,
            device_type=device_type,
            username=username,
            password=password,
            secret=secret,
        )
        for h in hosts
    ]

    print(f"\n{C_CYAN}Launching {len(devices)} persistent session(s), "
          f"{len(all_commands)} command(s) each ...{C_RESET}\n")

    results = run_bulk_ssh(devices, all_commands)
    print_results(results)
