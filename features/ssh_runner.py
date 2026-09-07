"""
features/ssh_runner.py
----------------------
Persistent Multi-Command Bulk SSH Runner
========================================
Run an ordered list of commands against many devices at once, each over a
single persistent session, with a full audit trail per device.

What this module does *not* do any more
---------------------------------------
It no longer opens or drives the SSH session itself.  The login ritual, the
privilege step, the paging quirk, error detection, retries and the circuit
breaker all live in core/connection.py, so every device-facing tool in the
toolkit behaves identically against VOSS, ERS, EXOS, IOS and Junos.  This
module is the fan-out, the result container and the presentation.

Data flow
---------
    core.prompts.pick_targets()  ──►  Netmiko profiles
    core.connection.SshRunner    ──►  one persistent session per device
    core.audit_logger.AuditLogger ──►  logs/<host>_<timestamp>.log
    run_bulk_ssh()               ──►  list[DeviceResult]

Usage (programmatic)
--------------------
    from features.ssh_runner import run_bulk_ssh
    results = run_bulk_ssh(
        devices=[{"host": "192.168.1.1", "device_type": "extreme_vsp", ...}],
        commands=["show sys-info"],
    )
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from core.audit_logger import AuditLogger
from core.colors import (
    C_BOLD,
    C_CYAN,
    C_GREEN,
    C_RED,
    C_RESET,
    C_YELLOW,
)
from core.connection import CommandError, ConnectionFailed, SshRunner
from core.dependency_check import check_dependency
from core.export import offer_export
from core.prompts import pick_targets

DEFAULT_DEVICE_TYPE = "extreme_vsp"


@dataclass
class DeviceResult:
    """Holds the outcome of a full session against one device."""
    host:      str
    success:   bool
    outputs:   dict[str, str] = field(default_factory=dict)  # cmd -> raw output
    failed:    list[str]      = field(default_factory=list)
    warnings:  list[str]      = field(default_factory=list)
    error:     str = ""
    log_path:  str = ""

    def as_rows(self) -> list[dict[str, str]]:
        """One export row per command, so a run is greppable as a table."""
        if not self.success:
            return [{"host": self.host, "command": "SESSION",
                     "status": "failed", "output": self.error}]
        return [
            {
                "host":    self.host,
                "command": command,
                "status":  "failed" if command in self.failed else "ok",
                "output":  output,
            }
            for command, output in self.outputs.items()
        ]


# ---------------------------------------------------------------------------
# Core session worker
# ---------------------------------------------------------------------------

def _run_session(device_profile: dict[str, Any], commands: list[str]) -> DeviceResult:
    """
    Open ONE persistent session to the device, send every command in order,
    log each response, then disconnect.

    This is the per-thread worker.  It never raises: a device that cannot be
    reached is one failed row in the report, not the end of the run.
    """
    host   = device_profile.get("host", "unknown")
    result = DeviceResult(host=host, success=False)

    audit = AuditLogger(host)
    result.log_path = str(audit.log_path)
    runner = None
    try:
        runner = SshRunner(device_profile, audit=audit)
        result.warnings = list(runner.setup_warnings)

        for command in commands:
            try:
                result.outputs[command] = runner.run(command)
            except CommandError as exc:
                # A rejected command is a fact about this release, not a
                # reason to abandon the remaining commands.
                result.outputs[command] = f"<ERROR: {exc}>"
                result.failed.append(command)

        result.success = True

    except ConnectionFailed as exc:
        result.error = str(exc)
        audit.log_error("SESSION", result.error)
    except Exception as exc:                      # noqa: BLE001
        result.error = f"{exc.__class__.__name__}: {exc}"
        audit.log_error("SESSION", result.error)
    finally:
        # Always closed, on every path.  A failure after connect (a bad enable
        # secret, say) used to leak the SSH session because disconnect() only
        # ran on the success path.
        if runner is not None:
            runner.close()
        audit.close()

    return result


# ---------------------------------------------------------------------------
# Public programmatic API
# ---------------------------------------------------------------------------

def run_bulk_ssh(
    devices:     list[dict[str, Any]],
    commands:    list[str],
    max_workers: int = 10,
) -> list[DeviceResult]:
    """
    Run *commands* concurrently across all *devices*, one persistent session
    each.  Results come back sorted by host so two runs are comparable.
    """
    if not check_dependency("netmiko"):
        return []
    if not devices or not commands:
        return []

    results: list[DeviceResult] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(devices))) as pool:
        futures = {
            pool.submit(_run_session, device, commands): device
            for device in devices
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.host)
    return results


# ---------------------------------------------------------------------------
# Result printer
# ---------------------------------------------------------------------------

def print_results(results: list[DeviceResult]) -> None:
    """Pretty-print a list of DeviceResult objects to stdout."""
    for result in results:
        if not result.success:
            print(f"\n{C_RED}{'=' * 60}{C_RESET}")
            print(f"{C_RED}Device: {result.host}  ✘  FAILED{C_RESET}")
            print(f"{C_YELLOW}Reason: {result.error}{C_RESET}")
            if result.log_path:
                print(f"{C_CYAN}Partial audit log: {result.log_path}{C_RESET}")
            continue

        print(f"\n{C_GREEN}{'=' * 60}{C_RESET}")
        print(f"{C_GREEN}Device: {result.host}{C_RESET}")
        print(f"{C_CYAN}Audit log: {result.log_path}{C_RESET}")
        for warning in result.warnings:
            print(f"{C_YELLOW}  ! {warning}{C_RESET}")
        for command, output in result.outputs.items():
            marker = f"{C_RED}✘{C_RESET}" if command in result.failed else f"{C_GREEN}✔{C_RESET}"
            print(f"\n{marker} {C_BOLD}[{command}]{C_RESET}")
            print(output)

    ok      = sum(1 for r in results if r.success)
    rejects = sum(len(r.failed) for r in results if r.success)
    print(f"\n{C_BOLD}{ok}/{len(results)} device(s) reachable"
          f"{f', {rejects} command(s) rejected' if rejects else ''}.{C_RESET}")


# ---------------------------------------------------------------------------
# Interactive CLI entry point
# ---------------------------------------------------------------------------

def run_interactive() -> None:
    """
    Interactive menu-driven wrapper used by main_menu.py.

    Targets come from the inventory or from manual entry — core.prompts
    validates the device type before any credential is asked for, so an
    unsupported type no longer raises ValueError *after* the operator has
    already typed a password.
    """
    if not check_dependency("netmiko"):
        return

    print(f"{C_BOLD}--- SSH Bulk Commander (Persistent Sessions) ---{C_RESET}")
    print(f"{C_YELLOW}Commands run over a single persistent session per "
          f"device. Paging is disabled automatically.{C_RESET}")

    targets = pick_targets(default_device_type=DEFAULT_DEVICE_TYPE)
    if not targets:
        return

    print("\nEnter commands one per line. Type 'RUN' on its own line to execute.")
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

    devices = [profile for _name, profile in targets]

    print(f"\n{C_CYAN}Launching {len(devices)} persistent session(s), "
          f"{len(commands)} command(s) each ...{C_RESET}\n")

    results = run_bulk_ssh(devices, commands)
    print_results(results)

    rows = [row for result in results for row in result.as_rows()]
    offer_export(rows, "ssh_bulk")
