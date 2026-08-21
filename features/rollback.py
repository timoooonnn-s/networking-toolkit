"""
features/rollback.py
--------------------
Feature E — Dynamic Multi-Vendor Configuration Rollback
========================================================
Provides a programmatic, OS-aware rollback interface that generates or
executes rollback operations contextually per vendor:

  Cisco IOS / IOS-XE  ──►  archive-based rollback  OR  "no <cmd>" inversion
  Juniper Junos        ──►  "rollback N" + "commit" / "commit confirmed"
  Extreme EXOS         ──►  fallback config save + load (ERS/VSP/Universal)

The user (or calling code) selects the target OS.  The module then:
  1. Generates a vendor-specific rollback script (dry-run, printed to screen)
  2. Optionally pushes it live via a persistent Netmiko session (with audit log)

Data flow
---------
    rollback.py  ──►  RollbackEngine.generate()  ──►  list[str] of rollback cmds
    rollback.py  ──►  RollbackEngine.push()       ──►  ssh_runner._run_session()
                                                  ──►  AuditLogger

Usage (programmatic)
--------------------
    from features.rollback import RollbackEngine

    engine = RollbackEngine(os_type="cisco_ios")
    rollback_cmds = engine.generate(["ip route 0.0.0.0 0.0.0.0 10.0.0.1"])
    print("\\n".join(rollback_cmds))

    # To push live (optional):
    engine.push(device_profile, rollback_cmds)

Usage (interactive)
-------------------
    from features.rollback import run_interactive
    run_interactive()
"""

from __future__ import annotations

import getpass
from typing import Any

from core.audit_logger import AuditLogger
from core.colors import (
    C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW,
)
from core.dependency_check import check_dependency
from core.inventory import SUPPORTED_OS, build_ad_hoc_profile

# ---------------------------------------------------------------------------
# Vendor OS identifiers used as keys throughout this module
# ---------------------------------------------------------------------------
OS_CISCO  = ("cisco_ios", "cisco_xe")
OS_JUNOS  = ("juniper_junos",)
OS_EXOS   = ("extreme_exos",)

ALL_OS_TYPES = OS_CISCO + OS_JUNOS + OS_EXOS


# ---------------------------------------------------------------------------
# Rollback strategy implementations
# ---------------------------------------------------------------------------

class _CiscoRollback:
    """
    Cisco IOS / IOS-XE rollback strategies.

    Strategy A — Archive rollback (requires 'archive' config on the device):
        Uses `rollback running-config file flash:archive_name`
        or  `configure replace flash:archive_name`

    Strategy B — Command inversion (no pre-existing archive required):
        Inverts each applied command using Cisco 'no' semantics.
    """

    @staticmethod
    def generate_inversion(commands: list[str]) -> list[str]:
        """
        Invert a list of Cisco IOS commands into their rollback counterparts.

        Logic
        -----
        - `no X`          → `X`            (remove the 'no' prefix)
        - `interface X`   → `default interface X`
        - `ip route ...`  → `no ip route ...`
        - everything else → `no <command>`
        """
        rollback: list[str] = [
            "! --- Cisco IOS Rollback Script (Auto-Generated) ---",
            "! Review carefully before applying.",
            "configure terminal",
        ]

        for cmd in commands:
            parts = cmd.strip().split()
            if not parts:
                continue

            if parts[0] == "no":
                # Inverse of 'no X' is 'X'
                rollback.append(" ".join(parts[1:]))

            elif parts[0].startswith("int"):
                # Interface context — use 'default' to reset to factory
                iface = parts[1] if len(parts) > 1 else ""
                rollback.append(f"default interface {iface}  ! Verify before applying")

            else:
                rollback.append(f"no {cmd}")

        rollback.extend(["end", "write memory"])
        return rollback

    @staticmethod
    def generate_archive_rollback(archive_label: str = "rollback_1") -> list[str]:
        """
        Generate commands to restore a Cisco archive snapshot.

        Parameters
        ----------
        archive_label : str
            The filename/label stored in flash (e.g. 'rollback_1').
        """
        return [
            "! --- Cisco IOS Archive Rollback ---",
            f"configure replace flash:{archive_label} force",
            "! If the above fails, try:",
            f"! rollback running-config file flash:{archive_label}",
        ]

    @staticmethod
    def generate_archive_save(archive_label: str = "rollback_1") -> list[str]:
        """Generate commands to save a pre-change archive snapshot."""
        return [
            "! --- Save pre-change archive ---",
            f"archive config",
            f"! Alternatively: copy running-config flash:{archive_label}",
        ]


class _JuniperRollback:
    """
    Juniper Junos rollback strategies.

    Junos maintains up to 50 committed configuration versions.
    'rollback 1' restores the previous committed config.
    'commit confirmed N' auto-reverts after N minutes unless confirmed.
    """

    @staticmethod
    def generate_rollback(rollback_id: int = 1) -> list[str]:
        """
        Generate a Junos rollback + commit sequence.

        Parameters
        ----------
        rollback_id : int
            Version index (0 = current, 1 = previous, etc.).
            Default is 1 (most recent prior commit).
        """
        return [
            "# --- Juniper Junos Rollback Script ---",
            f"rollback {rollback_id}",
            "show | compare",  # Review diff before committing
            "commit and-quit",
            "# If unsure, use 'commit confirmed 5' (auto-reverts in 5 min):",
            "# commit confirmed 5",
        ]

    @staticmethod
    def generate_inversion(set_commands: list[str]) -> list[str]:
        """
        Invert Junos 'set' commands into 'delete' equivalents.

        Junos 'delete' removes the stanza but cannot restore previous values
        without a snapshot.  Flag those with a comment.
        """
        rollback: list[str] = [
            "# --- Juniper Junos Command Inversion Rollback ---",
            "# WARNING: 'delete' removes the config stanza entirely.",
            "# For value restoration, use 'rollback N' instead.",
        ]

        for cmd in set_commands:
            parts = cmd.strip().split()
            if not parts:
                continue

            if parts[0] == "set":
                rollback.append(f"delete {' '.join(parts[1:])}")
            elif parts[0] == "delete":
                rollback.append(
                    f"# Cannot auto-invert 'delete' without prior value: {cmd}"
                )
            else:
                rollback.append(f"# Unknown prefix — review manually: {cmd}")

        rollback.extend(["commit and-quit"])
        return rollback

    @staticmethod
    def generate_commit_confirmed(minutes: int = 5) -> list[str]:
        """Generate a safe commit-confirmed with automatic revert."""
        return [
            "# --- Junos Commit Confirmed (Safety Net) ---",
            f"commit confirmed {minutes}",
            "# You have {minutes} minutes to verify and run 'commit' to keep changes.",
            "# If you do nothing, Junos will automatically rollback.",
        ]


class _ExtremeRollback:
    """
    Extreme Networks EXOS rollback strategies.

    Supports three Extreme platform families:
      ERS  — Extreme Routing Switch (older BayStack/Passport lineage)
      VSP  — Virtual Services Platform (Avaya/Extreme VSP series)
      EXOS — ExtremeXOS (X-series switches, the most common)
    """

    @staticmethod
    def generate_exos(save_filename: str = "rollback.cfg") -> list[str]:
        """
        Generate EXOS fallback configuration commands.

        Workflow:
          Pre-change  →  save a named checkpoint
          Post-change →  load checkpoint if rollback needed
        """
        return [
            "# --- Extreme EXOS Rollback Script ---",
            f"# Pre-change: save running config as fallback",
            f"save configuration {save_filename}",
            "#",
            "# To rollback after a bad change:",
            f"load configuration {save_filename}",
            "# Or reboot to primary saved config:",
            "# reboot",
        ]

    @staticmethod
    def generate_ers(save_filename: str = "config_backup.cfg") -> list[str]:
        """Generate ERS (Extreme Routing Switch) backup + restore commands."""
        return [
            "# --- Extreme ERS Rollback Script ---",
            f"# Pre-change backup:",
            f"copy config {save_filename}",
            "#",
            "# To restore:",
            f"restore config {save_filename}",
        ]

    @staticmethod
    def generate_vsp(save_filename: str = "vsp_rollback.cfg") -> list[str]:
        """Generate VSP (Virtual Services Platform) backup + restore commands."""
        return [
            "# --- Extreme VSP Rollback Script ---",
            "# Pre-change backup (from CLI):",
            "backup config",
            f"# Or explicitly:",
            f"copy running-config {save_filename}",
            "#",
            "# To restore:",
            f"copy {save_filename} running-config",
            "# Commit changes:",
            "save config",
        ]

    @staticmethod
    def generate_inversion(commands: list[str]) -> list[str]:
        """
        Invert EXOS commands.  EXOS uses 'disable' / 'unconfigure' as
        rollback primitives — not 'no' like Cisco.
        """
        rollback: list[str] = [
            "# --- Extreme EXOS Command Inversion ---",
        ]
        for cmd in commands:
            parts = cmd.strip().split()
            if not parts:
                continue

            if parts[0] == "enable":
                rollback.append(f"disable {' '.join(parts[1:])}")
            elif parts[0] == "disable":
                rollback.append(f"enable {' '.join(parts[1:])}")
            elif parts[0] == "configure":
                rollback.append(f"unconfigure {' '.join(parts[1:])}")
            elif parts[0] == "create":
                rollback.append(f"delete {' '.join(parts[1:])}")
            elif parts[0] == "add":
                rollback.append(f"delete {' '.join(parts[1:])}")
            else:
                rollback.append(f"# Manual review required: {cmd}")

        return rollback


# ---------------------------------------------------------------------------
# RollbackEngine — unified interface
# ---------------------------------------------------------------------------

class RollbackEngine:
    """
    Unified rollback generator and optional live-push interface.

    Parameters
    ----------
    os_type : str
        One of the SUPPORTED_OS strings.  Used to route to the correct
        vendor-specific rollback implementation.
    """

    def __init__(self, os_type: str) -> None:
        if os_type not in ALL_OS_TYPES:
            raise ValueError(
                f"Unsupported os_type '{os_type}'. "
                f"Choose from: {ALL_OS_TYPES}"
            )
        self.os_type = os_type

    def generate(
        self,
        commands:          list[str] | None = None,
        strategy:          str = "inversion",
        archive_label:     str = "rollback_1",
        junos_rollback_id: int = 1,
        extreme_platform:  str = "exos",
        save_filename:     str = "rollback.cfg",
        commit_confirmed:  int = 5,
    ) -> list[str]:
        """
        Generate rollback commands for this engine's OS type.

        Parameters
        ----------
        commands : list[str] | None
            Applied commands to invert (required for 'inversion' strategy).
        strategy : str
            For Cisco: 'inversion' or 'archive'.
            For Juniper: 'inversion', 'rollback', or 'commit_confirmed'.
            For Extreme: 'inversion', 'exos', 'ers', or 'vsp'.
        archive_label : str
            Cisco archive filename (archive strategy only).
        junos_rollback_id : int
            Junos rollback version index (rollback strategy only).
        extreme_platform : str
            Extreme sub-platform: 'exos', 'ers', or 'vsp'.
        save_filename : str
            Extreme config filename for save/load operations.
        commit_confirmed : int
            Minutes for Junos commit confirmed auto-revert.

        Returns
        -------
        list[str]
            Ordered list of rollback commands/comments ready for review
            or direct push.
        """
        cmds = commands or []

        # --- Cisco ---
        if self.os_type in OS_CISCO:
            if strategy == "archive":
                return _CiscoRollback.generate_archive_rollback(archive_label)
            else:  # default: inversion
                return _CiscoRollback.generate_inversion(cmds)

        # --- Juniper ---
        elif self.os_type in OS_JUNOS:
            if strategy == "commit_confirmed":
                return _JuniperRollback.generate_commit_confirmed(commit_confirmed)
            elif strategy == "rollback":
                return _JuniperRollback.generate_rollback(junos_rollback_id)
            else:  # default: inversion
                return _JuniperRollback.generate_inversion(cmds)

        # --- Extreme ---
        elif self.os_type in OS_EXOS:
            if strategy == "ers":
                return _ExtremeRollback.generate_ers(save_filename)
            elif strategy == "vsp":
                return _ExtremeRollback.generate_vsp(save_filename)
            elif strategy == "inversion":
                return _ExtremeRollback.generate_inversion(cmds)
            else:  # default: exos
                return _ExtremeRollback.generate_exos(save_filename)

        return [f"# No rollback template for os_type='{self.os_type}'"]

    def push(
        self,
        device_profile: dict[str, Any],
        rollback_cmds:  list[str],
    ) -> None:
        """
        Push *rollback_cmds* to the device via a persistent Netmiko session.

        Only non-comment lines are sent to the device.  Comment lines
        (starting with '#' or '!') are logged but not transmitted.

        Parameters
        ----------
        device_profile : dict
            Netmiko-compatible connection dict.
        rollback_cmds : list[str]
            Output of self.generate().
        """
        if not check_dependency("netmiko"):
            return

        from netmiko import ConnectHandler
        from netmiko.exceptions import (
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
        )

        host = device_profile.get("host", "unknown")
        executable = [
            cmd for cmd in rollback_cmds
            if cmd.strip() and not cmd.strip().startswith(("#", "!"))
        ]

        print(f"\n{C_CYAN}Pushing {len(executable)} rollback commands to {host} ...{C_RESET}")

        with AuditLogger(host) as audit:
            try:
                conn = ConnectHandler(**device_profile)
                conn.enable()

                for cmd in executable:
                    output = conn.send_command_timing(cmd)
                    audit.log(command=cmd, output=output)
                    print(f"  {C_GREEN}✔{C_RESET}  {cmd}")
                    if output.strip():
                        print(f"      {C_CYAN}{output[:80]}{C_RESET}")

                conn.disconnect()
                print(f"\n{C_GREEN}Rollback pushed successfully.{C_RESET}")
                print(f"{C_CYAN}Audit log: {audit.log_path}{C_RESET}")

            except (NetmikoAuthenticationException, NetmikoTimeoutException) as conn_err:
                print(f"{C_RED}Connection error: {conn_err}{C_RESET}")
                audit.log_error("ROLLBACK_SESSION", str(conn_err))

            except Exception as err:
                print(f"{C_RED}Unexpected error: {err}{C_RESET}")
                audit.log_error("ROLLBACK_SESSION", str(err))


# ---------------------------------------------------------------------------
# Strategy menu helpers for CLI
# ---------------------------------------------------------------------------

_STRATEGY_MENUS: dict[str, dict[str, str]] = {
    "cisco": {
        "1": "inversion   — Invert applied commands with 'no' logic",
        "2": "archive     — Restore from Cisco flash archive snapshot",
    },
    "junos": {
        "1": "inversion        — Convert 'set' commands to 'delete'",
        "2": "rollback         — Junos 'rollback N' + 'commit'",
        "3": "commit_confirmed — 'commit confirmed N' (auto-revert safety net)",
    },
    "extreme": {
        "1": "exos       — EXOS save/load configuration file",
        "2": "ers        — ERS copy config backup/restore",
        "3": "vsp        — VSP copy running-config backup/restore",
        "4": "inversion  — Invert EXOS commands (enable/disable/configure)",
    },
}

_STRATEGY_KEYS: dict[str, dict[str, str]] = {
    "cisco":   {"1": "inversion", "2": "archive"},
    "junos":   {"1": "inversion", "2": "rollback", "3": "commit_confirmed"},
    "extreme": {"1": "exos", "2": "ers", "3": "vsp", "4": "inversion"},
}


def _resolve_vendor_group(os_type: str) -> str:
    if os_type in OS_CISCO:
        return "cisco"
    if os_type in OS_JUNOS:
        return "junos"
    if os_type in OS_EXOS:
        return "extreme"
    return "cisco"


# ---------------------------------------------------------------------------
# Interactive CLI entry point
# ---------------------------------------------------------------------------

def run_interactive() -> None:
    """
    Interactive menu-driven rollback generator used by main_menu.py.
    """
    print(f"{C_BOLD}--- Dynamic Multi-Vendor Config Rollback Generator ---{C_RESET}")

    # --- Select OS type ---
    print(f"\n{C_BOLD}Select target OS:{C_RESET}")
    for i, os_t in enumerate(ALL_OS_TYPES, 1):
        print(f"  [{i}] {os_t}")
    os_choice = input("Choice: ").strip()
    try:
        os_type = ALL_OS_TYPES[int(os_choice) - 1]
    except (ValueError, IndexError):
        print(f"{C_RED}Invalid choice.{C_RESET}")
        return

    vendor_group = _resolve_vendor_group(os_type)
    engine       = RollbackEngine(os_type)

    # --- Select rollback strategy ---
    print(f"\n{C_BOLD}Rollback strategies for {C_CYAN}{os_type}{C_RESET}{C_BOLD}:{C_RESET}")
    for key, desc in _STRATEGY_MENUS[vendor_group].items():
        print(f"  [{key}] {desc}")
    strategy_choice = input("Strategy: ").strip()
    strategy = _STRATEGY_KEYS[vendor_group].get(strategy_choice, "inversion")

    # --- Collect applied commands (for inversion strategies) ---
    commands: list[str] = []
    if "inversion" in strategy:
        print("\nEnter the commands that were applied (to be inverted).")
        print("Type 'END' on its own line when done.")
        while True:
            line = input(f"  cmd {len(commands) + 1}> ").strip()
            if line.upper() == "END":
                break
            if line:
                commands.append(line)

    # --- Vendor-specific extra parameters ---
    extra_kwargs: dict[str, Any] = {}

    if vendor_group == "cisco" and strategy == "archive":
        extra_kwargs["archive_label"] = (
            input("Archive filename (default: rollback_1): ").strip() or "rollback_1"
        )

    elif vendor_group == "junos" and strategy == "rollback":
        raw_id = input("Rollback version ID (default: 1): ").strip()
        extra_kwargs["junos_rollback_id"] = int(raw_id) if raw_id.isdigit() else 1

    elif vendor_group == "junos" and strategy == "commit_confirmed":
        raw_min = input("Commit confirmed timeout in minutes (default: 5): ").strip()
        extra_kwargs["commit_confirmed"] = int(raw_min) if raw_min.isdigit() else 5

    elif vendor_group == "extreme" and strategy in ("exos", "ers", "vsp"):
        extra_kwargs["save_filename"] = (
            input("Config filename (default: rollback.cfg): ").strip() or "rollback.cfg"
        )

    # --- Generate and display ---
    rollback_cmds = engine.generate(commands=commands, strategy=strategy, **extra_kwargs)

    print(f"\n{C_BOLD}--- Generated Rollback Script ({os_type} / {strategy}) ---{C_RESET}")
    for line in rollback_cmds:
        if line.startswith(("#", "!")):
            print(f"{C_YELLOW}{line}{C_RESET}")
        else:
            print(f"{C_CYAN}{line}{C_RESET}")

    # --- Optionally push live ---
    if check_dependency("netmiko"):
        push = input(f"\n{C_YELLOW}Push this rollback to a device? (y/N): {C_RESET}").strip().lower()
        if push == "y":
            host     = input("Device IP: ").strip()
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            secret   = getpass.getpass("Enable secret (blank if none): ")

            profile = build_ad_hoc_profile(
                host=host,
                device_type=os_type,
                username=username,
                password=password,
                secret=secret,
            )
            engine.push(profile, rollback_cmds)
