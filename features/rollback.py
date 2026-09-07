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
    rollback.py  ──►  RollbackEngine.push()       ──►  core.connection.SshRunner
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
from core.prompts import pick_target

# ---------------------------------------------------------------------------
# Vendor OS identifiers used as keys throughout this module
# ---------------------------------------------------------------------------
OS_CISCO  = ("cisco_ios", "cisco_xe")
OS_JUNOS  = ("juniper_junos",)
OS_EXOS   = ("extreme_exos",)
OS_VSP    = ("extreme_vsp",)
OS_ERS    = ("extreme_ers",)

# ERS and VSP are separate OS types, not strategies under EXOS.  They used to
# be reachable only as "strategies" of extreme_exos while being absent from
# SUPPORTED_OS entirely, so a generated ERS/VSP script could be printed but
# never pushed — build_ad_hoc_profile() rejected the device type.
ALL_OS_TYPES = OS_CISCO + OS_JUNOS + OS_EXOS + OS_VSP + OS_ERS


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
                # Interface context — 'default interface' resets the port to
                # factory settings, which is destructive.  The warning goes on
                # its OWN line: a trailing '! Verify before applying' does not
                # start with '!', so push()'s comment filter used to send the
                # whole string to the device, IOS rejected it, and the UI
                # still reported "Rollback pushed successfully".
                iface = parts[1] if len(parts) > 1 else ""
                rollback.append(
                    "! WARNING: 'default interface' resets the port to factory "
                    "settings — verify before applying."
                )
                rollback.append(f"default interface {iface}")

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
            # 'configure' first: rollback / show | compare / commit are
            # configuration-mode commands and fail outright from the
            # operational mode a session lands in.
            "configure",
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
            "configure",
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
            "configure",
            f"commit confirmed {minutes}",
            f"# You have {minutes} minutes to verify and run 'commit' to keep changes.",
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
            "# Pre-change: save running config as fallback",
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
            "# Pre-change backup:",
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
            "# Or explicitly:",
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
            elif parts[0] == "create" or parts[0] == "add":
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
            Cisco:        'inversion' | 'archive'
            Juniper:      'inversion' | 'rollback' | 'commit_confirmed'
            Extreme EXOS: 'inversion' | 'exos'
            Extreme VSP:  'vsp'
            Extreme ERS:  'ers'
            An unrecognised value raises ValueError rather than quietly
            producing a different script than the one asked for.
        archive_label : str
            Cisco archive filename (archive strategy only).
        junos_rollback_id : int
            Junos rollback version index (rollback strategy only).
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
        valid = VALID_STRATEGIES.get(_resolve_vendor_group(self.os_type), ())
        if strategy not in valid:
            # Silently falling back to 'inversion' turned a typo into a
            # *different rollback script* than the operator asked for.
            raise ValueError(
                f"Unknown strategy '{strategy}' for {self.os_type}. "
                f"Choose from: {', '.join(valid)}"
            )

        # --- Cisco ---
        if self.os_type in OS_CISCO:
            if strategy == "archive":
                return _CiscoRollback.generate_archive_rollback(archive_label)
            return _CiscoRollback.generate_inversion(cmds)

        # --- Juniper ---
        if self.os_type in OS_JUNOS:
            if strategy == "commit_confirmed":
                return _JuniperRollback.generate_commit_confirmed(commit_confirmed)
            if strategy == "rollback":
                return _JuniperRollback.generate_rollback(junos_rollback_id)
            return _JuniperRollback.generate_inversion(cmds)

        # --- Extreme EXOS ---
        if self.os_type in OS_EXOS:
            if strategy == "inversion":
                return _ExtremeRollback.generate_inversion(cmds)
            return _ExtremeRollback.generate_exos(save_filename)

        # --- Extreme VSP / VOSS ---
        if self.os_type in OS_VSP:
            return _ExtremeRollback.generate_vsp(save_filename)

        # --- Extreme ERS / BOSS ---
        if self.os_type in OS_ERS:
            return _ExtremeRollback.generate_ers(save_filename)

        return [f"# No rollback template for os_type='{self.os_type}'"]

    def push(
        self,
        device_profile: dict[str, Any],
        rollback_cmds:  list[str],
    ) -> bool:
        """
        Push *rollback_cmds* to the device and report what actually happened.

        Only non-comment lines are sent; comment lines ('#' / '!') are shown
        but never transmitted.  Each command's output is checked with
        looks_like_error(), because ``send_command_timing`` returns a device
        rejection as ordinary text — the previous version never inspected it
        and printed "Rollback pushed successfully" for a script the device
        had refused line by line.

        Returns True only when every command was accepted.
        """
        if not check_dependency("netmiko"):
            return False

        host = device_profile.get("host", "unknown")
        executable = [
            cmd for cmd in rollback_cmds
            if cmd.strip() and not cmd.strip().startswith(("#", "!"))
        ]
        if not executable:
            print(f"{C_YELLOW}Nothing to push — the script is all comments.{C_RESET}")
            return False

        print(f"\n{C_CYAN}Pushing {len(executable)} rollback command(s) "
              f"to {host} ...{C_RESET}")

        audit  = AuditLogger(host)
        runner = None
        failed: list[str] = []
        try:
            # SshRunner handles the platform's login gate, privilege step and
            # paging quirk, and never sends 'enable' to a Junos box.
            runner = SshRunner(device_profile, audit=audit)
            for warning in runner.setup_warnings:
                print(f"{C_YELLOW}  ! {warning}{C_RESET}")

            for cmd in executable:
                try:
                    # run_timing, not run: a rollback script switches modes
                    # ('configure terminal', 'end', Junos's 'configure'), and
                    # after the first one the prompt no longer matches the
                    # base prompt send_command() waits for.
                    output = runner.run_timing(cmd)
                except CommandError as exc:
                    failed.append(cmd)
                    print(f"  {C_RED}✘{C_RESET}  {cmd}")
                    detail = (exc.output or str(exc)).strip().splitlines()
                    if detail:
                        print(f"      {C_RED}{detail[-1][:100]}{C_RESET}")
                    continue
                print(f"  {C_GREEN}✔{C_RESET}  {cmd}")
                if output.strip():
                    print(f"      {C_CYAN}{output.strip().splitlines()[0][:80]}{C_RESET}")

        except ConnectionFailed as exc:
            print(f"{C_RED}Connection error: {exc}{C_RESET}")
            audit.log_error("ROLLBACK_SESSION", str(exc))
            audit.close()
            return False
        except Exception as exc:                    # noqa: BLE001
            print(f"{C_RED}Unexpected error: {exc}{C_RESET}")
            audit.log_error("ROLLBACK_SESSION", str(exc))
            return False
        finally:
            # A failure after connect used to leak the SSH session entirely.
            if runner is not None:
                runner.close()
            audit.close()

        if failed:
            print(f"\n{C_RED}Rollback INCOMPLETE — {len(failed)} of "
                  f"{len(executable)} command(s) were rejected:{C_RESET}")
            for cmd in failed:
                print(f"  {C_RED}- {cmd}{C_RESET}")
            print(f"{C_YELLOW}The device is in a partially rolled-back state. "
                  f"Review it before leaving the change window.{C_RESET}")
        else:
            print(f"\n{C_GREEN}Rollback pushed successfully — all "
                  f"{len(executable)} command(s) accepted.{C_RESET}")
        print(f"{C_CYAN}Audit log: {audit.log_path}{C_RESET}")
        return not failed

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
    "exos": {
        "1": "exos       — EXOS save/load configuration file",
        "2": "inversion  — Invert EXOS commands (enable/disable/configure)",
    },
    "vsp": {
        "1": "vsp        — VSP/VOSS backup + restore of running-config",
    },
    "ers": {
        "1": "ers        — ERS/BOSS copy config backup + restore",
    },
}

_STRATEGY_KEYS: dict[str, dict[str, str]] = {
    "cisco": {"1": "inversion", "2": "archive"},
    "junos": {"1": "inversion", "2": "rollback", "3": "commit_confirmed"},
    "exos":  {"1": "exos", "2": "inversion"},
    "vsp":   {"1": "vsp"},
    "ers":   {"1": "ers"},
}

# Accepted strategy names per vendor group — generate() validates against this
# instead of silently defaulting an unrecognised strategy to 'inversion'.
VALID_STRATEGIES: dict[str, tuple[str, ...]] = {
    group: tuple(keys.values()) for group, keys in _STRATEGY_KEYS.items()
}


def _resolve_vendor_group(os_type: str) -> str:
    """Map an OS type to its strategy family."""
    if os_type in OS_CISCO:
        return "cisco"
    if os_type in OS_JUNOS:
        return "junos"
    if os_type in OS_VSP:
        return "vsp"
    if os_type in OS_ERS:
        return "ers"
    if os_type in OS_EXOS:
        return "exos"
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
    strategy_choice = input("Strategy [1]: ").strip() or "1"
    strategy = _STRATEGY_KEYS[vendor_group].get(strategy_choice)
    if strategy is None:
        print(f"{C_RED}Invalid strategy '{strategy_choice}'.{C_RESET}")
        return

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
    if not check_dependency("netmiko"):
        return

    push = input(f"\n{C_YELLOW}Push this rollback to a device? (y/N): "
                 f"{C_RESET}").strip().lower()
    if push != "y":
        return

    target = pick_target(default_device_type=os_type)
    if target is None:
        return
    _name, profile = target

    if profile["device_type"] != os_type:
        print(f"{C_RED}This script was generated for {os_type} but "
              f"{profile['host']} is a {profile['device_type']} device — "
              f"not pushing.{C_RESET}")
        return

    engine.push(profile, rollback_cmds)
