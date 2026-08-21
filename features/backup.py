"""
features/backup.py
------------------
Configuration Backup
====================
Pull the running configuration from every device in the inventory into a
timestamped, diffable directory tree — on demand, or on a schedule.

    backups/
      core-router-01/
        20260821_141500.cfg
        20260820_141500.cfg
        latest.cfg          <- a copy, not a symlink, so it survives rsync
      access-vsp-01/
        ...

Change detection
----------------
Every device's new capture is compared against its previous one, so a run
reports *which devices changed*, not just that it finished.  Volatile lines
(the VOSS command-execution banner, IOS's "Last configuration change", NTP
clock drift) are stripped before comparison — otherwise every device looks
changed on every run and the signal is worthless.

Scheduling
----------
The tool does not run a daemon.  ``print_schedule_hint()`` emits the exact
cron line for the non-interactive entry point, which is both simpler and
more honest than a sleep loop inside a menu-driven program:

    0 2 * * *  cd /path/to/toolkit && python3 cli.py backup --targets all

Usage (programmatic)
--------------------
    from features.backup import backup_targets
    results = backup_targets("all")
"""

from __future__ import annotations

import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from core.audit_logger import AuditLogger
from core.colors import C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW, pad
from core.connection import CommandError, ConnectionFailed, SshRunner
from core.dependency_check import check_dependency
from core.export import offer_export
from core.inventory import build_ad_hoc_profile, get_credentials, resolve_targets
from core.paths import BACKUP_DIR, ensure_dir

# ---------------------------------------------------------------------------
# Per-platform running-config command
# ---------------------------------------------------------------------------
RUNNING_CONFIG_COMMAND: dict[str, str] = {
    "cisco_ios":     "show running-config",
    "cisco_xe":      "show running-config",
    "juniper_junos": "show configuration | display set",
    "extreme_exos":  "show configuration",
    "extreme_vsp":   "show running-config",
    "extreme_ers":   "show running-config",
}

# Lines that differ on every capture of an unchanged device.  Stripping them
# is what makes "3 of 12 devices changed" mean something.
_VOLATILE_PATTERNS = (
    re.compile(r"Command Execution Time\s*:", re.IGNORECASE),       # VOSS banner
    re.compile(r"^\s*!\s*Last configuration change", re.IGNORECASE),  # IOS
    re.compile(r"^\s*!\s*NVRAM config last updated", re.IGNORECASE),  # IOS
    re.compile(r"^\s*ntp clock-period", re.IGNORECASE),               # IOS drift
    re.compile(r"^\s*#\s*(?:config|configuration) generated", re.IGNORECASE),
    re.compile(r"^\s*!\s*Time:", re.IGNORECASE),
    # A comment line that is just a timestamp.  VOSS stamps the capture time
    # into `show running-config` as a bare '# Fri Jul 24 09:40:46 2026 CEST',
    # so without this every device looks changed on every run and the whole
    # change report becomes noise.
    re.compile(r"^\s*[#!]\s*(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
               r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d",
               re.IGNORECASE),
    re.compile(r"^[*=\-]{20,}$"),                                     # banner rules
)

DEFAULT_WORKERS = 8


@dataclass
class BackupResult:
    """The outcome of backing up one device."""
    name:     str
    host:     str
    ok:       bool
    changed:  bool = False
    path:     Path | None = None
    error:    str = ""
    warnings: list[str] | None = None

    def as_row(self) -> dict[str, object]:
        return {
            "device":  self.name,
            "host":    self.host,
            "status":  "ok" if self.ok else "failed",
            "changed": "yes" if self.changed else "no",
            "path":    str(self.path) if self.path else "",
            "error":   self.error,
        }


def normalise_config(text: str) -> str:
    """
    Strip volatile lines and trailing whitespace so two captures of an
    unchanged device compare equal.
    """
    kept: list[str] = []
    for line in text.splitlines():
        if any(pattern.search(line) for pattern in _VOLATILE_PATTERNS):
            continue
        kept.append(line.rstrip())
    # Collapse trailing blank lines, which VOSS varies between captures.
    while kept and not kept[-1]:
        kept.pop()
    return "\n".join(kept)


def previous_backup(device_dir: Path) -> Path | None:
    """The most recent existing capture for a device, or None on first run."""
    if not device_dir.is_dir():
        return None
    captures = sorted(
        (p for p in device_dir.glob("*.cfg") if p.name != "latest.cfg"),
        key=lambda p: p.name,
    )
    return captures[-1] if captures else None


def backup_one(
    name: str,
    profile: dict[str, Any],
    root: Path | None = None,
    audit: bool = True,
) -> BackupResult:
    """
    Open one session, pull the running config, and write it under
    ``backups/<name>/<timestamp>.cfg``.

    Never raises: a device that cannot be reached is one failed row in the
    report, not the end of the run.
    """
    host        = profile.get("host", "unknown")
    device_type = profile.get("device_type", "cisco_ios")
    command     = RUNNING_CONFIG_COMMAND.get(device_type, "show running-config")
    result      = BackupResult(name=name, host=host, ok=False, warnings=[])

    audit_logger = AuditLogger(host) if audit else None
    runner = None
    try:
        runner = SshRunner(profile, audit=audit_logger)
        result.warnings = list(runner.setup_warnings)
        output = runner.run(command, read_timeout=120)
    except ConnectionFailed as exc:
        result.error = str(exc)
        return result
    except CommandError as exc:
        result.error = f"'{command}' failed: {exc}"
        return result
    except Exception as exc:                     # noqa: BLE001 — one bad device
        result.error = f"{exc.__class__.__name__}: {exc}"
        return result
    finally:
        if runner is not None:
            runner.close()
        if audit_logger is not None:
            audit_logger.close()

    device_dir = ensure_dir((root or BACKUP_DIR) / name)
    previous   = previous_backup(device_dir)
    stamp      = datetime.now().strftime("%Y%m%d_%H%M%S")
    path       = device_dir / f"{stamp}.cfg"

    try:
        path.write_text(output, encoding="utf-8")
        shutil.copyfile(path, device_dir / "latest.cfg")
    except OSError as exc:
        result.error = f"could not write backup: {exc}"
        return result

    if previous is not None:
        try:
            result.changed = (
                normalise_config(previous.read_text(encoding="utf-8", errors="replace"))
                != normalise_config(output)
            )
        except OSError:
            result.changed = True
    else:
        result.changed = True      # first capture always counts as a change

    result.ok   = True
    result.path = path
    return result


def backup_targets(
    selector: str = "all",
    workers: int = DEFAULT_WORKERS,
    root: Path | None = None,
    username: str | None = None,
    password: str | None = None,
) -> list[BackupResult]:
    """
    Back up every inventory device matching *selector* (see
    core.inventory.resolve_targets for the accepted forms).

    Credentials are resolved once and reused across the fan-out, so a 40-device
    run prompts once rather than 40 times.
    """
    targets = resolve_targets(selector)
    if not targets:
        return []

    if username is None or password is None:
        username, password = get_credentials(username)

    profiles = []
    for name, entry in targets:
        try:
            profiles.append((name, build_ad_hoc_profile(
                host        = entry["host"],
                device_type = entry.get("device_type", "cisco_ios"),
                username    = username,
                password    = password,
                port        = int(entry.get("port", 22)),
                secret      = entry.get("secret", ""),
            )))
        except ValueError as exc:
            profiles.append((name, None))
            print(f"{C_YELLOW}Skipping {name}: {exc}{C_RESET}")

    results: list[BackupResult] = []
    runnable = [(n, p) for n, p in profiles if p is not None]
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(runnable)))) as pool:
        futures = {
            pool.submit(backup_one, name, profile, root): name
            for name, profile in runnable
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.name)
    return results


# ---------------------------------------------------------------------------
# Optional git snapshotting
# ---------------------------------------------------------------------------

def git_commit_backups(root: Path | None = None) -> bool:
    """
    Commit the backup tree if it is inside a git repository.

    Best-effort by design: a missing git binary or an un-initialised directory
    is reported once and never fails the backup run, because the configs are
    already safely on disk by the time this is called.
    """
    backup_root = root or BACKUP_DIR
    if shutil.which("git") is None:
        print(f"{C_YELLOW}git not found on PATH — backups left uncommitted.{C_RESET}")
        return False
    if not backup_root.is_dir():
        return False

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        subprocess.run(["git", "add", "--", str(backup_root)],
                       cwd=backup_root.parent, check=True, capture_output=True)
        completed = subprocess.run(
            ["git", "commit", "-m", f"config backup {stamp}"],
            cwd=backup_root.parent, capture_output=True, text=True,
        )
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"{C_YELLOW}Could not commit backups: {exc}{C_RESET}")
        return False

    if completed.returncode != 0:
        if "nothing to commit" in (completed.stdout + completed.stderr).lower():
            print(f"{C_CYAN}No configuration changes to commit.{C_RESET}")
        else:
            print(f"{C_YELLOW}git commit failed: "
                  f"{completed.stderr.strip() or completed.stdout.strip()}{C_RESET}")
        return False

    print(f"{C_GREEN}Backups committed to git.{C_RESET}")
    return True


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_results(results: list[BackupResult]) -> None:
    """Render the backup run's outcome, changed devices first."""
    if not results:
        print(f"{C_YELLOW}No devices matched.{C_RESET}")
        return

    ok      = [r for r in results if r.ok]
    changed = [r for r in ok if r.changed]
    failed  = [r for r in results if not r.ok]

    print(f"\n{C_BOLD}{pad('Device', 24)}{pad('Host', 18)}"
          f"{pad('Result', 12)}Detail{C_RESET}")
    print("─" * 78)
    for result in results:
        if not result.ok:
            state, detail = f"{C_RED}failed{C_RESET}", result.error
        elif result.changed:
            state, detail = f"{C_YELLOW}changed{C_RESET}", str(result.path)
        else:
            state, detail = f"{C_GREEN}unchanged{C_RESET}", str(result.path)
        print(f"{pad(result.name, 24)}{pad(result.host, 18)}"
              f"{pad(state, 12)}{detail}")
        for warning in (result.warnings or []):
            print(f"{' ' * 54}{C_YELLOW}! {warning}{C_RESET}")

    print(f"\n{C_BOLD}{len(ok)} backed up "
          f"({len(changed)} changed), {len(failed)} failed.{C_RESET}")


def print_schedule_hint(selector: str = "all") -> None:
    """Print a ready-to-paste cron line for unattended nightly backups."""
    project = Path(__file__).resolve().parent.parent
    print(f"\n{C_BOLD}Run this backup unattended{C_RESET}")
    print(f"{C_CYAN}Add to crontab (crontab -e) for a nightly 02:00 run:{C_RESET}\n")
    print(f"  0 2 * * *  cd {project} && "
          f"SYSNET_USER=$USER SYSNET_PASS=... "
          f"python3 cli.py backup --targets {selector} --git >> "
          f"{project}/logs/backup.cron.log 2>&1\n")
    print(f"{C_YELLOW}Put the credentials in a root-only environment file "
          f"rather than inline in the crontab.{C_RESET}")


# ---------------------------------------------------------------------------
# Interactive CLI entry point
# ---------------------------------------------------------------------------

def run_interactive() -> None:
    """Interactive configuration backup used by main_menu.py."""
    if not check_dependency("netmiko"):
        return

    print(f"{C_BOLD}--- Configuration Backup ---{C_RESET}")
    print(f"{C_YELLOW}Pulls the running config from inventory devices into "
          f"{BACKUP_DIR} and reports which ones changed.{C_RESET}")

    selector = input("\nTargets (name / IP / tag:<tag> / all) [all]: ").strip() or "all"
    targets  = resolve_targets(selector)
    if not targets:
        print(f"{C_RED}No matching inventory device.{C_RESET}")
        return

    print(f"{C_CYAN}Backing up {len(targets)} device(s): "
          f"{', '.join(name for name, _ in targets)}{C_RESET}")
    results = backup_targets(selector)
    print_results(results)

    if input(f"\n{C_YELLOW}Commit backups to git? (y/N): "
             f"{C_RESET}").strip().lower() == "y":
        git_commit_backups()

    offer_export([r.as_row() for r in results], "config_backup")
    print_schedule_hint(selector)
