"""
core/paths.py
-------------
Single source of truth for every on-disk location the toolkit writes to.

Why this module exists
----------------------
The JSON stores used to be plain relative filenames ("sysnet_vlans.json"),
which resolve against the *current working directory*.  Launching the toolkit
from anywhere other than the project root silently produced a second, empty
database instead of an error.  Every path below is anchored to the project
root (the parent of this package) so the data follows the code, not the shell.

Override the root with the SYSNET_DATA_DIR environment variable when the
project directory is read-only (e.g. a system-wide install).
"""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Everything the toolkit writes lives under one directory so it can be
# backed up, git-ignored or pointed elsewhere in a single move.
DATA_DIR = Path(os.environ.get("SYSNET_DATA_DIR", PROJECT_ROOT)).resolve()

LOG_DIR      = DATA_DIR / "logs"
BACKUP_DIR   = DATA_DIR / "backups"
EXPORT_DIR   = DATA_DIR / "exports"
SNAPSHOT_DIR = DATA_DIR / "snapshots"

SNIPPET_FILE      = DATA_DIR / "sysnet_snippets.json"
VLAN_DB_FILE      = DATA_DIR / "sysnet_vlans.json"
SNMP_PRESETS_FILE = DATA_DIR / "snmp_presets.json"
INVENTORY_FILE = Path(
    os.environ.get("SYSNET_INVENTORY", DATA_DIR / "inventory.json")
).expanduser()


def ensure_dir(path: Path) -> Path:
    """Create *path* (and parents) if missing and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path
