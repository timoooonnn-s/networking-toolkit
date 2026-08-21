"""
core/export.py
--------------
CSV / JSON export shared by every tool that produces a table.

Any tool can hand off a list of dicts and get a timestamped file under
``exports/`` without re-implementing writer boilerplate or worrying about
column order:

    from core.export import export_rows, offer_export

    rows = [{"host": "10.0.0.1", "state": "up"}, ...]
    export_rows(rows, "reachability", fmt="csv")      # programmatic
    offer_export(rows, "reachability")                # interactive prompt

Column order is taken from the first row, then extended with any key a later
row introduces, so a ragged result set still exports every field instead of
raising or silently dropping columns.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from core.colors import C_GREEN, C_RED, C_RESET, C_YELLOW
from core.paths import EXPORT_DIR, ensure_dir

VALID_FORMATS = ("csv", "json")


def _columns(rows: Sequence[dict[str, Any]]) -> list[str]:
    """Union of every row's keys, in first-seen order."""
    columns: list[str] = []
    for row in rows:
        for key in row:
            if key not in columns:
                columns.append(key)
    return columns


def export_rows(
    rows: Iterable[dict[str, Any]],
    basename: str,
    fmt: str = "csv",
    path: Path | str | None = None,
) -> Path | None:
    """
    Write *rows* to ``exports/<basename>_<timestamp>.<fmt>`` (or to *path*).

    Returns the path written, or None when there was nothing to write or the
    write failed — callers print, they do not have to handle exceptions.
    """
    rows = list(rows)
    if not rows:
        print(f"{C_YELLOW}Nothing to export.{C_RESET}")
        return None

    fmt = fmt.lower().strip()
    if fmt not in VALID_FORMATS:
        print(f"{C_RED}Unknown export format '{fmt}' "
              f"(choose from: {', '.join(VALID_FORMATS)}).{C_RESET}")
        return None

    if path is not None:
        out_path = Path(path)
        ensure_dir(out_path.parent)
    else:
        stamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = ensure_dir(EXPORT_DIR) / f"{basename}_{stamp}.{fmt}"

    try:
        if fmt == "json":
            out_path.write_text(json.dumps(rows, indent=2, default=str),
                                encoding="utf-8")
        else:
            with open(out_path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=_columns(rows))
                writer.writeheader()
                for row in rows:
                    writer.writerow(row)
    except OSError as exc:
        print(f"{C_RED}Could not write {out_path}: {exc}{C_RESET}")
        return None

    print(f"{C_GREEN}Exported {len(rows)} row(s) → {out_path}{C_RESET}")
    return out_path


def export_json(data: Any, basename: str, path: Path | str | None = None) -> Path | None:
    """Write an arbitrary JSON-serialisable *data* structure (not just rows)."""
    if path is not None:
        out_path = Path(path)
        ensure_dir(out_path.parent)
    else:
        stamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = ensure_dir(EXPORT_DIR) / f"{basename}_{stamp}.json"
    try:
        out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    except OSError as exc:
        print(f"{C_RED}Could not write {out_path}: {exc}{C_RESET}")
        return None
    print(f"{C_GREEN}Exported → {out_path}{C_RESET}")
    return out_path


def offer_export(rows: Iterable[dict[str, Any]], basename: str) -> Path | None:
    """
    Ask the operator whether to export *rows*, then do it.

    Used at the end of interactive tools.  Declining, or a non-interactive
    stdin (piped input, cron), returns None without writing anything.
    """
    rows = list(rows)
    if not rows:
        return None
    try:
        answer = input(f"\n{C_YELLOW}Export {len(rows)} row(s)? "
                       f"(c=CSV, j=JSON, Enter=skip): {C_RESET}").strip().lower()
    except EOFError:
        return None
    if answer.startswith("c"):
        return export_rows(rows, basename, fmt="csv")
    if answer.startswith("j"):
        return export_rows(rows, basename, fmt="json")
    return None
