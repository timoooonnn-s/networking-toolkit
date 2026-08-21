"""
core/audit_logger.py
--------------------
Feature C — SSH Session Output Logger (Audit Trail)
====================================================
Every SSH command executed through the SysNet Toolkit is recorded to a
structured log file.  One log file is created *per session* (i.e. per
ConnectHandler lifetime), stored under the /logs/ directory.

Log entry format
----------------
Each line follows the pattern:

    [2024-11-15 14:32:01] [192.168.1.1] [show version] -> <output line 1>
    [2024-11-15 14:32:01] [192.168.1.1] [show version] -> <output line 2>

If the command produced multi-line output every line is written as its own
log record so that grep/awk can filter by device or command trivially.

Usage
-----
    from core.audit_logger import AuditLogger

    # One logger per device session
    logger = AuditLogger(device_ip="192.168.1.1")
    logger.log(command="show version", output="Cisco IOS XE ...")
    logger.close()

    # Or use as a context manager
    with AuditLogger("192.168.1.1") as log:
        log.log("show ip int brief", output)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Directory setup — /logs/ relative to the project root
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = _PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


class AuditLogger:
    """
    Writes a structured audit trail for a single SSH device session.

    Parameters
    ----------
    device_ip : str
        The IP or hostname of the target device (used in log entries and
        as part of the filename).
    log_dir : Path | None
        Override the default /logs/ directory (useful for testing).
    """

    def __init__(self, device_ip: str, log_dir: Optional[Path] = None) -> None:
        self.device_ip = device_ip
        self._log_dir  = Path(log_dir) if log_dir else LOG_DIR

        # Build a unique filename:  <ip>_<YYYYMMDD_HHMMSS>.log
        timestamp_str  = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ip        = device_ip.replace(".", "_").replace(":", "_")
        self._filename = self._log_dir / f"{safe_ip}_{timestamp_str}.log"

        # Use Python's logging module for thread-safe file writes
        self._logger = logging.getLogger(f"audit.{device_ip}.{timestamp_str}")
        self._logger.setLevel(logging.DEBUG)

        # File handler — each AuditLogger instance writes to its own file
        handler = logging.FileHandler(self._filename, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))   # raw format
        self._logger.addHandler(handler)
        self._handler = handler

        # Write a session-open marker
        self._write_marker(f"SESSION OPENED  device={device_ip}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(self, command: str, output: str) -> None:
        """
        Record a single command and its full output.

        Each line of *output* becomes a separate log record so the file
        remains grep-friendly.

        Parameters
        ----------
        command : str
            The CLI command that was sent to the device.
        output : str
            The raw text response received from the device.
        """
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"[{ts}] [{self.device_ip}] [{command}]"

        if not output or not output.strip():
            self._logger.info(f"{prefix} -> <empty response>")
            return

        for line in output.splitlines():
            self._logger.info(f"{prefix} -> {line}")

    def log_error(self, command: str, error: str) -> None:
        """Record a command that failed with an exception message."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._logger.error(
            f"[{ts}] [{self.device_ip}] [{command}] -> ERROR: {error}"
        )

    def close(self) -> None:
        """Flush and close the underlying file handler."""
        self._write_marker("SESSION CLOSED")
        self._handler.flush()
        self._handler.close()
        self._logger.removeHandler(self._handler)

    @property
    def log_path(self) -> Path:
        """Return the absolute path to this session's log file."""
        return self._filename

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_marker(self, label: str) -> None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        separator = "=" * 70
        self._logger.info(separator)
        self._logger.info(f"[{ts}] {label}")
        self._logger.info(separator)
