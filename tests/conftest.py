"""Shared pytest fixtures.

Every test in this suite runs offline: no device, no network, no fping.  The
VOSS captures under ``fixtures/voss/`` are real command output, so a parser
change that would break against a live switch breaks here first.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Tests import the toolkit as ``core.x`` / ``features.x``, the same way the
# menu and the CLI do.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def voss():
    """Return a reader for a VOSS fixture: ``voss("show_mlt")``."""
    def read(name: str) -> str:
        path = FIXTURE_DIR / "voss" / f"{name}.txt"
        if not path.exists():
            pytest.fail(f"missing fixture {path}")
        return path.read_text(encoding="utf-8")
    return read
