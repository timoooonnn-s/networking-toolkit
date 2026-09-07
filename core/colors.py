"""
core/colors.py
--------------
Centralised ANSI colour constants and terminal UI helpers shared across
every module in the SysNet Toolkit.  Import with:

    from core.colors import C_GREEN, C_RESET, print_header, wait_for_user

Colour is switched off automatically when stdout is not a TTY (piping the
non-interactive CLI into a file or a CI log) or when NO_COLOR is set, so the
same code path produces clean text output without a second "plain" branch.

Column alignment
----------------
ANSI escape sequences count toward f-string padding widths, so
``f"{C_GREEN}up{C_RESET}:>8"`` pads to 8 *characters including the escapes*
and the column collapses.  Use pad()/visible_len() for any coloured cell in
a table.
"""

from __future__ import annotations

import os
import re
import sys

VERSION = "2.4.0"

# ---------------------------------------------------------------------------
# ANSI escape codes — emptied when the terminal cannot render them
# ---------------------------------------------------------------------------

def _colour_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("SYSNET_FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


_ON = _colour_enabled()

C_RESET   = "\033[0m"  if _ON else ""
C_RED     = "\033[91m" if _ON else ""
C_GREEN   = "\033[92m" if _ON else ""
C_YELLOW  = "\033[93m" if _ON else ""
C_BLUE    = "\033[94m" if _ON else ""
C_MAGENTA = "\033[95m" if _ON else ""
C_CYAN    = "\033[96m" if _ON else ""
C_BOLD    = "\033[1m"  if _ON else ""

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Return *text* with every ANSI SGR sequence removed."""
    return _ANSI_RE.sub("", text)


def visible_len(text: str) -> int:
    """Length of *text* as the terminal renders it (escapes excluded)."""
    return len(strip_ansi(text))


def pad(text: str, width: int, align: str = "<") -> str:
    """
    Pad *text* to *width* visible characters, ignoring ANSI escapes.

    Use instead of f-string padding for any coloured table cell:

        print(f"{pad(state, 8)} {pad(name, 20)}")

    align: '<' left, '>' right, '^' centre.
    """
    fill = max(0, width - visible_len(text))
    if align == ">":
        return " " * fill + text
    if align == "^":
        left = fill // 2
        return " " * left + text + " " * (fill - left)
    return text + " " * fill


# ---------------------------------------------------------------------------
# Terminal UI helpers
# ---------------------------------------------------------------------------

_BANNER = r"""
 _______             __                             __    .__                   ___________                .__    __    .__   __
 ╲      ╲    ____  _╱  │_ __  _  __  ____  _______ │  │ __│__│  ____     ____   ╲__    ___╱  ____    ____  │  │  │  │ __│__│_╱  │_
 ╱   │   ╲ _╱ __ ╲ ╲   __╲╲ ╲╱ ╲╱ ╱ ╱  _ ╲ ╲_  __ ╲│  │╱ ╱│  │ ╱    ╲   ╱ ___╲    │    │    ╱  _ ╲  ╱  _ ╲ │  │  │  │╱ ╱│  │╲   __╲
╱    │    ╲╲  ___╱  │  │   ╲     ╱ (  <_> ) │  │ ╲╱│    < │  ││   │  ╲ ╱ ╱_╱  >   │    │   (  <_> )(  <_> )│  │__│    < │  │ │  │
╲____│__  ╱ ╲___  > │__│    ╲╱╲_╱   ╲____╱  │__│   │__│_ ╲│__││___│  ╱ ╲___  ╱    │____│    ╲____╱  ╲____╱ │____╱│__│_ ╲│__│ │__│
        ╲╱      ╲╱                                      ╲╱         ╲╱ ╱_____╱                                         ╲╱
"""


def print_header() -> None:
    """Clear the terminal and render the SysNet ASCII banner + version line."""
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")

    print(_BANNER)
    # Version is rendered from VERSION so the banner can never drift from it.
    print(f"{' ' * 88}by timmy        |       v{VERSION}\n")


def wait_for_user() -> None:
    """
    Pause execution until the operator presses Enter.

    EOF is swallowed deliberately.  This is a UI pause, and an exhausted
    stdin (piped input, a here-doc, a closed terminal) means "there is nobody
    to wait for" — never an error worth a traceback.  Both menu call sites sit
    outside their try blocks, so without this the menu ends on a stack trace
    instead of exiting cleanly.
    """
    try:
        input(f"\n{C_YELLOW}Press Enter to return to main menu...{C_RESET}")
    except EOFError:
        print()
