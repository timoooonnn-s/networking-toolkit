"""
core/dependency_check.py
------------------------
Centralised optional-dependency detection.  Replaces the scattered
try/except ImportError blocks in the original monolith.

Every feature module calls check_dependency() at the top of its public
function, so the user sees a clear, actionable error message instead of a
confusing AttributeError or NameError buried in a stack trace.

Usage
-----
    from core.dependency_check import check_dependency, HAS_NETMIKO, HAS_NAPALM

    def my_feature():
        if not check_dependency("netmiko"):
            return          # function exits gracefully with a printed hint
        ...

Why the libraries are never imported here
----------------------------------------
This module only answers "is it installed".  It deliberately does not import
and re-export Netmiko, NAPALM or Jinja2, because a symbol bound at module
level inside a try block is not reliably visible from a worker closure in
another module — which is how the original monolith managed to raise
NameError for ConnectHandler even when Netmiko *was* installed.  Every
feature module imports what it needs lazily, inside the function that uses
it, after calling check_dependency().
"""

from __future__ import annotations

from core.colors import C_RED, C_RESET, C_YELLOW

# ---------------------------------------------------------------------------
# Availability flags  (set once at import time)
# ---------------------------------------------------------------------------

def _try_import(module_name: str) -> bool:
    """Return True if *module_name* can be imported, False otherwise."""
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False


HAS_NETMIKO = _try_import("netmiko")
HAS_NAPALM  = _try_import("napalm")
HAS_JINJA   = _try_import("jinja2")

# ---------------------------------------------------------------------------
# Human-readable install hints
# ---------------------------------------------------------------------------
_INSTALL_HINTS: dict[str, str] = {
    "netmiko": "pip install netmiko",
    "napalm":  "pip install napalm",
    "jinja2":  "pip install jinja2",
}

_FLAG_MAP: dict[str, bool] = {
    "netmiko": HAS_NETMIKO,
    "napalm":  HAS_NAPALM,
    "jinja2":  HAS_JINJA,
}


def check_dependency(name: str) -> bool:
    """
    Verify that *name* is installed and importable.

    Prints a coloured error with the pip install command if missing.
    Returns True when available, False otherwise.

    Parameters
    ----------
    name : str
        Package name key — one of 'netmiko', 'napalm', 'jinja2'.
    """
    available = _FLAG_MAP.get(name, _try_import(name))
    if not available:
        hint = _INSTALL_HINTS.get(name, f"pip install {name}")
        print(
            f"{C_RED}[ERROR] Required library '{name}' is not installed.{C_RESET}\n"
            f"{C_YELLOW}  Fix:  {hint}{C_RESET}"
        )
    return available


def print_dependency_status() -> None:
    """Print a status table of all optional dependencies (useful at startup)."""
    from core.colors import C_BOLD, C_GREEN
    print(f"\n{C_BOLD}Dependency Status:{C_RESET}")
    for name, available in _FLAG_MAP.items():
        status = f"{C_GREEN}OK{C_RESET}" if available else f"{C_RED}MISSING{C_RESET}"
        hint   = "" if available else f"  →  pip install {name}"
        print(f"  {'✔' if available else '✘'} {name:<12} {status}{C_YELLOW}{hint}{C_RESET}")
    print()
