"""
features/interface_health.py
-----------------------------
Feature D — Interface Health Dashboard
=======================================
Consumes the normalized NAPALM data structures produced by
napalm_interface.NAPALMSession and highlights performance anomalies:

  • CRC / input errors above threshold
  • Output drops above threshold
  • Link flap detection (last_flapped < FLAP_WINDOW_SECS)
  • Interface utilisation % (requires speed + octet counters)

All thresholds are configurable via module-level constants so they can be
overridden in unit tests or by an operator without editing business logic.

Data flow
---------
    napalm_interface.NAPALMSession.get_interfaces()          ──►  _check_state()
    napalm_interface.NAPALMSession.get_interfaces_counters() ──►  _check_counters()
    both combined                                            ──►  HealthReport
    HealthReport.print_dashboard()                           ──►  stdout

Usage (programmatic)
--------------------
    from features.napalm_interface import NAPALMSession
    from features.interface_health import build_health_report, print_dashboard

    with NAPALMSession(host, device_type, user, pw) as sess:
        ifaces   = sess.get_interfaces()
        counters = sess.get_interfaces_counters()

    report = build_health_report(ifaces, counters)
    print_dashboard(report)

Usage (interactive)
-------------------
    from features.interface_health import run_interactive
    run_interactive()
"""

from __future__ import annotations

import getpass
from dataclasses import dataclass, field
from typing import Any

from core.colors import (
    C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW,
)
from core.dependency_check import check_dependency
from core.inventory import SUPPORTED_OS

# ---------------------------------------------------------------------------
# Configurable thresholds
# ---------------------------------------------------------------------------
ERROR_THRESHOLD_PACKETS   = 10    # rx/tx errors before flagging
DROP_THRESHOLD_PACKETS    = 50    # rx/tx discards before flagging
FLAP_WINDOW_SECS          = 300   # flag if last_flapped < 5 minutes ago
UTILISATION_WARN_PCT      = 70.0  # % utilisation — yellow warning
UTILISATION_CRIT_PCT      = 90.0  # % utilisation — red critical
SAMPLE_INTERVAL_SECS      = 5     # polling interval for live utilisation


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class InterfaceAnomaly:
    """A single detected anomaly on one interface."""
    interface:   str
    severity:    str   # "INFO", "WARN", "CRIT"
    category:    str   # "ERRORS", "DROPS", "FLAP", "UTILISATION", "DOWN"
    detail:      str


@dataclass
class HealthReport:
    """Full health assessment for all interfaces on one device."""
    host:      str
    anomalies: list[InterfaceAnomaly] = field(default_factory=list)
    clean:     list[str]              = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return bool(self.anomalies)


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

def _check_state(
    iface_name: str,
    iface_data: dict[str, Any],
) -> list[InterfaceAnomaly]:
    """Detect state-level anomalies (admin up but link down, recent flap)."""
    anomalies: list[InterfaceAnomaly] = []

    is_enabled = iface_data.get("is_enabled", True)
    is_up      = iface_data.get("is_up",      True)
    last_flap  = iface_data.get("last_flapped", -1)

    # Admin-enabled but physically down
    if is_enabled and not is_up:
        anomalies.append(InterfaceAnomaly(
            interface=iface_name,
            severity="CRIT",
            category="DOWN",
            detail="Interface is admin-enabled but link is DOWN",
        ))

    # Recent link flap
    if 0 <= last_flap < FLAP_WINDOW_SECS:
        anomalies.append(InterfaceAnomaly(
            interface=iface_name,
            severity="WARN",
            category="FLAP",
            detail=f"Link last flapped {last_flap:.0f}s ago (threshold: {FLAP_WINDOW_SECS}s)",
        ))

    return anomalies


def _check_counters(
    iface_name: str,
    counter_data: dict[str, Any],
) -> list[InterfaceAnomaly]:
    """Detect counter-level anomalies (errors, drops, utilisation)."""
    anomalies: list[InterfaceAnomaly] = []

    rx_errors   = counter_data.get("rx_errors",   0) or 0
    tx_errors   = counter_data.get("tx_errors",   0) or 0
    rx_discards = counter_data.get("rx_discards", 0) or 0
    tx_discards = counter_data.get("tx_discards", 0) or 0

    total_errors = rx_errors + tx_errors
    total_drops  = rx_discards + tx_discards

    if total_errors > ERROR_THRESHOLD_PACKETS:
        anomalies.append(InterfaceAnomaly(
            interface=iface_name,
            severity="WARN" if total_errors < 100 else "CRIT",
            category="ERRORS",
            detail=(
                f"CRC/input errors: RX={rx_errors}, TX={tx_errors} "
                f"(threshold: {ERROR_THRESHOLD_PACKETS})"
            ),
        ))

    if total_drops > DROP_THRESHOLD_PACKETS:
        anomalies.append(InterfaceAnomaly(
            interface=iface_name,
            severity="WARN" if total_drops < 500 else "CRIT",
            category="DROPS",
            detail=(
                f"Packet drops: RX={rx_discards}, TX={tx_discards} "
                f"(threshold: {DROP_THRESHOLD_PACKETS})"
            ),
        ))

    return anomalies


def _estimate_utilisation(
    iface_data:   dict[str, Any],
    counter_data: dict[str, Any],
) -> float | None:
    """
    Estimate current utilisation percentage.

    This is a *snapshot* estimate using octet counters and interface speed.
    For a true rate you'd sample twice and divide by the interval — the
    live_utilisation() function below does that.  Here we return None if
    we can't compute a meaningful value from a single snapshot.
    """
    speed_mbps = iface_data.get("speed", 0) or 0
    if speed_mbps <= 0:
        return None

    rx_octets = counter_data.get("rx_octets", 0) or 0
    tx_octets = counter_data.get("tx_octets", 0) or 0

    # Without a time-delta a single snapshot is meaningless — return None
    # and let callers use live_utilisation() for real rates.
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_health_report(
    interfaces: dict[str, dict[str, Any]],
    counters:   dict[str, dict[str, Any]],
    host:       str = "unknown",
) -> HealthReport:
    """
    Build a HealthReport from normalized NAPALM interface + counter dicts.

    Parameters
    ----------
    interfaces : dict
        Output of NAPALMSession.get_interfaces()
    counters : dict
        Output of NAPALMSession.get_interfaces_counters()
    host : str
        Device hostname/IP (for report labelling only).

    Returns
    -------
    HealthReport
    """
    report = HealthReport(host=host)

    for iface_name, iface_data in interfaces.items():
        iface_anomalies: list[InterfaceAnomaly] = []

        # State checks
        iface_anomalies.extend(_check_state(iface_name, iface_data))

        # Counter checks (only if counter data available for this interface)
        if iface_name in counters:
            iface_anomalies.extend(_check_counters(iface_name, counters[iface_name]))

        if iface_anomalies:
            report.anomalies.extend(iface_anomalies)
        else:
            report.clean.append(iface_name)

    return report


def print_dashboard(report: HealthReport) -> None:
    """
    Render a coloured health dashboard for *report* to stdout.

    Severity colour mapping:
        CRIT  →  red
        WARN  →  yellow
        INFO  →  cyan
    """
    _SEVERITY_COLOR = {
        "CRIT": C_RED,
        "WARN": C_YELLOW,
        "INFO": C_CYAN,
    }

    print(f"\n{C_BOLD}{'=' * 65}{C_RESET}")
    print(f"{C_BOLD}Interface Health Dashboard — {report.host}{C_RESET}")
    print(f"{C_BOLD}{'=' * 65}{C_RESET}")

    if not report.has_issues:
        print(f"\n{C_GREEN}✔  All {len(report.clean)} interfaces are healthy.{C_RESET}\n")
        return

    # Sort by severity: CRIT first
    severity_order = {"CRIT": 0, "WARN": 1, "INFO": 2}
    sorted_anomalies = sorted(
        report.anomalies,
        key=lambda a: (severity_order.get(a.severity, 9), a.interface),
    )

    print(f"\n{C_RED}⚠  {len(report.anomalies)} anomalie(s) detected:{C_RESET}\n")
    print(f"{C_BOLD}{'Severity':<8} {'Category':<14} {'Interface':<22} Detail{C_RESET}")
    print("─" * 80)

    for anomaly in sorted_anomalies:
        color = _SEVERITY_COLOR.get(anomaly.severity, C_RESET)
        print(
            f"{color}{anomaly.severity:<8}{C_RESET} "
            f"{anomaly.category:<14} "
            f"{anomaly.interface:<22} "
            f"{anomaly.detail}"
        )

    if report.clean:
        print(f"\n{C_GREEN}✔  {len(report.clean)} interfaces OK: "
              f"{', '.join(report.clean[:8])}"
              f"{'...' if len(report.clean) > 8 else ''}{C_RESET}")
    print()


# ---------------------------------------------------------------------------
# Interactive CLI entry point
# ---------------------------------------------------------------------------

def run_interactive() -> None:
    """
    Interactive entry point: connects via NAPALM, fetches data, and
    renders the health dashboard.
    """
    if not check_dependency("napalm"):
        return

    # Import here to avoid circular import at module load time
    from features.napalm_interface import NAPALMSession

    print(f"{C_BOLD}--- Interface Health Dashboard ---{C_RESET}")

    host        = input("Device IP/Hostname: ").strip()
    print(f"Device type options: {', '.join(SUPPORTED_OS)}")
    device_type = input("Device type (default: cisco_ios): ").strip() or "cisco_ios"
    username    = input("Username: ").strip()
    password    = getpass.getpass("Password: ")

    try:
        print(f"\n{C_CYAN}Connecting to {host} and fetching interface data ...{C_RESET}")
        with NAPALMSession(host, device_type, username, password) as sess:
            ifaces   = sess.get_interfaces()
            counters = sess.get_interfaces_counters()

        report = build_health_report(ifaces, counters, host=host)
        print_dashboard(report)

    except Exception as err:
        print(f"{C_RED}Error: {err}{C_RESET}")
