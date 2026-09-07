"""
features/multiping.py
---------------------
Multi-Host Reachability Check
=============================
"Are these clients still there?" — answered for a comma-separated list, a
CIDR subnet, or a three-octet prefix, in one pass.

Two engines, same output
------------------------
``fping`` is used when it is on PATH: it sends to every target in parallel
from a single process, so a /24 finishes in a couple of seconds instead of
one subprocess per host.  When it is missing the tool falls back to the
system ``ping`` driven by a thread pool — slower and RTT-less on some
platforms, but it needs nothing installed.

Both engines produce the same PingResult rows, so the summary table, the
exit status and the CSV/JSON export do not care which one ran.

Usage (programmatic)
--------------------
    from features.multiping import ping_hosts, expand_targets

    results = ping_hosts(expand_targets("192.168.1.0/24"))
    alive   = [r.host for r in results if r.alive]
"""

from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from core.colors import C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW, pad
from core.export import offer_export

# Per-probe timeout.  The old sweep passed no timeout at all, so an
# unreachable host blocked for the OS default (5–10 s) and a /24 took minutes.
DEFAULT_TIMEOUT_MS = 800
DEFAULT_RETRIES    = 1
DEFAULT_WORKERS    = 32

# fping's per-host summary line:
#   10.0.0.1 : xmt/rcv/%loss = 1/1/0%, min/avg/max = 0.42/0.42/0.42
_FPING_LINE = re.compile(
    r"^(?P<host>\S+)\s*:\s*xmt/rcv/%loss\s*=\s*(?P<xmt>\d+)/(?P<rcv>\d+)/"
    r"(?P<loss>\d+)%(?:,\s*min/avg/max\s*=\s*[\d.]+/(?P<avg>[\d.]+)/[\d.]+)?"
)

# 'time=0.42 ms' / 'time<1ms' from the system ping
_PING_RTT = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


@dataclass
class PingResult:
    """One host's reachability, from whichever engine ran."""
    host:    str
    alive:   bool
    rtt_ms:  float | None = None
    engine:  str = "ping"

    def as_row(self) -> dict[str, object]:
        return {
            "host":   self.host,
            "status": "up" if self.alive else "down",
            "rtt_ms": f"{self.rtt_ms:.2f}" if self.rtt_ms is not None else "",
            "engine": self.engine,
        }


def have_fping() -> bool:
    """True when fping is on PATH."""
    return shutil.which("fping") is not None


# ---------------------------------------------------------------------------
# Target expansion
# ---------------------------------------------------------------------------

def expand_targets(raw: str) -> list[str]:
    """
    Turn one operator string into a list of hosts.

    Accepted forms, comma-separated and mixable:
        10.0.0.1, server-a.example.com     literal hosts and names
        192.168.1.0/24                     every usable host in the subnet
        192.168.1.                         a three-octet prefix -> .1–.254
        10.0.0.5-10.0.0.9                  an inclusive IPv4 range

    Order is preserved and duplicates are dropped, so a list pasted from a
    ticket comes back in the order it was written.
    """
    hosts: list[str] = []
    seen: set[str] = set()

    def add(host: str) -> None:
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)

    for token in (t.strip() for t in raw.split(",")):
        if not token:
            continue

        if "/" in token:
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                add(token)
                continue
            # /31 and /32 have no 'hosts()' worth iterating — probe the
            # addresses themselves rather than returning nothing.
            addresses = list(network.hosts()) or [network.network_address]
            for address in addresses:
                add(str(address))
            continue

        if "-" in token and token.count(".") >= 3:
            start, _, end = token.partition("-")
            try:
                first = ipaddress.IPv4Address(start.strip())
                last  = ipaddress.IPv4Address(end.strip())
            except ValueError:
                add(token)
                continue
            if int(last) < int(first):
                first, last = last, first
            for value in range(int(first), int(last) + 1):
                add(str(ipaddress.IPv4Address(value)))
            continue

        # '192.168.1' or '192.168.1.' — a three-octet prefix
        stripped = token.rstrip(".")
        if stripped.count(".") == 2 and all(
            part.isdigit() for part in stripped.split(".")
        ):
            for last_octet in range(1, 255):
                add(f"{stripped}.{last_octet}")
            continue

        add(token)

    return hosts


# ---------------------------------------------------------------------------
# fping engine
# ---------------------------------------------------------------------------

def _ping_with_fping(
    hosts: list[str],
    timeout_ms: int,
    retries: int,
) -> list[PingResult]:
    """
    Probe every host in one fping process.

    ``-c 1 -q`` makes fping print one summary line per host on *stderr*
    carrying both the loss count and the average RTT, which is why stderr is
    what gets parsed here.  Hosts fping never mentions are reported down
    rather than dropped, so the result list always matches the input list.
    """
    command = [
        "fping",
        "-c", "1",                 # one probe per host
        "-q",                      # per-host summary only
        "-t", str(timeout_ms),     # per-probe timeout
        "-r", str(retries),
        *hosts,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            # A generous ceiling: fping's own -t/-r bound the real runtime.
            timeout=max(60, len(hosts) * timeout_ms / 1000),
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    results: dict[str, PingResult] = {}
    for line in completed.stderr.splitlines():
        match = _FPING_LINE.match(line.strip())
        if not match:
            continue
        received = int(match.group("rcv"))
        avg      = match.group("avg")
        results[match.group("host")] = PingResult(
            host   = match.group("host"),
            alive  = received > 0,
            rtt_ms = float(avg) if (avg and received > 0) else None,
            engine = "fping",
        )

    return [
        results.get(host, PingResult(host=host, alive=False, engine="fping"))
        for host in hosts
    ]


# ---------------------------------------------------------------------------
# system ping fallback
# ---------------------------------------------------------------------------

def _ping_once(host: str, timeout_ms: int) -> PingResult:
    """Probe one host with the system ping, bounded by an explicit timeout."""
    is_windows = platform.system().lower() == "windows"
    if is_windows:
        command = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        # -W is seconds on Linux/macOS ping and must be at least 1.
        seconds = max(1, round(timeout_ms / 1000))
        command = ["ping", "-c", "1", "-W", str(seconds), host]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(2, timeout_ms / 1000 + 2),
        )
    except subprocess.TimeoutExpired:
        return PingResult(host=host, alive=False)
    except FileNotFoundError:
        return PingResult(host=host, alive=False)

    alive = completed.returncode == 0
    match = _PING_RTT.search(completed.stdout)
    return PingResult(
        host   = host,
        alive  = alive,
        rtt_ms = float(match.group(1)) if (match and alive) else None,
    )


def _ping_host(host: str, timeout_ms: int, retries: int) -> PingResult:
    """
    Probe one host, re-probing up to *retries* times while it looks down.

    Same semantics as fping's -r: a host that answers on any attempt is up, so
    the retry budget only costs time for hosts that are genuinely unreachable.
    Without this the fallback engine ignored --retries entirely and reported a
    single dropped packet as a down host.
    """
    result = _ping_once(host, timeout_ms)
    for _ in range(max(0, retries)):
        if result.alive:
            break
        result = _ping_once(host, timeout_ms)
    return result


def _ping_with_system(
    hosts: list[str],
    timeout_ms: int,
    workers: int,
    retries: int = DEFAULT_RETRIES,
) -> list[PingResult]:
    """Fallback engine: one ping subprocess per host, across a thread pool."""
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(hosts)))) as pool:
        return list(pool.map(
            lambda h: _ping_host(h, timeout_ms, retries), hosts))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ping_hosts(
    hosts: list[str],
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    retries: int = DEFAULT_RETRIES,
    workers: int = DEFAULT_WORKERS,
    prefer_fping: bool = True,
) -> list[PingResult]:
    """
    Probe every host in *hosts* and return one PingResult each, in order.

    Uses fping when available (one process for the whole list), otherwise the
    system ping across a thread pool.  If fping is present but produces
    nothing usable — an unexpected build, a permissions problem — the system
    ping runs instead rather than reporting a whole subnet as down.

    *retries* applies to both engines: a host is only reported down after it
    has failed every attempt.
    """
    if not hosts:
        return []

    if prefer_fping and have_fping():
        results = _ping_with_fping(hosts, timeout_ms, retries)
        if results:
            return results
        print(f"{C_YELLOW}fping produced no usable output — "
              f"falling back to the system ping.{C_RESET}")

    return _ping_with_system(hosts, timeout_ms, workers, retries)


def print_results(results: list[PingResult]) -> None:
    """Render a reachability table and a one-line summary."""
    if not results:
        print(f"{C_YELLOW}No targets probed.{C_RESET}")
        return

    alive = [r for r in results if r.alive]
    dead  = [r for r in results if not r.alive]

    print(f"\n{C_BOLD}{pad('Host', 40)}{pad('Status', 10)}RTT{C_RESET}")
    print("─" * 62)
    for result in results:
        state = f"{C_GREEN}up{C_RESET}" if result.alive else f"{C_RED}down{C_RESET}"
        rtt   = f"{result.rtt_ms:.2f} ms" if result.rtt_ms is not None else "—"
        print(f"{pad(result.host, 40)}{pad(state, 10)}{rtt}")

    engine = results[0].engine
    print(f"\n{C_BOLD}{len(alive)} up, {len(dead)} down "
          f"({len(results)} probed via {engine}).{C_RESET}")
    if dead and len(dead) <= 20:
        print(f"{C_YELLOW}Down: {', '.join(r.host for r in dead)}{C_RESET}")


# ---------------------------------------------------------------------------
# Interactive CLI entry point
# ---------------------------------------------------------------------------

def run_interactive() -> None:
    """Interactive multi-host reachability check used by main_menu.py."""
    print(f"{C_BOLD}--- Multi-Host Reachability Check ---{C_RESET}")
    engine = "fping" if have_fping() else "system ping (fping not installed)"
    print(f"{C_CYAN}Engine: {engine}{C_RESET}")
    print("Targets: comma-separated hosts, a CIDR (192.168.1.0/24), "
          "a prefix (192.168.1.), or a range (10.0.0.5-10.0.0.9)")

    raw = input("Targets: ").strip()
    if not raw:
        print(f"{C_RED}No targets given.{C_RESET}")
        return

    hosts = expand_targets(raw)
    if not hosts:
        print(f"{C_RED}Nothing to probe.{C_RESET}")
        return

    timeout_raw = input(f"Per-probe timeout in ms [{DEFAULT_TIMEOUT_MS}]: ").strip()
    timeout_ms  = int(timeout_raw) if timeout_raw.isdigit() else DEFAULT_TIMEOUT_MS

    print(f"\n{C_CYAN}Probing {len(hosts)} host(s) ...{C_RESET}")
    results = ping_hosts(hosts, timeout_ms=timeout_ms)
    print_results(results)
    offer_export([r.as_row() for r in results], "reachability")
