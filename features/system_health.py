"""
features/system_health.py
--------------------------
System Health & Monitoring Tools
==================================
Refactored from the original monolith's Category B (System Health) and
parts of Category C (Log Analysis).

Tools
-----
    tool_sys_resource()  — CPU load, disk usage, memory
    tool_top_process()   — Top memory/CPU consumers via ps
    tool_port_listener() — Local listening ports via lsof/netstat
    tool_log_scanner()   — Log file keyword scanner
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess

from core.colors import C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW


# ---------------------------------------------------------------------------
# System Resource Snapshot
# ---------------------------------------------------------------------------

def tool_sys_resource() -> None:
    """Display CPU load average, disk usage, and memory stats."""
    print(f"{C_BOLD}--- System Resource Snapshot ---{C_RESET}")

    # Load average (Unix only)
    if hasattr(os, "getloadavg"):
        load = os.getloadavg()
        print(f"Load Avg (1/5/15m): {C_CYAN}{load[0]:.2f}  {load[1]:.2f}  {load[2]:.2f}{C_RESET}")
    else:
        print(f"Load Avg:           {C_YELLOW}Not available on this OS{C_RESET}")

    # Disk usage
    total, used, free = shutil.disk_usage("/")
    pct = (used / total) * 100
    color = C_RED if pct > 90 else C_YELLOW if pct > 75 else C_GREEN
    print(
        f"Disk Usage (/):     {color}{used // (2**30)} GB used "
        f"/ {total // (2**30)} GB total  ({pct:.1f}%){C_RESET}"
    )

    # Memory (Linux /proc/meminfo)
    if platform.system() == "Linux" and os.path.exists("/proc/meminfo"):
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        mem_total = int(lines[0].split()[1]) // 1024   # kB → MB
        mem_avail = int(lines[2].split()[1]) // 1024
        mem_used  = mem_total - mem_avail
        pct_mem   = (mem_used / mem_total) * 100
        color     = C_RED if pct_mem > 90 else C_YELLOW if pct_mem > 75 else C_GREEN
        print(
            f"Memory:             {color}{mem_used} MB used "
            f"/ {mem_total} MB total  ({pct_mem:.1f}%){C_RESET}"
        )
    else:
        print(f"Memory:             {C_YELLOW}Full details require psutil on non-Linux OS{C_RESET}")


# ---------------------------------------------------------------------------
# Top Process Hoggers
# ---------------------------------------------------------------------------

def tool_top_process() -> None:
    """Show the top processes by memory consumption (Linux/macOS)."""
    print(f"{C_BOLD}--- Top Process Hoggers ---{C_RESET}")

    if platform.system() not in ("Linux", "Darwin"):
        print(f"{C_RED}This tool supports Linux/macOS only.{C_RESET}")
        return

    try:
        cmd    = "ps -eo pid,ppid,%mem,%cpu,comm --sort=-%mem | head -n 11"
        output = subprocess.check_output(cmd, shell=True).decode()
        print(f"\n{C_CYAN}{output}{C_RESET}")
    except Exception as exc:
        print(f"{C_RED}Error running ps: {exc}{C_RESET}")


# ---------------------------------------------------------------------------
# Local Listening Port Scanner
# ---------------------------------------------------------------------------

def tool_port_listener() -> None:
    """List services listening on local ports using lsof or netstat."""
    print(f"{C_BOLD}--- Local Listening Ports ---{C_RESET}")

    if platform.system() not in ("Linux", "Darwin"):
        print(f"{C_RED}This tool supports Linux/macOS only.{C_RESET}")
        return

    print("Scanning listening ports (full details may require sudo) …")

    try:
        output = subprocess.check_output(
            "lsof -i -P -n | grep LISTEN", shell=True
        ).decode()
        print(f"\n{C_CYAN}{output}{C_RESET}")
        return
    except subprocess.CalledProcessError:
        print(f"{C_YELLOW}lsof failed or found nothing — trying netstat …{C_RESET}")

    try:
        output = subprocess.check_output("netstat -tuln", shell=True).decode()
        print(f"\n{C_CYAN}{output}{C_RESET}")
    except Exception as exc:
        print(f"{C_RED}Could not retrieve port data: {exc}{C_RESET}")


# ---------------------------------------------------------------------------
# Log Keyword Scanner
# ---------------------------------------------------------------------------

def tool_log_scanner() -> None:
    """Scan a log file for lines matching a keyword (case-insensitive)."""
    print(f"{C_BOLD}--- Log Keyword Scanner ---{C_RESET}")

    filepath = input("Path to log file: ").strip()
    keyword  = input("Search keyword (e.g. 'ERROR'): ").strip()
    max_hits = 20

    if not os.path.isfile(filepath):
        print(f"{C_RED}File not found: {filepath}{C_RESET}")
        return

    print(f"\nScanning {filepath} for '{keyword}' …\n")
    count = 0
    kw_lower = keyword.lower()

    try:
        with open(filepath, "r", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                if kw_lower in line.lower():
                    print(f"{C_CYAN}Line {line_no}:{C_RESET} {line.strip()[:120]}")
                    count += 1
                    if count >= max_hits:
                        print(f"{C_YELLOW}… stopped after {max_hits} matches.{C_RESET}")
                        break

        if count == 0:
            print(f"{C_GREEN}No matches found.{C_RESET}")
        else:
            print(f"\n{C_GREEN}Total matches shown: {count}{C_RESET}")

    except Exception as exc:
        print(f"{C_RED}Error reading file: {exc}{C_RESET}")
