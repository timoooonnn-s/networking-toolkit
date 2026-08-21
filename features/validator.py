"""
features/validator.py
---------------------
Pre / Post Change Validator
===========================
Take a snapshot of a device before a change, take another one after it, and
report exactly what moved.

The companion to the rollback generator: rollback tells you how to undo a
change, this tells you whether you need to.  A change window's real question
is never "did the command apply" — it is "did anything else break", and the
answer lives in the ports, VLANs, MLTs and LLDP neighbours that were *not*
supposed to change.

Snapshots are plain JSON under ``snapshots/`` so they survive the session,
can be diffed later, handed to someone else, or committed next to a change
ticket.

Platform support
----------------
VOSS / Fabric Engine (``extreme_vsp``) is parsed into structured facts by
features/voss_parsers.py, so the diff names the port, VLAN or neighbour that
changed.  Every other platform falls back to a raw-output diff of the same
command set: less precise, but it still answers the question and never
pretends to understand output it cannot parse.

Usage (interactive)
-------------------
    from features.validator import run_interactive
    run_interactive()

Usage (programmatic)
--------------------
    from features.validator import capture_snapshot, compare_snapshots

    pre  = capture_snapshot(profile, label="pre")
    #  ... apply the change ...
    post = capture_snapshot(profile, label="post")
    for finding in compare_snapshots(pre, post):
        print(finding.severity, finding.detail)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from core.audit_logger import AuditLogger
from core.colors import (
    C_BOLD,
    C_CYAN,
    C_GREEN,
    C_RED,
    C_RESET,
    C_YELLOW,
    pad,
)
from core.connection import CommandError, ConnectionFailed, SshRunner, command_slug
from core.dependency_check import check_dependency
from core.export import export_rows
from core.paths import SNAPSHOT_DIR, ensure_dir
from core.prompts import pick_target
from features import voss_parsers as voss

# ---------------------------------------------------------------------------
# Command sets
# ---------------------------------------------------------------------------
# (command, parser_key, required)
#
# required=False marks a command that legitimately does not exist on every
# model or release — a box with no vIST rejects `show virtual-ist`, and
# reporting that as a finding would train operators to ignore findings.

_VOSS_COMMANDS: list[tuple[str, str, bool]] = [
    ("show interfaces gigabitEthernet state",  "ports",      True),
    ("show vlan basic",                        "vlans",      True),
    ("show vlan i-sid",                        "vlan_isids", False),
    ("show vlan members",                      "members",    False),
    ("show mlt",                               "mlts",       True),
    ("show lldp neighbor summary",             "lldp",       False),
    ("show interfaces gigabitEthernet i-sid",  "port_isids", False),
    ("show virtual-ist",                       "ist",        False),
]

_GENERIC_COMMANDS: dict[str, list[tuple[str, str, bool]]] = {
    "cisco_ios": [
        ("show ip interface brief", "raw", True),
        ("show vlan brief",         "raw", False),
        ("show etherchannel summary", "raw", False),
        ("show cdp neighbors",      "raw", False),
    ],
    "cisco_xe": [
        ("show ip interface brief", "raw", True),
        ("show vlan brief",         "raw", False),
        ("show etherchannel summary", "raw", False),
        ("show lldp neighbors",     "raw", False),
    ],
    "juniper_junos": [
        ("show interfaces terse",   "raw", True),
        ("show vlans",              "raw", False),
        ("show lldp neighbors",     "raw", False),
    ],
    "extreme_exos": [
        ("show ports no-refresh",   "raw", True),
        ("show vlan",               "raw", False),
        ("show lldp neighbors",     "raw", False),
    ],
    "extreme_ers": [
        ("show interfaces",         "raw", True),
        ("show vlan",               "raw", False),
        ("show mlt",                "raw", False),
        ("show lldp neighbor",      "raw", False),
    ],
}

_VOSS_PARSERS = {
    "ports":      voss.parse_port_state,
    "vlans":      voss.parse_vlan_basic,
    "vlan_isids": voss.parse_vlan_isid,
    "members":    voss.parse_vlan_members,
    "mlts":       voss.parse_mlt,
    "lldp":       voss.parse_lldp_summary,
    "port_isids": voss.parse_port_isid,
    "ist":        voss.parse_ist,
}


def commands_for(device_type: str) -> list[tuple[str, str, bool]]:
    """Return the (command, key, required) set this platform is checked with."""
    if device_type == "extreme_vsp":
        return _VOSS_COMMANDS
    return _GENERIC_COMMANDS.get(device_type, _GENERIC_COMMANDS["cisco_ios"])


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One difference between a pre- and a post-change snapshot."""
    severity: str    # "CRIT", "WARN", "INFO"
    category: str    # "PORT", "VLAN", "MLT", "LLDP", "IST", "OUTPUT", "CAPTURE"
    subject:  str    # the port / VLAN id / MLT id the finding is about
    detail:   str

    def as_row(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "category": self.category,
            "subject":  self.subject,
            "detail":   self.detail,
        }


@dataclass
class Snapshot:
    """One device's state at one moment."""
    host:         str
    device_type:  str
    label:        str
    captured_at:  str
    facts:        dict[str, Any]       = field(default_factory=dict)
    raw:          dict[str, str]       = field(default_factory=dict)
    warnings:     list[str]            = field(default_factory=list)
    failed:       list[str]            = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host":        self.host,
            "device_type": self.device_type,
            "label":       self.label,
            "captured_at": self.captured_at,
            "facts":       self.facts,
            "raw":         self.raw,
            "warnings":    self.warnings,
            "failed":      self.failed,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Snapshot:
        return cls(
            host        = data.get("host", "unknown"),
            device_type = data.get("device_type", "cisco_ios"),
            label       = data.get("label", ""),
            captured_at = data.get("captured_at", ""),
            facts       = data.get("facts", {}),
            raw         = data.get("raw", {}),
            warnings    = data.get("warnings", []),
            failed      = data.get("failed", []),
        )


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

def capture_snapshot(
    profile: dict[str, Any],
    label: str = "pre",
    audit: bool = True,
) -> Snapshot:
    """
    Open one session, run the platform's command set, and return a Snapshot.

    Raises ConnectionFailed when the device could not be reached at all — a
    change window needs to know that immediately, not as an empty diff.
    """
    host        = profile.get("host", "unknown")
    device_type = profile.get("device_type", "cisco_ios")
    snapshot = Snapshot(
        host        = host,
        device_type = device_type,
        label       = label,
        captured_at = datetime.now().isoformat(timespec="seconds"),
    )

    audit_logger = AuditLogger(host) if audit else None
    try:
        runner = SshRunner(profile, audit=audit_logger)
    except ConnectionFailed:
        if audit_logger:
            audit_logger.close()
        raise

    try:
        snapshot.warnings.extend(runner.setup_warnings)
        for command, key, required in commands_for(device_type):
            try:
                output = runner.run(command)
            except CommandError as exc:
                if required:
                    snapshot.failed.append(command)
                    snapshot.warnings.append(
                        f"required command '{command}' failed: {exc}"
                    )
                else:
                    # Expected on releases/models without the feature.
                    snapshot.failed.append(command)
                continue

            snapshot.raw[command_slug(command)] = output
            parser = _VOSS_PARSERS.get(key) if device_type == "extreme_vsp" else None
            if parser is not None:
                snapshot.facts[key] = parser(output)
    finally:
        runner.close()
        if audit_logger:
            audit_logger.close()

    return snapshot


def save_snapshot(snapshot: Snapshot, path: Path | str | None = None) -> Path:
    """
    Write *snapshot* to ``snapshots/<host>_<label>_<timestamp>.json`` and
    return the path written.

    *path* is coerced with Path(): callers hand in whatever they have, and
    the CLI's ``--out`` arrives as a plain string.
    """
    if path is None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe  = snapshot.host.replace(".", "_").replace(":", "_")
        out   = ensure_dir(SNAPSHOT_DIR) / f"{safe}_{snapshot.label}_{stamp}.json"
    else:
        out = Path(path)
        ensure_dir(out.parent)

    out.write_text(json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8")
    return out


def load_snapshot(path) -> Snapshot:
    """Read a snapshot written by save_snapshot()."""
    with open(path) as handle:
        return Snapshot.from_dict(json.load(handle))


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def _compare_ports(pre: dict, post: dict) -> list[Finding]:
    findings: list[Finding] = []
    for port, before in sorted(pre.items()):
        after = post.get(port)
        if after is None:
            findings.append(Finding(
                "WARN", "PORT", port,
                "port disappeared from the post-change capture",
            ))
            continue
        if before.get("oper") != after.get("oper"):
            went_down = after.get("oper") != "up"
            reason    = after.get("reason") or "--"
            findings.append(Finding(
                "CRIT" if went_down else "INFO", "PORT", port,
                f"link {before.get('oper')} → {after.get('oper')}"
                + (f" (reason: {reason})" if went_down and reason != "--" else ""),
            ))
        if before.get("admin") != after.get("admin"):
            findings.append(Finding(
                "WARN", "PORT", port,
                f"admin state {before.get('admin')} → {after.get('admin')}",
            ))
    for port in sorted(set(post) - set(pre)):
        findings.append(Finding(
            "INFO", "PORT", port,
            f"new port in the post-change capture "
            f"(link {post[port].get('oper')})",
        ))
    return findings


def _compare_vlans(pre_basic: dict, post_basic: dict,
                   pre_isid: dict, post_isid: dict,
                   pre_members: dict, post_members: dict) -> list[Finding]:
    findings: list[Finding] = []

    for vlan in sorted(set(pre_basic) - set(post_basic), key=int):
        findings.append(Finding(
            "CRIT", "VLAN", vlan,
            f"VLAN '{pre_basic[vlan].get('name', '')}' no longer exists",
        ))
    for vlan in sorted(set(post_basic) - set(pre_basic), key=int):
        findings.append(Finding(
            "INFO", "VLAN", vlan,
            f"new VLAN '{post_basic[vlan].get('name', '')}'",
        ))
    for vlan in sorted(set(pre_basic) & set(post_basic), key=int):
        before, after = pre_basic[vlan], post_basic[vlan]
        if before.get("name") != after.get("name"):
            findings.append(Finding(
                "INFO", "VLAN", vlan,
                f"name '{before.get('name')}' → '{after.get('name')}'",
            ))

    # I-SID bindings: losing one silently takes a VLAN off the fabric.
    for vlan in sorted(set(pre_isid) & set(post_isid), key=int):
        before = pre_isid[vlan].get("isid", "")
        after  = post_isid[vlan].get("isid", "")
        if before != after:
            findings.append(Finding(
                "CRIT" if before and not after else "WARN", "VLAN", vlan,
                f"I-SID binding {before or '<none>'} → {after or '<none>'}",
            ))

    # Active members: a port that quietly left a VLAN is exactly what a
    # post-change check is for.
    for vlan in sorted(set(pre_members) & set(post_members), key=int):
        before = set(pre_members[vlan].get("active_members", []))
        after  = set(post_members[vlan].get("active_members", []))
        lost   = sorted(before - after)
        gained = sorted(after - before)
        if lost:
            findings.append(Finding(
                "CRIT", "VLAN", vlan,
                f"ports no longer active in this VLAN: {', '.join(lost)}",
            ))
        if gained:
            findings.append(Finding(
                "INFO", "VLAN", vlan,
                f"ports newly active in this VLAN: {', '.join(gained)}",
            ))
    return findings


def _compare_mlts(pre: dict, post: dict) -> list[Finding]:
    findings: list[Finding] = []
    for mlt in sorted(set(pre) - set(post), key=int):
        findings.append(Finding(
            "CRIT", "MLT", mlt,
            f"MLT '{pre[mlt].get('name', '')}' no longer exists",
        ))
    for mlt in sorted(set(post) - set(pre), key=int):
        findings.append(Finding("INFO", "MLT", mlt,
                                f"new MLT '{post[mlt].get('name', '')}'"))
    for mlt in sorted(set(pre) & set(post), key=int):
        before, after = pre[mlt], post[mlt]
        lost = sorted(set(before.get("members", [])) - set(after.get("members", [])))
        new  = sorted(set(after.get("members", [])) - set(before.get("members", [])))
        if lost:
            findings.append(Finding("CRIT", "MLT", mlt,
                                    f"lost member port(s): {', '.join(lost)}"))
        if new:
            findings.append(Finding("INFO", "MLT", mlt,
                                    f"new member port(s): {', '.join(new)}"))
        vlan_lost = sorted(set(before.get("vlans", [])) - set(after.get("vlans", [])))
        if vlan_lost:
            findings.append(Finding(
                "WARN", "MLT", mlt,
                f"VLAN(s) no longer carried: "
                f"{', '.join(str(v) for v in vlan_lost)}",
            ))
    return findings


def _compare_lldp(pre: dict, post: dict) -> list[Finding]:
    findings: list[Finding] = []
    for port in sorted(set(pre) - set(post)):
        neighbour = pre[port].get("sysname") or pre[port].get("ip") or "unknown"
        findings.append(Finding(
            "CRIT", "LLDP", port,
            f"lost neighbour '{neighbour}'",
        ))
    for port in sorted(set(post) - set(pre)):
        neighbour = post[port].get("sysname") or post[port].get("ip") or "unknown"
        findings.append(Finding("INFO", "LLDP", port,
                                f"new neighbour '{neighbour}'"))
    for port in sorted(set(pre) & set(post)):
        before, after = pre[port], post[port]
        if before.get("sysname") != after.get("sysname"):
            findings.append(Finding(
                "WARN", "LLDP", port,
                f"neighbour changed: '{before.get('sysname')}' → "
                f"'{after.get('sysname')}'",
            ))
        elif before.get("remote_port") != after.get("remote_port"):
            findings.append(Finding(
                "WARN", "LLDP", port,
                f"neighbour port changed: '{before.get('remote_port')}' → "
                f"'{after.get('remote_port')}'",
            ))
    return findings


def _compare_ist(pre: dict, post: dict) -> list[Finding]:
    if not pre and not post:
        return []
    if pre and not post:
        return [Finding("CRIT", "IST", pre.get("peer_ip", "?"),
                        "vIST is no longer reported at all")]
    if post and not pre:
        return [Finding("INFO", "IST", post.get("peer_ip", "?"),
                        "vIST appeared in the post-change capture")]
    findings: list[Finding] = []
    if pre.get("status") != post.get("status"):
        findings.append(Finding(
            "CRIT" if post.get("status") != "up" else "INFO",
            "IST", post.get("peer_ip", "?"),
            f"vIST status {pre.get('status')} → {post.get('status')}",
        ))
    if pre.get("peer_ip") != post.get("peer_ip"):
        findings.append(Finding(
            "WARN", "IST", post.get("peer_ip", "?"),
            f"vIST peer {pre.get('peer_ip')} → {post.get('peer_ip')}",
        ))
    return findings


def _compare_raw(pre: dict[str, str], post: dict[str, str]) -> list[Finding]:
    """
    Fallback for platforms with no structured parser: report which command
    outputs changed and by how many lines.

    Deliberately coarse.  Naming the command whose output moved is enough to
    send the operator to the right place; pretending to understand output the
    toolkit cannot parse would be worse than saying nothing.
    """
    import difflib

    findings: list[Finding] = []
    for slug in sorted(set(pre) & set(post)):
        before = pre[slug].splitlines()
        after  = post[slug].splitlines()
        if before == after:
            continue
        delta = [
            line for line in difflib.unified_diff(before, after, lineterm="", n=0)
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
        ]
        findings.append(Finding(
            "WARN", "OUTPUT", slug.replace("_", " "),
            f"output changed ({len(delta)} line(s) differ)",
        ))
    for slug in sorted(set(pre) - set(post)):
        findings.append(Finding("WARN", "OUTPUT", slug.replace("_", " "),
                                "command succeeded before the change but not after"))
    return findings


def compare_snapshots(pre: Snapshot, post: Snapshot) -> list[Finding]:
    """
    Diff two snapshots and return findings, most severe first.

    A capture that lost a required command is itself a finding: comparing
    against data that was never collected would report "no change" for a
    device nobody actually checked.
    """
    findings: list[Finding] = []

    newly_failed = set(post.failed) - set(pre.failed)
    for command in sorted(newly_failed):
        findings.append(Finding(
            "WARN", "CAPTURE", command,
            "command worked before the change and failed after it",
        ))

    if pre.device_type == "extreme_vsp" and post.device_type == "extreme_vsp":
        findings += _compare_ports(pre.facts.get("ports", {}),
                                   post.facts.get("ports", {}))
        findings += _compare_vlans(
            pre.facts.get("vlans", {}),      post.facts.get("vlans", {}),
            pre.facts.get("vlan_isids", {}), post.facts.get("vlan_isids", {}),
            pre.facts.get("members", {}),    post.facts.get("members", {}),
        )
        findings += _compare_mlts(pre.facts.get("mlts", {}),
                                  post.facts.get("mlts", {}))
        findings += _compare_lldp(pre.facts.get("lldp", {}),
                                  post.facts.get("lldp", {}))
        findings += _compare_ist(pre.facts.get("ist", {}),
                                 post.facts.get("ist", {}))
    else:
        findings += _compare_raw(pre.raw, post.raw)

    order = {"CRIT": 0, "WARN": 1, "INFO": 2}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.category, f.subject))
    return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_findings(findings: list[Finding], pre: Snapshot, post: Snapshot) -> None:
    """Render a coloured pre/post comparison report to stdout."""
    colour = {"CRIT": C_RED, "WARN": C_YELLOW, "INFO": C_CYAN}

    print(f"\n{C_BOLD}{'=' * 78}{C_RESET}")
    print(f"{C_BOLD}Pre/Post Change Validation — {post.host} ({post.device_type}){C_RESET}")
    print(f"  pre : {pre.captured_at}")
    print(f"  post: {post.captured_at}")
    print(f"{C_BOLD}{'=' * 78}{C_RESET}")

    for warning in post.warnings:
        print(f"{C_YELLOW}  ! {warning}{C_RESET}")

    if not findings:
        print(f"\n{C_GREEN}✔  No differences detected — the device looks "
              f"unchanged outside the intended change.{C_RESET}\n")
        return

    crit = sum(1 for f in findings if f.severity == "CRIT")
    warn = sum(1 for f in findings if f.severity == "WARN")
    print(f"\n{C_BOLD}{len(findings)} difference(s): "
          f"{C_RED}{crit} critical{C_RESET}{C_BOLD}, "
          f"{C_YELLOW}{warn} warning{C_RESET}{C_BOLD}, "
          f"{len(findings) - crit - warn} informational{C_RESET}\n")

    print(f"{C_BOLD}{pad('Severity', 9)}{pad('Category', 10)}"
          f"{pad('Subject', 22)}Detail{C_RESET}")
    print("─" * 78)
    for finding in findings:
        tint = colour.get(finding.severity, "")
        print(f"{pad(f'{tint}{finding.severity}{C_RESET}', 9)}"
              f"{pad(finding.category, 10)}"
              f"{pad(finding.subject, 22)}{finding.detail}")
    print()


# ---------------------------------------------------------------------------
# Interactive CLI entry point
# ---------------------------------------------------------------------------

def run_interactive() -> None:
    """Interactive pre/post change validation used by main_menu.py."""
    if not check_dependency("netmiko"):
        return

    print(f"{C_BOLD}--- Pre / Post Change Validator ---{C_RESET}")
    print(f"{C_YELLOW}Capture the device before your change, apply the change, "
          f"then capture again and compare.{C_RESET}")
    print("\n  1. Capture a snapshot (pre or post)")
    print("  2. Compare two saved snapshots")
    print("  3. Capture 'post' now and compare against a saved snapshot")
    mode = input("Choice: ").strip()

    if mode == "2":
        pre_path  = input("Path to the PRE snapshot JSON:  ").strip()
        post_path = input("Path to the POST snapshot JSON: ").strip()
        try:
            pre, post = load_snapshot(pre_path), load_snapshot(post_path)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"{C_RED}Could not read snapshots: {exc}{C_RESET}")
            return
        findings = compare_snapshots(pre, post)
        print_findings(findings, pre, post)
        if findings and input(f"{C_YELLOW}Export findings to CSV? (y/N): "
                              f"{C_RESET}").strip().lower() == "y":
            export_rows([f.as_row() for f in findings], f"validation_{post.host}")
        return

    target = pick_target(default_device_type="extreme_vsp")
    if target is None:
        return
    _name, profile = target

    if mode == "3":
        pre_path = input("Path to the PRE snapshot JSON: ").strip()
        try:
            pre = load_snapshot(pre_path)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"{C_RED}Could not read the pre snapshot: {exc}{C_RESET}")
            return
        label = "post"
    else:
        pre   = None
        label = (input("Snapshot label [pre]: ").strip() or "pre").lower()

    print(f"\n{C_CYAN}Capturing '{label}' snapshot from "
          f"{profile['host']} ...{C_RESET}")
    try:
        snapshot = capture_snapshot(profile, label=label)
    except ConnectionFailed as exc:
        print(f"{C_RED}{exc}{C_RESET}")
        return

    path = save_snapshot(snapshot)
    ok   = len(snapshot.raw)
    print(f"{C_GREEN}Captured {ok} command output(s) → {path}{C_RESET}")
    for warning in snapshot.warnings:
        print(f"{C_YELLOW}  ! {warning}{C_RESET}")

    if pre is not None:
        findings = compare_snapshots(pre, snapshot)
        print_findings(findings, pre, snapshot)
        if findings and input(f"{C_YELLOW}Export findings to CSV? (y/N): "
                              f"{C_RESET}").strip().lower() == "y":
            export_rows([f.as_row() for f in findings], f"validation_{snapshot.host}")
    else:
        print(f"{C_CYAN}Apply your change, then run this tool again with "
              f"option 3 and this file as the PRE snapshot.{C_RESET}")
