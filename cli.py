"""
cli.py
------
Non-interactive entry point for the SysNet Toolkit.

Everything the menu does interactively, the tools that make sense unattended
also do from argparse — so the toolkit can run from cron, a CI job or a
change-window script instead of only from a keyboard:

    python3 cli.py ping      --targets 192.168.1.0/24 --format csv
    python3 cli.py backup    --targets tag:core --git
    python3 cli.py run       --targets all --command "show sys-info"
    python3 cli.py snapshot  --target core-vsp-01 --label pre
    python3 cli.py compare   --pre snapshots/a.json --post snapshots/b.json
    python3 cli.py snmp      preset --target core-vsp-01 --preset if-oper-status
    python3 cli.py snmp      preset --target core-vsp-01 --preset port-up --port 1/1 --yes
    python3 cli.py inventory

Credentials come from $SYSNET_USER / $SYSNET_PASS.  When they are absent and
stdin is a terminal the tool prompts once; when it is not (cron), it fails
with a message naming the variables rather than hanging on a prompt nobody
can answer.

Exit codes are meant to be checked by whatever ran this:
    0  success, nothing to report
    1  the operation found a problem (host down, device changed, findings)
    2  the operation could not run (bad arguments, no credentials, no targets)
"""

from __future__ import annotations

import argparse
import json
import sys

from core.colors import C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW, VERSION

EXIT_OK       = 0
EXIT_FINDINGS = 1
EXIT_ERROR    = 2


class _NoPreset:
    """Stand-in so an unknown preset name is reported, not crashed on."""
    writes = False


_NO_PRESET = _NoPreset()


# ---------------------------------------------------------------------------
# Credential handling for unattended runs
# ---------------------------------------------------------------------------

def _resolve_credentials(username: str | None) -> tuple[str, str] | None:
    """
    Return (username, password) or None when they cannot be obtained.

    A cron job with no credentials must fail loudly and immediately; hanging
    on a getpass prompt that nothing will ever answer is the worst outcome.
    """
    import os

    from core.inventory import get_credentials

    user = username or os.environ.get("SYSNET_USER")
    if os.environ.get("SYSNET_PASS"):
        return get_credentials(user)

    if not sys.stdin.isatty():
        print(f"{C_RED}No credentials available and stdin is not a terminal.{C_RESET}",
              file=sys.stderr)
        print(f"{C_YELLOW}Set SYSNET_USER and SYSNET_PASS in the environment.{C_RESET}",
              file=sys.stderr)
        return None

    return get_credentials(user)


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_ping(args: argparse.Namespace) -> int:
    from core.export import export_rows
    from features.multiping import expand_targets, ping_hosts, print_results

    hosts = expand_targets(args.targets)
    if not hosts:
        print(f"{C_RED}No targets to probe.{C_RESET}", file=sys.stderr)
        return EXIT_ERROR

    results = ping_hosts(hosts, timeout_ms=args.timeout, retries=args.retries,
                         prefer_fping=not args.no_fping)
    if not args.quiet:
        print_results(results)

    if args.format:
        export_rows([r.as_row() for r in results], "reachability", fmt=args.format,
                    path=args.out)

    down = [r for r in results if not r.alive]
    if down and args.quiet:
        print(f"{len(down)} of {len(results)} host(s) down: "
              f"{', '.join(r.host for r in down[:20])}")
    return EXIT_FINDINGS if down else EXIT_OK


def cmd_backup(args: argparse.Namespace) -> int:
    from core.export import export_rows
    from features.backup import backup_targets, git_commit_backups, print_results

    credentials = _resolve_credentials(args.username)
    if credentials is None:
        return EXIT_ERROR
    username, password = credentials

    results = backup_targets(args.targets, workers=args.workers,
                             username=username, password=password)
    if not results:
        print(f"{C_RED}No inventory device matched '{args.targets}'.{C_RESET}",
              file=sys.stderr)
        return EXIT_ERROR

    print_results(results)
    if args.git:
        git_commit_backups()
    if args.format:
        export_rows([r.as_row() for r in results], "config_backup",
                    fmt=args.format, path=args.out)

    return EXIT_FINDINGS if any(not r.ok for r in results) else EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    from core.export import export_rows
    from core.inventory import build_ad_hoc_profile, resolve_targets
    from features.ssh_runner import print_results, run_bulk_ssh

    credentials = _resolve_credentials(args.username)
    if credentials is None:
        return EXIT_ERROR
    username, password = credentials

    entries = resolve_targets(args.targets)
    if not entries:
        print(f"{C_RED}No inventory device matched '{args.targets}'.{C_RESET}",
              file=sys.stderr)
        return EXIT_ERROR

    devices = []
    for name, entry in entries:
        try:
            devices.append(build_ad_hoc_profile(
                host        = entry["host"],
                device_type = entry.get("device_type", "cisco_ios"),
                username    = username,
                password    = password,
                port        = int(entry.get("port", 22)),
                secret      = entry.get("secret", ""),
            ))
        except ValueError as exc:
            print(f"{C_YELLOW}Skipping {name}: {exc}{C_RESET}", file=sys.stderr)

    if not devices:
        print(f"{C_RED}None of the {len(entries)} matched device(s) had a "
              f"usable connection profile.{C_RESET}", file=sys.stderr)
        return EXIT_ERROR

    results = run_bulk_ssh(devices, args.command, max_workers=args.workers)

    # run_bulk_ssh returns nothing at all when Netmiko is missing.  Reporting
    # that as success is how a broken cron job stays green forever: no device
    # was contacted, so this is "could not run", not "nothing to report".
    if not results:
        print(f"{C_RED}No device was contacted — see the message above "
              f"(Netmiko missing, or every session failed to start).{C_RESET}",
              file=sys.stderr)
        return EXIT_ERROR

    print_results(results)

    if args.format:
        rows = [row for result in results for row in result.as_rows()]
        export_rows(rows, "ssh_bulk", fmt=args.format, path=args.out)

    unreachable = any(not r.success for r in results)
    rejected    = any(r.failed for r in results)
    return EXIT_FINDINGS if (unreachable or rejected) else EXIT_OK


def cmd_snapshot(args: argparse.Namespace) -> int:
    from core.connection import ConnectionFailed
    from core.inventory import build_ad_hoc_profile, resolve_targets
    from features.validator import capture_snapshot, save_snapshot

    credentials = _resolve_credentials(args.username)
    if credentials is None:
        return EXIT_ERROR
    username, password = credentials

    entries = resolve_targets(args.target)
    if not entries:
        print(f"{C_RED}No inventory device matched '{args.target}'.{C_RESET}",
              file=sys.stderr)
        return EXIT_ERROR
    if len(entries) > 1:
        print(f"{C_YELLOW}'{args.target}' matched {len(entries)} devices; "
              f"snapshotting '{entries[0][0]}'.{C_RESET}")

    _name, entry = entries[0]
    profile = build_ad_hoc_profile(
        host        = entry["host"],
        device_type = entry.get("device_type", "extreme_vsp"),
        username    = username,
        password    = password,
        port        = int(entry.get("port", 22)),
        secret      = entry.get("secret", ""),
    )

    try:
        snapshot = capture_snapshot(profile, label=args.label)
    except ConnectionFailed as exc:
        print(f"{C_RED}{exc}{C_RESET}", file=sys.stderr)
        return EXIT_ERROR

    path = save_snapshot(snapshot, args.out)
    print(f"{C_GREEN}Captured {len(snapshot.raw)} command output(s) "
          f"→ {path}{C_RESET}")
    for warning in snapshot.warnings:
        print(f"{C_YELLOW}  ! {warning}{C_RESET}")
    return EXIT_OK


def cmd_compare(args: argparse.Namespace) -> int:
    from core.export import export_rows
    from features.validator import compare_snapshots, load_snapshot, print_findings

    try:
        pre  = load_snapshot(args.pre)
        post = load_snapshot(args.post)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{C_RED}Could not read snapshots: {exc}{C_RESET}", file=sys.stderr)
        return EXIT_ERROR

    findings = compare_snapshots(pre, post)
    print_findings(findings, pre, post)

    if args.format:
        export_rows([f.as_row() for f in findings], f"validation_{post.host}",
                    fmt=args.format, path=args.out)

    critical = [f for f in findings if f.severity == "CRIT"]
    if args.fail_on == "any":
        return EXIT_FINDINGS if findings else EXIT_OK
    return EXIT_FINDINGS if critical else EXIT_OK


def cmd_snmp(args: argparse.Namespace) -> int:
    """
    SNMP reads and writes from the command line.

    Writes need --yes.  Requiring it explicitly is the point: an unattended
    SNMP SET against the wrong ifIndex takes a port down, and there is no
    confirmation prompt out here to catch it.
    """
    from core.export import export_rows
    from core.inventory import load_inventory, resolve_targets
    from core.snmp import snmp_get, snmp_set, snmp_walk
    from features.snmp_assistant import (
        annotate,
        build_ifindex_map,
        credentials_for,
        describe_write,
        print_presets,
        print_result,
        resolve_ifindex,
        run_preset,
    )
    from features.snmp_presets import PresetStore

    store = PresetStore.load()

    if args.snmp_action == "presets":
        print_presets(store.matching(platform=args.platform or "",
                                     writes_only=args.writes_only))
        return EXIT_OK

    # --- resolve the target through the inventory when it knows the name ---
    inventory = load_inventory()
    # quiet: the SNMP tools accept a bare IP, so "not in the inventory"
    # is an ordinary case here rather than something to warn about.
    matches   = resolve_targets(args.target, inventory, quiet=True)
    if matches:
        name, entry = matches[0]
        host = entry["host"]
        if len(matches) > 1:
            print(f"{C_YELLOW}'{args.target}' matched {len(matches)} devices; "
                  f"using '{name}'.{C_RESET}", file=sys.stderr)
    else:
        host, entry = args.target, {}

    writes = args.snmp_action == "set" or (
        args.snmp_action == "preset"
        and (store.get(args.preset) or _NO_PRESET).writes
    )

    # Unattended runs must not stop on a getpass prompt nothing can answer.
    creds = credentials_for(entry, write=writes, prompt=sys.stdin.isatty())
    problem = creds.validate()
    if problem:
        print(f"{C_RED}{problem}{C_RESET}", file=sys.stderr)
        print(f"{C_YELLOW}Set SNMP_COMMUNITY (or SNMP_WRITE_COMMUNITY for "
              f"writes), or the SNMP_V3_* variables for v3.{C_RESET}",
              file=sys.stderr)
        return EXIT_ERROR

    # --- ifIndex, when the operation needs one ---
    ifindex = args.ifindex
    if args.port and not ifindex:
        mapping, error = build_ifindex_map(host, credentials_for(entry, prompt=False))
        if not mapping:
            print(f"{C_RED}Could not read the interface table: "
                  f"{error or 'no rows returned'}{C_RESET}", file=sys.stderr)
            return EXIT_ERROR
        ifindex = resolve_ifindex(args.port, mapping)
        if ifindex is None:
            print(f"{C_RED}'{args.port}' did not match exactly one "
                  f"interface.{C_RESET}", file=sys.stderr)
            return EXIT_ERROR
        print(f"{C_CYAN}{args.port} → ifIndex {ifindex}{C_RESET}")

    # --- run it ---
    if args.snmp_action == "preset":
        preset = store.get(args.preset)
        if preset is None:
            print(f"{C_RED}No preset called '{args.preset}'. "
                  f"List them with: cli.py snmp presets{C_RESET}", file=sys.stderr)
            return EXIT_ERROR
        if preset.writes and not args.yes:
            try:
                oid, value = preset.resolve(ifindex=ifindex, value=args.value)
            except ValueError as exc:
                print(f"{C_RED}{exc}{C_RESET}", file=sys.stderr)
                return EXIT_ERROR
            print(f"{C_RED}This preset WRITES to the device:{C_RESET}")
            print(describe_write(preset, host, oid, value, creds))
            print(f"{C_YELLOW}Re-run with --yes to send it.{C_RESET}")
            return EXIT_ERROR
        result = run_preset(preset, host, creds, ifindex=ifindex, value=args.value)
        title  = f"{preset.name} on {host}"

    elif args.snmp_action == "get":
        result = snmp_get(host, args.oid, creds)
        title  = f"GET on {host}"

    elif args.snmp_action == "walk":
        result = snmp_walk(host, args.oid[0], creds)
        title  = f"WALK {args.oid[0]} on {host}"

    else:   # set
        if not args.yes:
            print(f"{C_RED}Refusing to write without --yes.{C_RESET}",
                  file=sys.stderr)
            print(f"  {host}  {args.oid[0]} = {args.type}:{args.value}",
                  file=sys.stderr)
            return EXIT_ERROR
        result = snmp_set(host, args.oid[0], args.type, args.value, creds)
        title  = f"SET {args.oid[0]} on {host}"

    print_result(result, title)
    if result.ok and args.format:
        export_rows(annotate(result.varbinds), f"snmp_{args.snmp_action}",
                    fmt=args.format, path=args.out)
    return EXIT_OK if result.ok else EXIT_FINDINGS


def cmd_inventory(args: argparse.Namespace) -> int:
    from core.export import export_rows
    from core.inventory import load_inventory, resolve_targets
    from core.paths import INVENTORY_FILE

    inventory = load_inventory()
    entries   = resolve_targets(args.targets, inventory) if args.targets else \
        sorted(inventory.items())

    if not entries:
        print(f"{C_YELLOW}No devices matched.{C_RESET}")
        return EXIT_OK

    print(f"{C_CYAN}Inventory file: {INVENTORY_FILE}"
          f"{'' if INVENTORY_FILE.exists() else '  (not present — built-in example)'}"
          f"{C_RESET}\n")
    print(f"{C_BOLD}{'Name':<26}{'Host':<18}{'Type':<16}{'Port':<6}Tags{C_RESET}")
    print("─" * 78)
    rows = []
    for name, entry in entries:
        tags = ",".join(str(t) for t in entry.get("tags", []))
        print(f"{name:<26}{entry.get('host', ''):<18}"
              f"{entry.get('device_type', ''):<16}{str(entry.get('port', 22)):<6}{tags}")
        rows.append({"name": name, "host": entry.get("host", ""),
                     "device_type": entry.get("device_type", ""),
                     "port": entry.get("port", 22), "tags": tags})

    if args.format:
        export_rows(rows, "inventory", fmt=args.format, path=args.out)
    return EXIT_OK


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="SysNet Toolkit — non-interactive entry point. "
                    "Run 'python3 main_menu.py' for the interactive menu.",
        epilog="Credentials: set SYSNET_USER and SYSNET_PASS for unattended runs.",
    )
    parser.add_argument("--version", action="version", version=f"SysNet Toolkit {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_export_flags(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--format", choices=("csv", "json"),
                         help="also write the result to a file")
        sub.add_argument("--out", help="explicit output path (implies --format)")

    # --- ping ---
    ping = subparsers.add_parser(
        "ping", help="multi-host reachability check (fping when available)")
    ping.add_argument("--targets", required=True,
                      help="hosts, CIDR, prefix or range — see 'expand_targets'")
    ping.add_argument("--timeout", type=int, default=800,
                      help="per-probe timeout in ms (default: 800)")
    ping.add_argument("--retries", type=int, default=1,
                      help="probe retries per host (default: 1)")
    ping.add_argument("--no-fping", action="store_true",
                      help="force the system ping even when fping is installed")
    ping.add_argument("--quiet", action="store_true",
                      help="print only the down hosts")
    add_export_flags(ping)
    ping.set_defaults(func=cmd_ping)

    # --- backup ---
    backup = subparsers.add_parser(
        "backup", help="pull running-config from inventory devices")
    backup.add_argument("--targets", default="all",
                        help="device name, IP, tag:<tag> or all (default: all)")
    backup.add_argument("--username", help="override $SYSNET_USER")
    backup.add_argument("--workers", type=int, default=8,
                        help="parallel sessions (default: 8)")
    backup.add_argument("--git", action="store_true",
                        help="commit the backup tree afterwards")
    add_export_flags(backup)
    backup.set_defaults(func=cmd_backup)

    # --- run ---
    run = subparsers.add_parser(
        "run", help="run commands across inventory devices")
    run.add_argument("--targets", required=True,
                     help="device name, IP, tag:<tag> or all")
    run.add_argument("--command", required=True, action="append",
                     help="a command to run; repeat for several, in order")
    run.add_argument("--username", help="override $SYSNET_USER")
    run.add_argument("--workers", type=int, default=10,
                     help="parallel sessions (default: 10)")
    add_export_flags(run)
    run.set_defaults(func=cmd_run)

    # --- snapshot ---
    snapshot = subparsers.add_parser(
        "snapshot", help="capture a pre/post change snapshot of one device")
    snapshot.add_argument("--target", required=True,
                          help="device name or IP from the inventory")
    snapshot.add_argument("--label", default="pre",
                          help="snapshot label, e.g. pre or post (default: pre)")
    snapshot.add_argument("--username", help="override $SYSNET_USER")
    snapshot.add_argument("--out", help="explicit output path for the JSON")
    snapshot.set_defaults(func=cmd_snapshot)

    # --- compare ---
    compare = subparsers.add_parser(
        "compare", help="compare two snapshots and report what changed")
    compare.add_argument("--pre", required=True, help="path to the PRE snapshot")
    compare.add_argument("--post", required=True, help="path to the POST snapshot")
    compare.add_argument("--fail-on", choices=("crit", "any"), default="crit",
                         help="exit 1 on critical findings only (default) or on any")
    add_export_flags(compare)
    compare.set_defaults(func=cmd_compare)

    # --- snmp ---
    snmp = subparsers.add_parser(
        "snmp", help="SNMP reads and writes, with a saved-preset library")
    snmp_actions = snmp.add_subparsers(dest="snmp_action", required=True)

    def add_snmp_target(sub: argparse.ArgumentParser, needs_target: bool = True) -> None:
        if needs_target:
            sub.add_argument("--target", required=True,
                             help="inventory device name, or a bare IP/hostname")
            sub.add_argument("--port", help="port NAME to resolve to an ifIndex "
                                            "(e.g. 1/1); walks ifName to do it")
            sub.add_argument("--ifindex", help="ifIndex directly, skipping the walk")
        add_export_flags(sub)

    snmp_get_p = snmp_actions.add_parser("get", help="read one or more OIDs")
    snmp_get_p.add_argument("--oid", required=True, action="append",
                            help="numeric OID; repeat for several")
    add_snmp_target(snmp_get_p)

    snmp_walk_p = snmp_actions.add_parser("walk", help="read a subtree")
    snmp_walk_p.add_argument("--oid", required=True, action="append",
                             help="numeric root OID of the subtree")
    add_snmp_target(snmp_walk_p)

    snmp_set_p = snmp_actions.add_parser("set", help="write one OID (needs --yes)")
    snmp_set_p.add_argument("--oid", required=True, action="append",
                            help="numeric OID to write")
    snmp_set_p.add_argument("--type", required=True,
                            help="net-snmp type code: i u s x a o t c")
    snmp_set_p.add_argument("--value", required=True, help="value to write")
    snmp_set_p.add_argument("--yes", action="store_true",
                            help="confirm the write; without it nothing is sent")
    add_snmp_target(snmp_set_p)

    snmp_preset_p = snmp_actions.add_parser(
        "preset", help="run a saved preset by name")
    snmp_preset_p.add_argument("--preset", required=True, help="preset name")
    snmp_preset_p.add_argument("--value", help="value, for presets that write one")
    snmp_preset_p.add_argument("--yes", action="store_true",
                               help="confirm, for presets that write")
    add_snmp_target(snmp_preset_p)

    snmp_presets_p = snmp_actions.add_parser(
        "presets", help="list the available presets")
    snmp_presets_p.add_argument("--platform", help="filter by platform")
    snmp_presets_p.add_argument("--writes-only", action="store_true",
                                help="show only presets that write")
    add_snmp_target(snmp_presets_p, needs_target=False)

    snmp.set_defaults(func=cmd_snmp)

    # --- inventory ---
    inventory = subparsers.add_parser(
        "inventory", help="list the device inventory")
    inventory.add_argument("--targets", help="filter with a selector")
    add_export_flags(inventory)
    inventory.set_defaults(func=cmd_inventory)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    # --out on its own is a clear enough intent to export.
    if (getattr(args, "out", None) and not getattr(args, "format", None)
            and args.command != "snapshot"):
        args.format = "json" if str(args.out).endswith(".json") else "csv"

    # Every snmp sub-action reads the same attribute set; fill in the ones
    # its own parser does not define so cmd_snmp never needs hasattr checks.
    if getattr(args, "command", None) == "snmp":
        for attribute, default in (("target", ""), ("port", None), ("ifindex", None),
                                   ("value", None), ("yes", False), ("preset", ""),
                                   ("oid", []), ("type", "s"), ("platform", ""),
                                   ("writes_only", False), ("format", None),
                                   ("out", None)):
            if not hasattr(args, attribute):
                setattr(args, attribute, default)

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}Cancelled.{C_RESET}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
