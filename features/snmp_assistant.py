"""
features/snmp_assistant.py
--------------------------
SNMP Assistant
==============
Make SNMP reads and writes something you can actually do under pressure.

Three things it gives you over raw ``snmpget``:

1. **Saved operations.** A named library of presets, so recovery does not
   depend on remembering that ifAdminStatus is 1.3.6.1.2.1.2.2.1.7 and that
   "up" is 1. See features/snmp_presets.py.
2. **Port names instead of ifIndex numbers.** SNMP addresses ports by
   ifIndex, and the mapping is not guessable — on a VOSS switch, port ``1/1``
   is ifIndex 192 and ``2/1/1`` is 400. The assistant walks ifName once and
   lets you say ``1/1``.
3. **Writes you can trust yourself with.** Every SET shows exactly what will
   be sent, needs confirmation, and lands in the audit log.

The break-glass case, honestly
------------------------------
The motivating scenario is "I broke SSH on a switch and cannot get back in".
Two things have to be true for SNMP to rescue you, and both are worth knowing
*before* you need them:

* **SNMP write access must already be configured.** A device with read-only
  SNMP will answer every GET and refuse every SET with ``notWritable`` or
  ``noAccess``. Set it up while you can still log in.
* **The object you need must exist.** ``ifAdminStatus`` is standard and
  writable, so bouncing a port always works — that alone recovers a wedged
  uplink or a port you shut by accident. Re-enabling an SSH *daemon* needs a
  vendor-private object, which this toolkit does not ship guessed values for;
  use ``discover`` to find and pin the real OID from your own switch first.

If neither applies, the console or an out-of-band management port is your
recovery path, and no SNMP tool changes that.

Usage (interactive)
-------------------
    from features.snmp_assistant import run_interactive
    run_interactive()

Usage (programmatic)
--------------------
    from features.snmp_assistant import resolve_ifindex, run_preset
    from core.snmp import SnmpCredentials

    creds = SnmpCredentials(version="2c", community="public")
    result = run_preset(store.get("port-up"), "10.0.0.1", creds, ifindex=192)
"""

from __future__ import annotations

import getpass
import os
import re
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
from core.export import offer_export
from core.inventory import load_inventory, resolve_targets
from core.paths import SNMP_PRESETS_FILE
from core.snmp import (
    SET_TYPE_CODES,
    SnmpCredentials,
    SnmpResult,
    VarBind,
    engine_description,
    have_netsnmp,
    snmp_get,
    snmp_set,
    snmp_walk,
)
from features.snmp_presets import (
    EXTREME_ROOT,
    RAPIDCITY_ROOT,
    Preset,
    PresetStore,
)

# IF-MIB tables used to turn a port name into an ifIndex.
OID_IF_NAME  = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"

# Enum decoding for the two status columns, so a walk reads as words.
_STATUS_WORDS = {
    "1.3.6.1.2.1.2.2.1.7": {1: "up", 2: "down", 3: "testing"},
    "1.3.6.1.2.1.2.2.1.8": {1: "up", 2: "down", 3: "testing",
                            4: "unknown", 5: "dormant",
                            6: "notPresent", 7: "lowerLayerDown"},
}


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def credentials_for(
    entry: dict[str, Any] | None = None,
    write: bool = False,
    prompt: bool = True,
) -> SnmpCredentials:
    """
    Build SNMP credentials for one device.

    Resolution order, most specific first:

      1. the inventory entry's own ``snmp_*`` fields
      2. environment variables ($SNMP_COMMUNITY, $SNMP_V3_USER, ...)
      3. an interactive prompt (skipped when *prompt* is False)

    The read and write communities are separate on purpose: a device commonly
    has a public read string and a closely-held write one, and nothing should
    make you paste the write string for a GET.  As with ``secret_env``
    elsewhere in the toolkit, the inventory names an *environment variable*
    rather than holding the secret itself.
    """
    entry = entry or {}

    version = str(entry.get("snmp_version") or os.environ.get("SNMP_VERSION", "2c"))
    creds = SnmpCredentials(version=version)
    creds.port = int(entry.get("snmp_port", 161))

    if version == "3":
        creds.user = (entry.get("snmp_v3_user")
                      or os.environ.get("SNMP_V3_USER", ""))
        creds.auth_protocol = (entry.get("snmp_v3_auth_protocol")
                               or os.environ.get("SNMP_V3_AUTH_PROTO", "SHA"))
        creds.priv_protocol = (entry.get("snmp_v3_priv_protocol")
                               or os.environ.get("SNMP_V3_PRIV_PROTO", "AES"))
        creds.auth_key = _from_env_or_entry(
            entry, "snmp_v3_auth_key_env", "SNMP_V3_AUTH_KEY")
        creds.priv_key = _from_env_or_entry(
            entry, "snmp_v3_priv_key_env", "SNMP_V3_PRIV_KEY")

        if not creds.user and prompt:
            creds.user = input("SNMPv3 user: ").strip()
        if not creds.auth_key and prompt:
            creds.auth_key = getpass.getpass(
                "SNMPv3 auth key (blank for noAuthNoPriv): ")
        if creds.auth_key and not creds.priv_key and prompt:
            creds.priv_key = getpass.getpass(
                "SNMPv3 privacy key (blank for authNoPriv): ")
        return creds

    if write:
        creds.community = _from_env_or_entry(
            entry, "snmp_write_community_env", "SNMP_WRITE_COMMUNITY")
        if not creds.community and prompt:
            creds.community = getpass.getpass("SNMP write community: ")
    else:
        creds.community = _from_env_or_entry(
            entry, "snmp_community_env", "SNMP_COMMUNITY")
        if not creds.community and prompt:
            creds.community = getpass.getpass("SNMP read community: ") or "public"
    return creds


def _from_env_or_entry(entry: dict[str, Any], entry_key: str, env_key: str) -> str:
    """Read a secret named by the inventory, falling back to a global env var."""
    named = entry.get(entry_key)
    if named:
        return os.environ.get(str(named), "")
    return os.environ.get(env_key, "")


# ---------------------------------------------------------------------------
# ifIndex resolution
# ---------------------------------------------------------------------------

def build_ifindex_map(
    host: str,
    creds: SnmpCredentials,
) -> tuple[dict[str, str], str]:
    """
    Walk ifName (falling back to ifDescr) and return ({name: ifIndex}, error).

    The ifIndex is the last arc of each returned OID.  Both tables are worth
    trying: some agents leave ifName empty and only populate ifDescr.
    """
    mapping: dict[str, str] = {}
    last_error = ""

    for root in (OID_IF_NAME, OID_IF_DESCR):
        result = snmp_walk(host, root, creds)
        if not result.ok:
            last_error = result.error
            continue
        for varbind in result.varbinds:
            name = str(varbind.value or "").strip()
            index = varbind.oid.rsplit(".", 1)[-1]
            if name and index.isdigit():
                mapping.setdefault(name, index)
        if mapping:
            return mapping, ""
    return mapping, last_error


def resolve_ifindex(
    port: str,
    mapping: dict[str, str],
) -> str | None:
    """
    Turn a port name into an ifIndex using a walked map.

    Matching is forgiving on purpose: an operator types ``1/1`` while the
    agent may report ``Port1/1``, ``1/1`` or ``GigabitEthernet1/1``.  A plain
    number is taken as an ifIndex already.  An exact match always wins over a
    suffix match, so ``1/1`` can never be captured by ``11/1``.
    """
    wanted = (port or "").strip()
    if not wanted:
        return None
    if wanted.isdigit() and wanted not in mapping:
        return wanted                      # already an ifIndex

    for name, index in mapping.items():
        if name.lower() == wanted.lower():
            return index

    # Suffix match, anchored so '1/1' does not match '11/1'.
    pattern = re.compile(rf"(^|[^0-9/]){re.escape(wanted)}$", re.IGNORECASE)
    matches = [index for name, index in mapping.items() if pattern.search(name)]
    return matches[0] if len(matches) == 1 else None


# ---------------------------------------------------------------------------
# Running presets
# ---------------------------------------------------------------------------

def run_preset(
    preset: Preset,
    host: str,
    creds: SnmpCredentials,
    ifindex: str | int | None = None,
    value: str | None = None,
    audit: bool = True,
) -> SnmpResult:
    """
    Execute one preset against one host.

    Confirmation is the caller's job — by the time this runs, the write has
    been agreed.  Writes are always audit-logged, successful or not, because
    "what did we send that device at 02:00" is the question you will actually
    be asked afterwards.
    """
    try:
        oid, resolved_value = preset.resolve(ifindex=ifindex, value=value)
    except ValueError as exc:
        return SnmpResult(False, error=str(exc))

    if preset.mode == "walk":
        return snmp_walk(host, oid, creds)
    if preset.mode == "get":
        return snmp_get(host, [oid], creds)
    if preset.mode != "set":
        return SnmpResult(False, error=f"unknown preset mode '{preset.mode}'")

    logger = AuditLogger(host) if audit else None
    try:
        result = snmp_set(host, oid, preset.value_type, resolved_value, creds)
        if logger is not None:
            # The community/key is never part of this line.
            command = (f"SNMP SET {oid} = {preset.value_type}:{resolved_value} "
                       f"[preset {preset.name}, {creds.redacted()}]")
            if result.ok:
                logger.log(command=command,
                           output="\n".join(f"{v.oid} = {v.type}: {v.value}"
                                            for v in result.varbinds) or "accepted")
            else:
                logger.log_error(command=command, error=result.error)
        return result
    finally:
        if logger is not None:
            logger.close()


def describe_write(
    preset: Preset,
    host: str,
    oid: str,
    value: str,
    creds: SnmpCredentials,
) -> str:
    """The exact write, rendered for a confirmation prompt."""
    type_name = SET_TYPE_CODES.get(preset.value_type, preset.value_type)
    return (
        f"  device : {host}:{creds.port}  ({creds.redacted()})\n"
        f"  oid    : {oid}\n"
        f"  value  : {value}   [{type_name}]\n"
        f"  preset : {preset.name} — {preset.description}"
    )


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

def annotate(varbinds: list[VarBind]) -> list[dict[str, Any]]:
    """
    Rows for display and export, with status enums spelled out.

    ``ifAdminStatus = 2`` is correct but unhelpful at 02:00; ``2 (down)`` is
    the same fact in a form you can act on.
    """
    rows: list[dict[str, Any]] = []
    for varbind in varbinds:
        shown = varbind.value
        for root, words in _STATUS_WORDS.items():
            if varbind.oid.lstrip(".").startswith(root) and isinstance(shown, int):
                shown = f"{shown} ({words.get(shown, '?')})"
                break
        rows.append({"oid": varbind.oid, "type": varbind.type, "value": shown})
    return rows


def print_result(result: SnmpResult, title: str = "") -> None:
    """Render one operation's outcome."""
    if title:
        print(f"\n{C_BOLD}{title}{C_RESET}")

    if not result.ok:
        print(f"{C_RED}✘ {result.error}{C_RESET}")
        return

    if not result.varbinds:
        print(f"{C_YELLOW}The agent answered, but returned nothing for that "
              f"OID (an empty table, or an object it does not implement).{C_RESET}")
        return

    rows = annotate(result.varbinds)
    width = min(46, max(len(r["oid"]) for r in rows) + 2)
    print(f"{C_BOLD}{pad('OID', width)}{pad('Type', 14)}Value{C_RESET}")
    print("─" * 78)
    for row in rows:
        print(f"{pad(row['oid'], width)}{pad(str(row['type']), 14)}"
              f"{C_GREEN}{row['value']}{C_RESET}")

    print(f"\n{C_CYAN}{len(rows)} value(s) via {result.engine}.{C_RESET}")
    if result.error:
        # A walk that returned partial data plus a reason.
        print(f"{C_YELLOW}Stopped early: {result.error}{C_RESET}")


def print_presets(presets: list[Preset]) -> None:
    """Render the preset library."""
    print(f"\n{C_BOLD}{pad('Name', 20)}{pad('Mode', 6)}{pad('Platform', 15)}"
          f"Description{C_RESET}")
    print("─" * 96)
    for preset in presets:
        colour = C_RED if preset.writes else C_CYAN
        flags = []
        if preset.writes:
            flags.append("WRITE")
        if not preset.verified:
            flags.append("unverified")
        suffix = f"  {C_YELLOW}[{', '.join(flags)}]{C_RESET}" if flags else ""
        print(f"{colour}{pad(preset.name, 20)}{C_RESET}"
              f"{pad(preset.mode, 6)}{pad(preset.platform, 15)}"
              f"{preset.description}{suffix}")


# ---------------------------------------------------------------------------
# Interactive entry point
# ---------------------------------------------------------------------------

def _pick_host() -> tuple[str, dict[str, Any]]:
    """Choose a target from the inventory or by hand. Returns (host, entry)."""
    inventory = load_inventory()
    if inventory:
        print(f"\n{C_CYAN}Inventory:{C_RESET}")
        for name, entry in sorted(inventory.items()):
            print(f"  {name:<24} {entry.get('host', ''):<16} "
                  f"{entry.get('device_type', '')}")

    raw = input("\nDevice name or IP: ").strip()
    if not raw:
        return "", {}

    matches = resolve_targets(raw, inventory, quiet=True)
    if matches:
        name, entry = matches[0]
        if len(matches) > 1:
            print(f"{C_YELLOW}'{raw}' matched {len(matches)} devices; "
                  f"using '{name}'.{C_RESET}")
        return entry["host"], entry
    return raw, {}


def _confirm_write(preset: Preset, host: str, oid: str,
                   value: str, creds: SnmpCredentials) -> bool:
    """Show the write and require an explicit yes."""
    print(f"\n{C_RED}{C_BOLD}About to WRITE to a live device:{C_RESET}")
    print(describe_write(preset, host, oid, value, creds))
    if preset.danger == "high":
        print(f"{C_RED}This can drop traffic. Be sure you have the right "
              f"port.{C_RESET}")
    if not preset.verified:
        print(f"{C_YELLOW}This OID was discovered, not RFC-defined — it has "
              f"not been verified.{C_RESET}")
    try:
        return input(f"\n{C_YELLOW}Type 'yes' to send: {C_RESET}").strip().lower() == "yes"
    except EOFError:
        return False


def _do_preset(store: PresetStore, host: str, entry: dict[str, Any]) -> None:
    """Run a preset interactively."""
    device_type = entry.get("device_type", "")
    print_presets(store.matching(platform=device_type))

    name = input("\nPreset name: ").strip()
    preset = store.get(name)
    if preset is None:
        print(f"{C_RED}No preset called '{name}'.{C_RESET}")
        return

    creds = credentials_for(entry, write=preset.writes)
    problem = creds.validate()
    if problem:
        print(f"{C_RED}{problem}{C_RESET}")
        return

    ifindex = None
    if preset.needs_ifindex:
        port = input("Port name or ifIndex (e.g. 1/1): ").strip()
        if port.isdigit():
            ifindex = port
        else:
            print(f"{C_CYAN}Walking ifName to resolve '{port}' ...{C_RESET}")
            # Reads use the read community even when the operation writes.
            mapping, error = build_ifindex_map(host, credentials_for(entry))
            if not mapping:
                print(f"{C_RED}Could not read the interface table: "
                      f"{error or 'no rows returned'}{C_RESET}")
                return
            ifindex = resolve_ifindex(port, mapping)
            if ifindex is None:
                print(f"{C_RED}'{port}' did not match exactly one interface. "
                      f"Known names: {', '.join(sorted(mapping)[:12])}"
                      f"{' ...' if len(mapping) > 12 else ''}{C_RESET}")
                return
            print(f"{C_GREEN}{port} → ifIndex {ifindex}{C_RESET}")

    value = None
    if preset.needs_value:
        value = input("Value to write: ").strip()

    if preset.writes:
        try:
            oid, resolved = preset.resolve(ifindex=ifindex, value=value)
        except ValueError as exc:
            print(f"{C_RED}{exc}{C_RESET}")
            return
        if not _confirm_write(preset, host, oid, resolved, creds):
            print(f"{C_YELLOW}Cancelled — nothing was sent.{C_RESET}")
            return

    result = run_preset(preset, host, creds, ifindex=ifindex, value=value)
    print_result(result, f"{preset.name} on {host}")
    if result.ok and preset.writes:
        print(f"{C_GREEN}Write accepted by the agent. Verify it took effect "
              f"with a read before you walk away.{C_RESET}")
    if result.ok:
        offer_export(annotate(result.varbinds), f"snmp_{preset.name}")


def _do_manual(host: str, entry: dict[str, Any]) -> None:
    """Ad-hoc GET / WALK / SET without a preset."""
    print("\n  1. GET   — read one OID")
    print("  2. WALK  — read a subtree")
    print("  3. SET   — write one OID")
    choice = input("Choice [1]: ").strip() or "1"
    if choice not in ("1", "2", "3"):
        print(f"{C_RED}Invalid choice.{C_RESET}")
        return

    oid = input("OID (numeric, e.g. 1.3.6.1.2.1.1.5.0): ").strip()
    if not oid:
        print(f"{C_RED}No OID given.{C_RESET}")
        return

    writes = choice == "3"
    creds = credentials_for(entry, write=writes)
    problem = creds.validate()
    if problem:
        print(f"{C_RED}{problem}{C_RESET}")
        return

    if choice == "1":
        print_result(snmp_get(host, [oid], creds), f"GET {oid}")
        return
    if choice == "2":
        print_result(snmp_walk(host, oid, creds), f"WALK {oid}")
        return

    print("\nValue types: "
          + ", ".join(f"{k}={v}" for k, v in SET_TYPE_CODES.items()))
    type_code = input("Type code [s]: ").strip() or "s"
    value     = input("Value: ").strip()

    ad_hoc = Preset(name="manual", description="ad-hoc write", mode="set",
                    oid=oid, value_type=type_code, value=value, danger="high")
    if not _confirm_write(ad_hoc, host, oid, value, creds):
        print(f"{C_YELLOW}Cancelled — nothing was sent.{C_RESET}")
        return
    print_result(run_preset(ad_hoc, host, creds), f"SET {oid}")


def _do_discover(store: PresetStore, host: str, entry: dict[str, Any]) -> None:
    """
    Walk a private-MIB subtree and offer to save what was found as presets.

    This is how a real VOSS OID gets into the library: read it off your own
    switch rather than trusting a value someone guessed.  Anything saved here
    is marked unverified until you confirm what it does.
    """
    print(f"\n{C_BOLD}Discover vendor OIDs{C_RESET}")
    print(f"  1. VOSS / Fabric Engine  (rapidCity {RAPIDCITY_ROOT})")
    print(f"  2. ExtremeXOS            ({EXTREME_ROOT})")
    print("  3. Another subtree")
    choice = input("Choice [1]: ").strip() or "1"
    root = {"1": RAPIDCITY_ROOT, "2": EXTREME_ROOT}.get(choice) or \
        input("Subtree OID: ").strip()
    if not root:
        return

    creds = credentials_for(entry)
    print(f"{C_CYAN}Walking {root} — a full private tree can be large and "
          f"slow.{C_RESET}")
    result = snmp_walk(host, root, creds)
    print_result(result, f"WALK {root}")
    if not result.ok or not result.varbinds:
        return

    rows = annotate(result.varbinds)
    offer_export(rows, "snmp_discovery")

    if input(f"\n{C_YELLOW}Save one of these as a preset? (y/N): "
             f"{C_RESET}").strip().lower() != "y":
        return

    oid = input("OID to save: ").strip()
    if not oid:
        return
    name = input("Preset name: ").strip()
    if not name:
        return
    description = input("What does it do? ").strip()
    mode = input("Mode — get/walk/set [get]: ").strip() or "get"

    preset = Preset(
        name=name, description=description or f"discovered on {host}",
        mode=mode, oid=oid,
        platform=entry.get("device_type", "") or "custom",
        verified=False,
    )
    if mode == "set":
        print("Value types: " + ", ".join(f"{k}={v}" for k, v in SET_TYPE_CODES.items()))
        preset.value_type = input("Type code [i]: ").strip() or "i"
        preset.value = input("Value (or {value} to ask each run) [{value}]: ").strip() \
            or "{value}"
        preset.danger = "high"

    store.add(preset)
    store.save_user_presets()
    print(f"{C_GREEN}Saved '{name}' — marked unverified until you confirm "
          f"what it does.{C_RESET}")


def run_interactive() -> None:
    """Interactive SNMP assistant used by main_menu.py."""
    store = PresetStore.load()

    print(f"{C_BOLD}--- SNMP Assistant ---{C_RESET}")
    print(f"{C_CYAN}Engine: {engine_description()}{C_RESET}")
    if not have_netsnmp():
        print(f"{C_YELLOW}Install the net-snmp tools for SNMPv3 support "
              f"(apt install snmp / brew install net-snmp).{C_RESET}")

    print("\n  1. Run a saved preset")
    print("  2. Manual GET / WALK / SET")
    print("  3. Discover vendor OIDs and save them as presets")
    print("  4. List presets")
    print("  5. Delete a saved preset")
    choice = input("Choice [1]: ").strip() or "1"

    if choice == "4":
        print_presets(store.matching())
        print(f"\n{C_CYAN}Presets file: {SNMP_PRESETS_FILE}{C_RESET}")
        return

    if choice == "5":
        print_presets([p for p in store.matching() if not p.builtin])
        name = input("\nPreset to delete: ").strip()
        if store.remove(name):
            store.save_user_presets()
            print(f"{C_GREEN}Deleted '{name}'.{C_RESET}")
        else:
            print(f"{C_RED}'{name}' is not a saved preset "
                  f"(built-ins cannot be deleted, only overridden).{C_RESET}")
        return

    host, entry = _pick_host()
    if not host:
        print(f"{C_RED}No device given.{C_RESET}")
        return

    if choice == "1":
        _do_preset(store, host, entry)
    elif choice == "2":
        _do_manual(host, entry)
    elif choice == "3":
        _do_discover(store, host, entry)
    else:
        print(f"{C_RED}Invalid choice.{C_RESET}")
