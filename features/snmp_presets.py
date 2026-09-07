"""
features/snmp_presets.py
------------------------
The saved-operation library behind the SNMP assistant.

A preset is a named SNMP operation you do not want to retype under pressure:
"read every port's admin state", "set the description on port 1/1", "bring
port 1/47 back up". They are the whole point of the assistant — at 02:00,
nobody remembers that ifAdminStatus is 1.3.6.1.2.1.2.2.1.7.

Where the OIDs come from
------------------------
Every built-in preset uses a **standard MIB** OID (MIB-2, IF-MIB, ENTITY-MIB,
LLDP-MIB, BRIDGE-MIB). Those are RFC-defined, identical on every vendor, and
verifiable against any device — so they are safe to ship.

There are deliberately **no built-in Extreme/VOSS presets**. VOSS private
objects live under rapidCity (``1.3.6.1.4.1.2272``), but the specific leaf
OIDs are not something to guess: a wrong OID in a break-glass preset is worse
than no preset, because you would be trusting it at exactly the moment you
cannot verify it. Use the assistant's discovery helper to walk that subtree on
your own switch and save what you actually find — a discovered preset is
stored with ``verified: false`` until you say otherwise.

The good news is that the recovery case does not need a private OID:
**ifAdminStatus is writable over standard SNMP**, so bouncing a port works on
any agent that permits writes.

Storage
-------
Built-ins live in this file. User presets live in ``snmp_presets.json`` and
are merged over them, so you can override a built-in by reusing its name and
your edits survive an upgrade.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from core.colors import C_RED, C_RESET, C_YELLOW
from core.paths import SNMP_PRESETS_FILE

# Placeholders a preset may contain, substituted before the request is sent.
PLACEHOLDER_IFINDEX = "{ifindex}"
PLACEHOLDER_VALUE   = "{value}"

# The VOSS / Fabric Engine private MIB root (ex-Nortel/Avaya "rapidCity").
# Shipped as a *starting point for discovery*, not as a preset.
RAPIDCITY_ROOT = "1.3.6.1.4.1.2272"
EXTREME_ROOT   = "1.3.6.1.4.1.1916"      # ExtremeXOS / EXOS-native gear


@dataclass
class Preset:
    """One named SNMP operation."""
    name:        str
    description: str
    mode:        str = "get"      # "get" | "walk" | "set"
    oid:         str = ""
    value_type:  str = ""         # SET only: net-snmp type code (i/u/s/x/a/o/t)
    value:       str = ""         # SET only; may be {value}
    platform:    str = "standard"
    danger:      str = ""         # "" | "low" | "high"
    verified:    bool = True      # False once discovered rather than RFC-defined
    builtin:     bool = False

    @property
    def writes(self) -> bool:
        return self.mode == "set"

    @property
    def needs_ifindex(self) -> bool:
        return PLACEHOLDER_IFINDEX in self.oid

    @property
    def needs_value(self) -> bool:
        return PLACEHOLDER_VALUE in self.value

    def resolve(self, ifindex: str | int | None = None,
                value: str | None = None) -> tuple[str, str]:
        """
        Substitute placeholders and return the (oid, value) actually sent.

        Raises ValueError when a placeholder has nothing to fill it, rather
        than sending a literal '{ifindex}' to the agent.
        """
        oid = self.oid
        if self.needs_ifindex:
            if ifindex in (None, ""):
                raise ValueError(
                    f"preset '{self.name}' needs an interface — pass a port "
                    f"name or an ifIndex")
            oid = oid.replace(PLACEHOLDER_IFINDEX, str(ifindex))

        out_value = self.value
        if self.needs_value:
            if value in (None, ""):
                raise ValueError(f"preset '{self.name}' needs a value")
            out_value = out_value.replace(PLACEHOLDER_VALUE, str(value))
        return oid, out_value

    def as_row(self) -> dict[str, Any]:
        return {
            "name":        self.name,
            "mode":        self.mode,
            "oid":         self.oid,
            "platform":    self.platform,
            "writes":      "yes" if self.writes else "no",
            "verified":    "yes" if self.verified else "NO",
            "description": self.description,
        }


def _p(**kwargs: Any) -> Preset:
    return Preset(builtin=True, **kwargs)


# ---------------------------------------------------------------------------
# Built-in presets — standard MIBs only
# ---------------------------------------------------------------------------

BUILTIN_PRESETS: list[Preset] = [
    # --- System (MIB-2 system group, RFC 1213) ---
    _p(name="sysdescr", mode="get", oid="1.3.6.1.2.1.1.1.0",
       description="System description — model and firmware version"),
    _p(name="sysobjectid", mode="get", oid="1.3.6.1.2.1.1.2.0",
       description="Vendor object ID; identifies the platform family"),
    _p(name="sysuptime", mode="get", oid="1.3.6.1.2.1.1.3.0",
       description="Time since the agent restarted, in hundredths of a second"),
    _p(name="syscontact", mode="get", oid="1.3.6.1.2.1.1.4.0",
       description="Configured contact string"),
    _p(name="sysname", mode="get", oid="1.3.6.1.2.1.1.5.0",
       description="System name — the device's own hostname"),
    _p(name="syslocation", mode="get", oid="1.3.6.1.2.1.1.6.0",
       description="Configured location string"),

    # --- Interfaces (IF-MIB, RFC 2863) ---
    _p(name="if-names", mode="walk", oid="1.3.6.1.2.1.31.1.1.1.1",
       description="ifName for every interface — the port-name to ifIndex map"),
    _p(name="if-descr", mode="walk", oid="1.3.6.1.2.1.2.2.1.2",
       description="ifDescr for every interface (fallback when ifName is empty)"),
    _p(name="if-alias", mode="walk", oid="1.3.6.1.2.1.31.1.1.1.18",
       description="Port descriptions as configured by an operator"),
    _p(name="if-admin-status", mode="walk", oid="1.3.6.1.2.1.2.2.1.7",
       description="Admin state per port (1=up, 2=down) — is it shut?"),
    _p(name="if-oper-status", mode="walk", oid="1.3.6.1.2.1.2.2.1.8",
       description="Link state per port (1=up, 2=down) — is it actually up?"),
    _p(name="if-speed", mode="walk", oid="1.3.6.1.2.1.31.1.1.1.15",
       description="Negotiated port speed in Mbit/s"),
    _p(name="if-in-octets", mode="walk", oid="1.3.6.1.2.1.31.1.1.1.6",
       description="64-bit inbound byte counters (for utilisation deltas)"),
    _p(name="if-out-octets", mode="walk", oid="1.3.6.1.2.1.31.1.1.1.10",
       description="64-bit outbound byte counters"),
    _p(name="if-in-errors", mode="walk", oid="1.3.6.1.2.1.2.2.1.14",
       description="Inbound error counters — the CRC/FCS hunt"),
    _p(name="if-out-errors", mode="walk", oid="1.3.6.1.2.1.2.2.1.20",
       description="Outbound error counters"),

    # --- Neighbours and addresses ---
    _p(name="lldp-neighbours", mode="walk", oid="1.0.8802.1.1.2.1.4.1.1.9",
       description="LLDP remote system names — who is on each port"),
    _p(name="lldp-remote-port", mode="walk", oid="1.0.8802.1.1.2.1.4.1.1.7",
       description="LLDP remote port IDs"),
    _p(name="ip-addresses", mode="walk", oid="1.3.6.1.2.1.4.20.1.1",
       description="IPv4 addresses configured on the device"),
    _p(name="fdb-ports", mode="walk", oid="1.3.6.1.2.1.17.4.3.1.2",
       description="Bridge forwarding table: learned MAC to bridge port"),

    # --- Inventory (ENTITY-MIB, RFC 4133) ---
    _p(name="entity-descr", mode="walk", oid="1.3.6.1.2.1.47.1.1.1.1.2",
       description="Physical entity descriptions — chassis, slots, optics"),
    _p(name="entity-serial", mode="walk", oid="1.3.6.1.2.1.47.1.1.1.1.11",
       description="Serial numbers of every physical entity"),

    # --- Writes ---------------------------------------------------------
    # ifAdminStatus is writable in the standard IF-MIB, which is what makes
    # port recovery possible without a single vendor-private OID.
    _p(name="port-up", mode="set", oid="1.3.6.1.2.1.2.2.1.7.{ifindex}",
       value_type="i", value="1", danger="high",
       description="Bring a port up (ifAdminStatus=up). The break-glass one."),
    _p(name="port-down", mode="set", oid="1.3.6.1.2.1.2.2.1.7.{ifindex}",
       value_type="i", value="2", danger="high",
       description="Shut a port (ifAdminStatus=down). Will drop traffic."),
    _p(name="set-ifalias", mode="set", oid="1.3.6.1.2.1.31.1.1.1.18.{ifindex}",
       value_type="s", value="{value}", danger="low",
       description="Set a port's description"),
    _p(name="set-sysname", mode="set", oid="1.3.6.1.2.1.1.5.0",
       value_type="s", value="{value}", danger="low",
       description="Set the device hostname"),
    _p(name="set-syslocation", mode="set", oid="1.3.6.1.2.1.1.6.0",
       value_type="s", value="{value}", danger="low",
       description="Set the device location string"),
    _p(name="set-syscontact", mode="set", oid="1.3.6.1.2.1.1.4.0",
       value_type="s", value="{value}", danger="low",
       description="Set the device contact string"),

    # --- Discovery starting points --------------------------------------
    _p(name="discover-voss", mode="walk", oid=RAPIDCITY_ROOT,
       platform="extreme_vsp",
       description="Walk the whole VOSS rapidCity private tree "
                   "(large — use to find and pin real vendor OIDs)"),
    _p(name="discover-exos", mode="walk", oid=EXTREME_ROOT,
       platform="extreme_exos",
       description="Walk the whole ExtremeXOS private tree"),
]


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

@dataclass
class PresetStore:
    """Built-in presets merged with the user's, keyed by name."""
    presets: dict[str, Preset] = field(default_factory=dict)

    @classmethod
    def load(cls, path=None) -> PresetStore:
        """
        Load built-ins, then merge the user's file over them.

        A user preset reusing a built-in name replaces it, so a corrected OID
        survives an upgrade of this file.
        """
        store = cls({p.name: p for p in BUILTIN_PRESETS})

        preset_path = path or SNMP_PRESETS_FILE
        try:
            with open(preset_path) as handle:
                raw = json.load(handle)
        except FileNotFoundError:
            return store
        except (json.JSONDecodeError, OSError) as exc:
            print(f"{C_RED}Could not read {preset_path}: {exc}{C_RESET}")
            print(f"{C_YELLOW}Using the built-in presets only.{C_RESET}")
            return store

        entries = raw.get("presets", raw) if isinstance(raw, dict) else raw
        if not isinstance(entries, list):
            print(f"{C_RED}{preset_path} must hold a list of presets.{C_RESET}")
            return store

        known = {f.name for f in Preset.__dataclass_fields__.values()}
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            fields = {k: v for k, v in entry.items() if k in known}
            fields["builtin"] = False
            try:
                preset = Preset(**fields)
            except TypeError as exc:
                print(f"{C_YELLOW}Skipping preset "
                      f"{entry.get('name')!r}: {exc}{C_RESET}")
                continue
            store.presets[preset.name] = preset
        return store

    def save_user_presets(self, path=None) -> None:
        """Write every non-built-in preset back to the JSON store."""
        preset_path = path or SNMP_PRESETS_FILE
        user = [asdict(p) for p in self.presets.values() if not p.builtin]
        for entry in user:
            entry.pop("builtin", None)
        payload = {
            "_comment": "SNMP presets for the toolkit. Built-ins live in "
                        "features/snmp_presets.py; reusing a built-in name "
                        "here overrides it. 'verified: false' marks an OID "
                        "discovered from a device rather than an RFC.",
            "presets": user,
        }
        with open(preset_path, "w") as handle:
            json.dump(payload, handle, indent=2)

    def add(self, preset: Preset) -> None:
        preset.builtin = False
        self.presets[preset.name] = preset

    def remove(self, name: str) -> bool:
        """Delete a user preset. Built-ins cannot be removed, only overridden."""
        preset = self.presets.get(name)
        if preset is None or preset.builtin:
            return False
        del self.presets[name]
        return True

    def get(self, name: str) -> Preset | None:
        return self.presets.get(name)

    def matching(self, mode: str = "", platform: str = "",
                 writes_only: bool = False) -> list[Preset]:
        """Filtered, name-sorted view for the listings."""
        found = sorted(self.presets.values(), key=lambda p: (p.mode, p.name))
        if mode:
            found = [p for p in found if p.mode == mode]
        if platform:
            found = [p for p in found if p.platform in (platform, "standard")]
        if writes_only:
            found = [p for p in found if p.writes]
        return found
