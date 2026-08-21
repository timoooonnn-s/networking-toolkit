"""
core/inventory.py
-----------------
Single source of truth for device authentication profiles and the device
inventory.  Every feature module imports from here so credentials and
device-type mappings are never duplicated.

Usage
-----
    from core.inventory import get_device_profile, load_inventory, resolve_targets

Data flow
---------
    inventory.json ──►  load_inventory()
    inventory.py   ──►  features/ssh_runner.py       (ConnectHandler kwargs)
                   ──►  features/napalm_interface.py (NAPALM driver selection)
                   ──►  features/rollback.py         (OS-type routing)
                   ──►  features/backup.py           (fan-out targets)

Inventory file
--------------
The built-in INVENTORY below is an example.  A real inventory lives in
``inventory.json`` at the project root (override with $SYSNET_INVENTORY):

    {
      "core-router-01": {
        "host": "192.168.1.1",
        "device_type": "cisco_ios",
        "port": 22,
        "secret_env": "CISCO_ENABLE",
        "tags": ["core", "site-a"]
      }
    }

``secret_env`` names an environment variable holding the enable secret — the
file itself never has to contain one.  ``tags`` let a tool address a group of
devices ("backup every device tagged 'core'") instead of listing hosts.
"""

from __future__ import annotations

import json
import os
from typing import Any

from core.colors import C_RED, C_RESET, C_YELLOW
from core.paths import INVENTORY_FILE

# ---------------------------------------------------------------------------
# Supported OS types (used as keys throughout the toolkit)
# ---------------------------------------------------------------------------
# These are Netmiko driver strings.  extreme_vsp (VOSS / Fabric Engine) and
# extreme_ers (BOSS stackables) are first-class here because the toolkit's
# validator and backup features target them directly.
SUPPORTED_OS = (
    "cisco_ios",
    "cisco_xe",
    "juniper_junos",
    "extreme_exos",
    "extreme_vsp",
    "extreme_ers",
)

# Device types whose privileged mode is reached with a plain `enable` and no
# separate secret.  Juniper never enters an enable mode at all — sending
# `enable` to Junos raises in Netmiko because the prompt never becomes '#'.
NO_ENABLE_MODE = ("juniper_junos",)

# Device types that prompt for a separate enable secret.
NEEDS_ENABLE_SECRET = ("cisco_ios", "cisco_xe")

# ---------------------------------------------------------------------------
# Paging-disable commands, per device type
# ---------------------------------------------------------------------------
# One tuple per platform: the primary spelling first, then field-verified
# fallbacks.  A live pager stalls long output at --More-- *and* swallows the
# next command's characters, so one missed paging command corrupts the rest
# of the session rather than just one output.
PAGING_DISABLE: dict[str, tuple[str, ...]] = {
    "cisco_ios":     ("terminal length 0",),
    "cisco_xe":      ("terminal length 0",),
    "juniper_junos": ("set cli screen-length 0",),
    "extreme_exos":  ("disable clipaging",),
    "extreme_vsp":   ("terminal more disable", "term more dis"),
    "extreme_ers":   ("terminal length 0",),
}

# ---------------------------------------------------------------------------
# Example device inventory (overridden by inventory.json when present)
# ---------------------------------------------------------------------------
INVENTORY: dict[str, dict[str, Any]] = {
    "core-router-01": {
        "host":        "192.168.1.1",
        "device_type": "cisco_ios",
        "port":        22,
        "secret":      os.environ.get("CISCO_ENABLE", ""),
        "tags":        ["core"],
    },
    "dist-xe-01": {
        "host":        "192.168.1.2",
        "device_type": "cisco_xe",
        "port":        22,
        "secret":      os.environ.get("CISCO_ENABLE", ""),
        "tags":        ["distribution"],
    },
    "edge-junos-01": {
        "host":        "192.168.1.10",
        "device_type": "juniper_junos",
        "port":        22,
        "secret":      "",
        "tags":        ["edge"],
    },
    "access-exos-01": {
        "host":        "192.168.1.20",
        "device_type": "extreme_exos",
        "port":        22,
        "secret":      "",
        "tags":        ["access"],
    },
}

# ---------------------------------------------------------------------------
# NAPALM driver mapping  (Netmiko device_type  →  NAPALM driver name)
# ---------------------------------------------------------------------------
# Only platforms with a real, maintained NAPALM driver appear here.
NAPALM_DRIVER_MAP: dict[str, str] = {
    "cisco_ios":     "ios",
    "cisco_xe":      "ios",
    "juniper_junos": "junos",
}

# Platforms deliberately absent from NAPALM_DRIVER_MAP, with the reason shown
# to the operator.  extreme_exos used to be mapped to NAPALM's 'eos' driver,
# which is *Arista* EOS over pyeapi/eAPI — it can never talk to Extreme gear,
# so every NAPALM feature against those devices failed by design.  Use the
# SSH-based tools (bulk runner, backup, validator) for these instead.
NAPALM_UNSUPPORTED: dict[str, str] = {
    "extreme_exos": "NAPALM has no maintained ExtremeXOS driver",
    "extreme_vsp":  "NAPALM has no VOSS / Fabric Engine driver",
    "extreme_ers":  "NAPALM has no ERS / BOSS driver",
}


def napalm_driver_for(device_type: str) -> str:
    """
    Return the NAPALM driver name for *device_type*.

    Raises ValueError with an actionable message for platforms NAPALM cannot
    reach, rather than routing them to a driver for a different vendor.
    """
    if device_type in NAPALM_DRIVER_MAP:
        return NAPALM_DRIVER_MAP[device_type]
    if device_type in NAPALM_UNSUPPORTED:
        raise ValueError(
            f"'{device_type}' is not supported by NAPALM "
            f"({NAPALM_UNSUPPORTED[device_type]}). "
            f"Use the SSH-based tools (bulk runner / backup / validator) instead."
        )
    raise ValueError(
        f"No NAPALM driver mapping for '{device_type}'. "
        f"Supported: {', '.join(sorted(NAPALM_DRIVER_MAP))}"
    )


# ---------------------------------------------------------------------------
# Inventory file loading
# ---------------------------------------------------------------------------

def load_inventory(path=None) -> dict[str, dict[str, Any]]:
    """
    Return the device inventory, preferring ``inventory.json`` on disk and
    falling back to the built-in example INVENTORY.

    A malformed or unreadable file is reported and the built-in inventory is
    used, so a typo in the JSON never leaves a tool silently addressing zero
    devices.
    """
    inv_path = path or INVENTORY_FILE
    if not os.path.exists(inv_path):
        return {name: dict(profile) for name, profile in INVENTORY.items()}

    try:
        with open(inv_path) as handle:
            raw = json.load(handle)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"{C_RED}Could not read inventory {inv_path}: {exc}{C_RESET}")
        print(f"{C_YELLOW}Falling back to the built-in example inventory.{C_RESET}")
        return {name: dict(profile) for name, profile in INVENTORY.items()}

    if not isinstance(raw, dict):
        print(f"{C_RED}Inventory {inv_path} must be a JSON object of "
              f"name -> profile.{C_RESET}")
        return {}

    inventory: dict[str, dict[str, Any]] = {}
    for name, profile in raw.items():
        # JSON has no comments; a leading underscore is the usual stand-in,
        # so those keys are skipped silently rather than warned about.
        if name.startswith("_"):
            continue
        if not isinstance(profile, dict) or "host" not in profile:
            print(f"{C_YELLOW}Skipping inventory entry '{name}': "
                  f"missing 'host'.{C_RESET}")
            continue
        entry = dict(profile)
        entry.setdefault("device_type", "cisco_ios")
        entry.setdefault("port", 22)
        entry.setdefault("tags", [])
        # secret_env keeps the actual secret out of the inventory file
        if "secret_env" in entry:
            entry["secret"] = os.environ.get(entry.pop("secret_env"), "")
        entry.setdefault("secret", "")
        inventory[name] = entry
    return inventory


def resolve_targets(
    selector: str,
    inventory: dict[str, dict[str, Any]] | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    """
    Turn an operator-supplied *selector* into a list of (name, profile) pairs.

    Accepted forms, comma-separated and mixable:
        all                 every device in the inventory
        tag:core            every device carrying the tag 'core'
        core-router-01      an inventory key
        192.168.1.1         an inventory entry's host value

    Unknown entries are reported and skipped, so a typo costs one device
    rather than the whole run.
    """
    inv = inventory if inventory is not None else load_inventory()
    selected: dict[str, dict[str, Any]] = {}

    for token in (t.strip() for t in selector.split(",")):
        if not token:
            continue

        if token.lower() == "all":
            selected.update(inv)
            continue

        if token.lower().startswith("tag:"):
            tag = token[4:].strip().lower()
            matches = {
                name: profile for name, profile in inv.items()
                if tag in [str(t).lower() for t in profile.get("tags", [])]
            }
            if not matches:
                print(f"{C_YELLOW}No inventory device carries tag '{tag}'.{C_RESET}")
            selected.update(matches)
            continue

        if token in inv:
            selected[token] = inv[token]
            continue

        by_host = {
            name: profile for name, profile in inv.items()
            if profile.get("host") == token
        }
        if by_host:
            selected.update(by_host)
        else:
            print(f"{C_YELLOW}'{token}' is not in the inventory — skipped.{C_RESET}")

    return sorted(selected.items())


# ---------------------------------------------------------------------------
# Auth credential helpers
# ---------------------------------------------------------------------------

# Cached for the lifetime of the process: a fan-out across 40 devices used to
# prompt for the same password 40 times.
_CREDENTIAL_CACHE: dict[str, tuple[str, str]] = {}


def get_credentials(
    username: str | None = None,
    prompt: bool = True,
    force: bool = False,
) -> tuple[str, str]:
    """
    Return (username, password), resolved in this order:

      1. the *username* argument, or $SYSNET_USER, or 'admin'
      2. $SYSNET_PASS
      3. an interactive getpass prompt (skipped when prompt=False)

    The result is cached per username for the rest of the session; pass
    force=True to re-prompt (e.g. after an authentication failure).

    Set before running to avoid the prompt entirely:
        export SYSNET_USER=admin
        export SYSNET_PASS=secret
    """
    user = username or os.environ.get("SYSNET_USER", "admin")

    if not force and user in _CREDENTIAL_CACHE:
        return _CREDENTIAL_CACHE[user]

    password = os.environ.get("SYSNET_PASS", "")
    if not password and prompt:
        import getpass
        password = getpass.getpass(f"Password for '{user}': ")

    _CREDENTIAL_CACHE[user] = (user, password)
    return user, password


def clear_credential_cache() -> None:
    """Forget every cached credential (used after an auth failure)."""
    _CREDENTIAL_CACHE.clear()


def get_device_profile(
    hostname_or_ip: str,
    inventory: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Look up a device in the inventory by name or by 'host' value and return a
    Netmiko-compatible dict with 'username' and 'password' injected.

    Raises KeyError if the device is not found.
    """
    inv = inventory if inventory is not None else load_inventory()
    username, password = get_credentials()

    profile = inv.get(hostname_or_ip)
    if profile is None:
        profile = next(
            (p for p in inv.values() if p.get("host") == hostname_or_ip),
            None,
        )
    if profile is None:
        raise KeyError(
            f"Device '{hostname_or_ip}' not found in inventory. "
            f"Add it to inventory.json or pass credentials manually."
        )

    return build_ad_hoc_profile(
        host=profile["host"],
        device_type=profile.get("device_type", "cisco_ios"),
        username=username,
        password=password,
        port=int(profile.get("port", 22)),
        secret=profile.get("secret", ""),
    )


def build_ad_hoc_profile(
    host: str,
    device_type: str,
    username: str,
    password: str,
    port: int = 22,
    secret: str = "",
    timeout: int = 20,
) -> dict[str, Any]:
    """
    Build a one-off Netmiko connection profile without touching the inventory.
    Used by the interactive CLI when an operator supplies devices at runtime.

    Every key returned is one Netmiko accepts, so the dict can be passed
    straight to ConnectHandler(**profile).
    """
    if device_type not in SUPPORTED_OS:
        raise ValueError(
            f"Unsupported device_type '{device_type}'. "
            f"Choose from: {', '.join(SUPPORTED_OS)}"
        )
    return {
        "host":         host,
        "device_type":  device_type,
        "port":         int(port),
        "username":     username,
        "password":     password,
        "secret":       secret,
        "conn_timeout": timeout,
        # fast_cli off: old ERS/BOSS gear chokes on Netmiko's fast path.
        "fast_cli":     False,
    }
