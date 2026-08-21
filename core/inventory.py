"""
core/inventory.py
-----------------
Single source of truth for device authentication profiles and the device
inventory.  Every feature module imports from here so credentials and
device-type mappings are never duplicated.

Usage
-----
    from core.inventory import get_device_profile, INVENTORY

Data flow
---------
    inventory.py  ──►  features/ssh_runner.py      (ConnectHandler kwargs)
                  ──►  features/napalm_interface.py (NAPALM driver selection)
                  ──►  features/rollback.py         (OS-type routing)
"""

from __future__ import annotations

import os
from typing import Any

# ---------------------------------------------------------------------------
# Supported OS types (used as keys throughout the toolkit)
# ---------------------------------------------------------------------------
SUPPORTED_OS = ("cisco_ios", "cisco_xe", "juniper_junos", "extreme_exos")

# ---------------------------------------------------------------------------
# Device Inventory
# ---------------------------------------------------------------------------
# Each entry maps a friendly hostname/IP to its connection profile.
# Fields:
#   host        - resolvable hostname or IP address
#   device_type - Netmiko driver string  (also maps to NAPALM driver below)
#   port        - SSH port (default 22)
#   secret      - enable/privilege secret (Cisco only; leave "" for others)
#
# In production, replace plaintext credentials with a vault lookup
# (e.g. HashiCorp Vault, Ansible Vault, CyberArk) or environment variables.
# ---------------------------------------------------------------------------
INVENTORY: dict[str, dict[str, Any]] = {
    "core-router-01": {
        "host":        "192.168.1.1",
        "device_type": "cisco_ios",
        "port":        22,
        "secret":      os.environ.get("CISCO_ENABLE", ""),
    },
    "dist-xe-01": {
        "host":        "192.168.1.2",
        "device_type": "cisco_xe",
        "port":        22,
        "secret":      os.environ.get("CISCO_ENABLE", ""),
    },
    "edge-junos-01": {
        "host":        "192.168.1.10",
        "device_type": "juniper_junos",
        "port":        22,
        "secret":      "",
    },
    "access-exos-01": {
        "host":        "192.168.1.20",
        "device_type": "extreme_exos",
        "port":        22,
        "secret":      "",
    },
}

# ---------------------------------------------------------------------------
# NAPALM driver mapping  (Netmiko device_type  →  NAPALM driver name)
# ---------------------------------------------------------------------------
NAPALM_DRIVER_MAP: dict[str, str] = {
    "cisco_ios":      "ios",
    "cisco_xe":       "ios",
    "juniper_junos":  "junos",
    "extreme_exos":   "eos",   # NAPALM uses 'eos' for Extreme EOS-based platforms
}

# ---------------------------------------------------------------------------
# Auth credential helpers
# ---------------------------------------------------------------------------

def get_credentials() -> tuple[str, str]:
    """
    Return (username, password) from environment variables.

    Set before running:
        export SYSNET_USER=admin
        export SYSNET_PASS=secret
    """
    username = os.environ.get("SYSNET_USER", "admin")
    password = os.environ.get("SYSNET_PASS", "")
    if not password:
        import getpass
        password = getpass.getpass(f"Password for '{username}': ")
    return username, password


def get_device_profile(hostname_or_ip: str) -> dict[str, Any]:
    """
    Look up a device in INVENTORY by hostname key or by 'host' IP value.

    Returns a Netmiko-compatible dict with 'username' and 'password' injected.
    Raises KeyError if the device is not found.

    Parameters
    ----------
    hostname_or_ip : str
        Either the inventory key (e.g. "core-router-01") or the IP address.
    """
    username, password = get_credentials()

    # Try direct key lookup first
    if hostname_or_ip in INVENTORY:
        profile = dict(INVENTORY[hostname_or_ip])
        profile["username"] = username
        profile["password"] = password
        return profile

    # Fall back to IP-based search
    for _key, profile in INVENTORY.items():
        if profile["host"] == hostname_or_ip:
            result = dict(profile)
            result["username"] = username
            result["password"] = password
            return result

    raise KeyError(
        f"Device '{hostname_or_ip}' not found in inventory. "
        f"Add it to core/inventory.py or pass credentials manually."
    )


def build_ad_hoc_profile(
    host: str,
    device_type: str,
    username: str,
    password: str,
    port: int = 22,
    secret: str = "",
) -> dict[str, Any]:
    """
    Build a one-off Netmiko connection profile without touching INVENTORY.
    Used by the interactive CLI when an operator supplies devices at runtime.
    """
    if device_type not in SUPPORTED_OS:
        raise ValueError(
            f"Unsupported device_type '{device_type}'. "
            f"Choose from: {SUPPORTED_OS}"
        )
    return {
        "host":        host,
        "device_type": device_type,
        "port":        port,
        "username":    username,
        "password":    password,
        "secret":      secret,
        "timeout":     15,
        "session_log": None,  # populated by ssh_runner when audit logging is on
    }
