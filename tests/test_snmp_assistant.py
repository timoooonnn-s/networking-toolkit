"""
SNMP assistant tests: presets, ifIndex resolution, credentials, write safety.

Nothing here touches a device.  The preset library and the ifIndex resolver
are pure, and the credential resolution is environment-driven by design.
"""

from __future__ import annotations

import json

import pytest

from core.snmp import SnmpCredentials
from features.snmp_assistant import (
    annotate,
    build_ifindex_map,
    credentials_for,
    describe_write,
    resolve_ifindex,
    run_preset,
)
from features.snmp_presets import BUILTIN_PRESETS, Preset, PresetStore
from tests.fake_agent import FakeAgent, integer, octet_string

# ---------------------------------------------------------------------------
# The preset library
# ---------------------------------------------------------------------------

def test_no_builtin_preset_ships_a_guessed_vendor_oid():
    # Every built-in must be a standard MIB OID.  A wrong vendor OID in a
    # break-glass preset is worse than no preset: you would trust it at
    # exactly the moment you cannot verify it.
    enterprise = "1.3.6.1.4.1."
    for preset in BUILTIN_PRESETS:
        if not preset.oid.startswith(enterprise):
            continue
        # The only enterprise OIDs allowed are the bare discovery roots.
        assert preset.name.startswith("discover-"), \
            f"{preset.name} ships a guessed vendor OID: {preset.oid}"
        assert preset.mode == "walk"
        assert not preset.writes


def test_every_builtin_write_uses_a_standard_writable_object():
    writable = (
        "1.3.6.1.2.1.1.4.0",              # sysContact
        "1.3.6.1.2.1.1.5.0",              # sysName
        "1.3.6.1.2.1.1.6.0",              # sysLocation
        "1.3.6.1.2.1.2.2.1.7.",           # ifAdminStatus
        "1.3.6.1.2.1.31.1.1.1.18.",       # ifAlias
    )
    for preset in BUILTIN_PRESETS:
        if preset.writes:
            assert preset.oid.startswith(writable), preset.name


def test_port_up_is_ifadminstatus_up():
    store = PresetStore.load("/nonexistent.json")
    oid, value = store.get("port-up").resolve(ifindex=192)
    assert oid == "1.3.6.1.2.1.2.2.1.7.192"
    assert value == "1"                    # 1 == up in the IF-MIB


def test_port_down_is_marked_dangerous():
    store = PresetStore.load("/nonexistent.json")
    assert store.get("port-down").danger == "high"
    assert store.get("port-down").writes


def test_a_placeholder_with_nothing_to_fill_it_raises(caplog):
    store = PresetStore.load("/nonexistent.json")
    with pytest.raises(ValueError, match="needs an interface"):
        store.get("port-up").resolve()
    with pytest.raises(ValueError, match="needs a value"):
        store.get("set-sysname").resolve()


def test_a_user_preset_overrides_a_builtin_of_the_same_name(tmp_path):
    path = tmp_path / "snmp_presets.json"
    path.write_text(json.dumps({"presets": [
        {"name": "sysname", "description": "corrected", "mode": "get",
         "oid": "1.2.3.4.0"},
    ]}))
    store = PresetStore.load(path)
    assert store.get("sysname").oid == "1.2.3.4.0"
    assert store.get("sysname").builtin is False
    # the rest of the built-ins survive
    assert store.get("port-up") is not None


def test_a_broken_preset_file_falls_back_to_the_builtins(tmp_path, capsys):
    path = tmp_path / "snmp_presets.json"
    path.write_text("{not json")
    store = PresetStore.load(path)
    assert store.get("sysname") is not None
    assert "Could not read" in capsys.readouterr().out


def test_a_preset_entry_missing_a_name_is_skipped(tmp_path):
    path = tmp_path / "snmp_presets.json"
    path.write_text(json.dumps({"presets": [{"oid": "1.2.3", "mode": "get"}]}))
    assert PresetStore.load(path).get("") is None


def test_user_presets_round_trip_through_disk(tmp_path):
    path = tmp_path / "snmp_presets.json"
    store = PresetStore.load(path)
    store.add(Preset(name="voss-ssh", description="found on a real box",
                     mode="get", oid="1.3.6.1.4.1.2272.1.99.1.0",
                     platform="extreme_vsp", verified=False))
    store.save_user_presets(path)

    reloaded = PresetStore.load(path)
    saved = reloaded.get("voss-ssh")
    assert saved.oid == "1.3.6.1.4.1.2272.1.99.1.0"
    assert saved.verified is False          # discovered, not RFC-defined
    assert saved.builtin is False


def test_builtins_cannot_be_deleted_only_overridden():
    store = PresetStore.load("/nonexistent.json")
    assert store.remove("sysname") is False
    assert store.get("sysname") is not None


# ---------------------------------------------------------------------------
# ifIndex resolution
# ---------------------------------------------------------------------------

@pytest.fixture
def port_map():
    # The numbers are from a real VOSS box: 1/1 is 192, not 1.
    return {"Port1/1": "192", "Port1/2": "193", "Port2/1/1": "400",
            "Port11/1": "500", "Mgmt": "1"}


def test_a_port_name_resolves_to_its_ifindex(port_map):
    assert resolve_ifindex("1/1", port_map) == "192"
    assert resolve_ifindex("2/1/1", port_map) == "400"


def test_a_suffix_match_cannot_be_captured_by_a_longer_port(port_map):
    # '1/1' must not silently resolve to Port11/1 — that would shut the
    # wrong port.
    assert resolve_ifindex("1/1", port_map) == "192"
    assert resolve_ifindex("11/1", port_map) == "500"


def test_an_exact_name_wins(port_map):
    assert resolve_ifindex("Port1/2", port_map) == "193"
    assert resolve_ifindex("Mgmt", port_map) == "1"


def test_a_bare_number_is_taken_as_an_ifindex(port_map):
    assert resolve_ifindex("192", port_map) == "192"


def test_an_unknown_port_resolves_to_nothing_rather_than_a_guess(port_map):
    assert resolve_ifindex("1/99", port_map) is None
    assert resolve_ifindex("", port_map) is None


def test_an_ambiguous_name_resolves_to_nothing(port_map):
    ambiguous = {"eth1/1": "10", "swp1/1": "20"}
    assert resolve_ifindex("1/1", ambiguous) is None


def test_the_ifindex_map_is_walked_from_the_device():
    table = {
        "1.3.6.1.2.1.31.1.1.1.1.192": octet_string("Port1/1"),
        "1.3.6.1.2.1.31.1.1.1.1.400": octet_string("Port2/1/1"),
    }
    with FakeAgent(table) as agent:
        creds = SnmpCredentials(version="2c", community="public",
                                port=agent.port, timeout_s=2)
        mapping, error = build_ifindex_map("127.0.0.1", creds)

    assert error == ""
    assert mapping == {"Port1/1": "192", "Port2/1/1": "400"}
    assert resolve_ifindex("1/1", mapping) == "192"


def test_an_empty_ifname_table_falls_back_to_ifdescr():
    # Some agents populate only ifDescr.
    table = {"1.3.6.1.2.1.2.2.1.2.7": octet_string("GigabitEthernet0/7")}
    with FakeAgent(table) as agent:
        creds = SnmpCredentials(version="2c", community="public",
                                port=agent.port, timeout_s=2)
        mapping, _ = build_ifindex_map("127.0.0.1", creds)
    assert mapping == {"GigabitEthernet0/7": "7"}


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def test_read_and_write_communities_are_separate(monkeypatch):
    monkeypatch.setenv("SNMP_COMMUNITY", "public")
    monkeypatch.setenv("SNMP_WRITE_COMMUNITY", "private")
    assert credentials_for(prompt=False).community == "public"
    assert credentials_for(write=True, prompt=False).community == "private"


def test_the_inventory_names_an_env_var_never_the_secret(monkeypatch):
    monkeypatch.setenv("SITE_A_RO", "site-a-community")
    entry = {"snmp_community_env": "SITE_A_RO"}
    assert credentials_for(entry, prompt=False).community == "site-a-community"


def test_a_v3_inventory_entry_builds_v3_credentials(monkeypatch):
    monkeypatch.setenv("VOSS_AUTH", "authpass")
    monkeypatch.setenv("VOSS_PRIV", "privpass")
    entry = {
        "snmp_version": "3", "snmp_v3_user": "netops",
        "snmp_v3_auth_protocol": "SHA-256", "snmp_v3_priv_protocol": "AES",
        "snmp_v3_auth_key_env": "VOSS_AUTH", "snmp_v3_priv_key_env": "VOSS_PRIV",
    }
    creds = credentials_for(entry, prompt=False)
    assert creds.version == "3"
    assert creds.user == "netops"
    assert creds.security_level == "authPriv"
    assert creds.auth_protocol == "SHA-256"
    assert creds.validate() == ""


def test_a_non_interactive_run_does_not_prompt(monkeypatch):
    monkeypatch.delenv("SNMP_COMMUNITY", raising=False)
    monkeypatch.setattr("builtins.input",
                        lambda *_: pytest.fail("prompted with prompt=False"))
    creds = credentials_for(prompt=False)
    assert creds.community == ""
    assert "community" in creds.validate()


# ---------------------------------------------------------------------------
# Writes and presentation
# ---------------------------------------------------------------------------

def test_the_write_description_shows_the_oid_but_not_the_community():
    store = PresetStore.load("/nonexistent.json")
    preset = store.get("port-down")
    creds = SnmpCredentials(version="2c", community="s3cret")
    text = describe_write(preset, "10.0.0.1", "1.3.6.1.2.1.2.2.1.7.192", "2", creds)

    assert "1.3.6.1.2.1.2.2.1.7.192" in text
    assert "10.0.0.1" in text
    assert "s3cret" not in text


def test_running_a_write_preset_applies_it(tmp_path):
    store = PresetStore.load("/nonexistent.json")
    with FakeAgent({"1.3.6.1.2.1.2.2.1.7.192": integer(2)}) as agent:
        creds = SnmpCredentials(version="2c", community="private",
                                port=agent.port, timeout_s=2)
        result = run_preset(store.get("port-up"), "127.0.0.1", creds,
                            ifindex="192", audit=False)
        assert result.ok, result.error
        assert agent.table["1.3.6.1.2.1.2.2.1.7.192"][1] == b"\x01"


def test_a_write_against_a_read_only_agent_fails_clearly():
    store = PresetStore.load("/nonexistent.json")
    with FakeAgent({}, error_status=17) as agent:
        creds = SnmpCredentials(version="2c", community="public",
                                port=agent.port, timeout_s=2)
        result = run_preset(store.get("port-up"), "127.0.0.1", creds,
                            ifindex="192", audit=False)
    assert not result.ok
    assert "notWritable" in result.error


def test_status_enums_are_spelled_out_for_the_operator():
    from core.snmp import VarBind

    rows = annotate([
        VarBind(".1.3.6.1.2.1.2.2.1.7.192", "INTEGER", 2),
        VarBind(".1.3.6.1.2.1.2.2.1.8.192", "INTEGER", 7),
        VarBind(".1.3.6.1.2.1.1.5.0", "STRING", "core-01"),
    ])
    assert rows[0]["value"] == "2 (down)"
    assert rows[1]["value"] == "7 (lowerLayerDown)"
    assert rows[2]["value"] == "core-01"      # untouched
