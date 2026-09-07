"""
Core-layer tests: error detection, audit logging, inventory, export, colours.

Each of these pins a bug that was live in the toolkit, so a regression shows
up as a failing test rather than as a wrong answer in a change window.
"""

from __future__ import annotations

import json

import pytest

from core.audit_logger import AuditLogger
from core.colors import C_GREEN, C_RESET, pad, strip_ansi, visible_len
from core.connection import command_slug, looks_like_error
from core.export import export_rows
from core.inventory import (
    NAPALM_DRIVER_MAP,
    SUPPORTED_OS,
    build_ad_hoc_profile,
    load_inventory,
    napalm_driver_for,
    resolve_targets,
)

# ---------------------------------------------------------------------------
# looks_like_error
# ---------------------------------------------------------------------------

def test_looks_like_error_spots_a_plain_rejection():
    assert looks_like_error("% Invalid input detected at '^' marker.")


def test_looks_like_error_sees_past_the_voss_execution_banner():
    # VOSS frames a 'Command Execution Time' banner in 84-character rules and
    # prints it BEFORE the error — well past a 200-character head scan.
    output = (
        "*" * 84 + "\n"
        "                Command Execution Time: Thu Jul 16 13:53:55 2026 CEST\n"
        + "*" * 84 + "\n"
        "% Invalid input detected at '^' marker.\n"
    )
    assert len(output[:200]) == 200          # the head really is all banner
    assert "invalid" not in output[:200].lower()
    assert looks_like_error(output)


def test_looks_like_error_ignores_a_percent_sign_in_ordinary_data():
    assert not looks_like_error("port 1/1 utilization: 42 %\nport 1/2: 7 %")


def test_looks_like_error_ignores_healthy_output():
    assert not looks_like_error("VLAN  NAME       TYPE\n100   Users      byPort")


def test_command_slug_matches_the_fixture_filenames():
    assert command_slug("show vlan i-sid") == "show_vlan_i_sid"
    assert command_slug("show interfaces gigabitEthernet state") == \
        "show_interfaces_gigabitethernet_state"


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------

def test_two_sessions_to_one_host_do_not_share_a_logger(tmp_path):
    # Same host, same second: the logger name used to collide, so both
    # instances shared one Logger, stacked two handlers, and wrote every
    # audit line twice.
    first  = AuditLogger("192.168.1.1", log_dir=tmp_path)
    second = AuditLogger("192.168.1.1", log_dir=tmp_path)

    first.log("show version", "output-a")
    second.log("show version", "output-b")
    first.close()
    second.close()

    files = sorted(tmp_path.glob("*.log"))
    assert len(files) == 2
    for path in files:
        assert path.read_text().count("show version") == 1


def test_close_is_idempotent(tmp_path):
    logger = AuditLogger("10.0.0.1", log_dir=tmp_path)
    logger.close()
    logger.close()             # a second close must not write to a closed handler
    logger.log("show run", "x")  # nor must a late write
    assert logger.log_path.read_text().count("SESSION CLOSED") == 1


def test_multiline_output_becomes_one_record_per_line(tmp_path):
    with AuditLogger("10.0.0.1", log_dir=tmp_path) as logger:
        logger.log("show vlan", "line one\nline two\nline three")
    body = logger.log_path.read_text()
    assert body.count("[show vlan] ->") == 3


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

def test_no_extreme_platform_is_mapped_to_a_napalm_driver():
    # extreme_exos used to map to 'eos' — Arista's eAPI driver — so every
    # NAPALM getter against Extreme gear was broken by construction.
    for device_type in ("extreme_exos", "extreme_vsp", "extreme_ers"):
        assert device_type not in NAPALM_DRIVER_MAP
        with pytest.raises(ValueError, match="not supported by NAPALM"):
            napalm_driver_for(device_type)


def test_napalm_driver_for_supported_platforms():
    assert napalm_driver_for("cisco_ios") == "ios"
    assert napalm_driver_for("cisco_xe") == "ios"
    assert napalm_driver_for("juniper_junos") == "junos"


def test_extreme_platforms_are_supported_device_types():
    # They must be in SUPPORTED_OS even though NAPALM cannot reach them: the
    # SSH tools do, and build_ad_hoc_profile() gates on this tuple.
    for device_type in ("extreme_exos", "extreme_vsp", "extreme_ers"):
        assert device_type in SUPPORTED_OS


def test_build_ad_hoc_profile_rejects_an_unknown_device_type():
    with pytest.raises(ValueError, match="Unsupported device_type"):
        build_ad_hoc_profile("10.0.0.1", "nonsense_os", "user", "pw")


def test_build_ad_hoc_profile_keeps_fast_cli_off():
    # Old ERS/BOSS gear chokes on Netmiko's fast path.
    profile = build_ad_hoc_profile("10.0.0.1", "extreme_ers", "user", "pw")
    assert profile["fast_cli"] is False


def test_resolve_targets_accepts_names_ips_tags_and_all():
    inventory = {
        "sw-a": {"host": "10.0.0.1", "device_type": "extreme_vsp", "tags": ["core"]},
        "sw-b": {"host": "10.0.0.2", "device_type": "extreme_ers", "tags": ["access"]},
    }
    assert [n for n, _ in resolve_targets("all", inventory)] == ["sw-a", "sw-b"]
    assert [n for n, _ in resolve_targets("sw-b", inventory)] == ["sw-b"]
    assert [n for n, _ in resolve_targets("10.0.0.1", inventory)] == ["sw-a"]
    assert [n for n, _ in resolve_targets("tag:core", inventory)] == ["sw-a"]


def test_resolve_targets_skips_an_unknown_token_without_dropping_the_rest():
    inventory = {"sw-a": {"host": "10.0.0.1", "tags": []}}
    assert [n for n, _ in resolve_targets("sw-a,typo", inventory)] == ["sw-a"]


def test_load_inventory_reads_a_file_and_resolves_secret_env(tmp_path, monkeypatch):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({
        "sw-a": {"host": "10.0.0.1", "device_type": "extreme_vsp",
                 "secret_env": "TEST_ENABLE_SECRET"},
    }))
    monkeypatch.setenv("TEST_ENABLE_SECRET", "s3cret")

    inventory = load_inventory(path)
    assert inventory["sw-a"]["secret"] == "s3cret"
    assert "secret_env" not in inventory["sw-a"]      # never carried further
    assert inventory["sw-a"]["port"] == 22            # defaulted


def test_load_inventory_skips_an_entry_with_no_host(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"broken": {"device_type": "cisco_ios"}}))
    assert load_inventory(path) == {}


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def test_export_csv_covers_columns_a_later_row_introduces(tmp_path):
    path = export_rows([{"a": 1}, {"a": 2, "b": 3}], "t", "csv",
                       path=tmp_path / "out.csv")
    assert path.read_text().splitlines()[0] == "a,b"


def test_export_json_round_trips(tmp_path):
    rows = [{"host": "10.0.0.1", "status": "up"}]
    path = export_rows(rows, "t", "json", path=tmp_path / "out.json")
    assert json.loads(path.read_text()) == rows


def test_export_refuses_an_unknown_format(tmp_path):
    assert export_rows([{"a": 1}], "t", "xml", path=tmp_path / "o.xml") is None


def test_export_of_nothing_writes_nothing(tmp_path):
    assert export_rows([], "t", "csv", path=tmp_path / "o.csv") is None
    assert not (tmp_path / "o.csv").exists()


# ---------------------------------------------------------------------------
# ANSI-safe padding
# ---------------------------------------------------------------------------

def test_pad_ignores_ansi_escapes():
    # f"{coloured:>8}" counts the escape bytes toward the width and collapses
    # the column; pad() measures what the terminal actually renders.
    cell = f"{C_GREEN}up{C_RESET}"
    assert visible_len(cell) == 2
    assert visible_len(pad(cell, 8)) == 8
    assert visible_len(pad(cell, 8, ">")) == 8


def test_pad_does_not_truncate_oversized_content():
    assert pad("a-very-long-value", 4) == "a-very-long-value"


def test_strip_ansi():
    assert strip_ansi(f"{C_GREEN}core-01{C_RESET}") == "core-01"


# ---------------------------------------------------------------------------
# The session must never be left open when setup fails
# ---------------------------------------------------------------------------

class _FakeConn:
    """Minimal stand-in for a Netmiko connection."""

    def __init__(self):
        self.disconnected = False

    def disconnect(self):
        self.disconnected = True


def test_a_setup_failure_after_connect_closes_the_session(monkeypatch):
    # __init__ raising means the caller never gets an object to .close(), so
    # anything escaping the setup steps leaks the SSH session for the life of
    # the process.  Ctrl-C during 'enable' is the realistic way in: it is a
    # BaseException, so the broad handlers inside the setup steps miss it.
    from core.connection import SshRunner

    fake = _FakeConn()

    def fake_connect(self):
        self._conn = fake

    def boom(self):
        raise KeyboardInterrupt

    monkeypatch.setattr(SshRunner, "_connect", fake_connect)
    monkeypatch.setattr(SshRunner, "_ensure_privileged", boom)

    with pytest.raises(KeyboardInterrupt):
        SshRunner({"host": "10.0.0.1", "device_type": "extreme_vsp"},
                  legacy_algorithms=False)

    assert fake.disconnected, "the SSH session was leaked"


def test_a_clean_setup_leaves_the_session_open(monkeypatch):
    from core.connection import SshRunner

    fake = _FakeConn()
    monkeypatch.setattr(SshRunner, "_connect",
                        lambda self: setattr(self, "_conn", fake))
    monkeypatch.setattr(SshRunner, "_ensure_privileged", lambda self: None)
    monkeypatch.setattr(SshRunner, "_ensure_paging_disabled", lambda self: None)

    runner = SshRunner({"host": "10.0.0.1", "device_type": "extreme_vsp"},
                       legacy_algorithms=False)
    assert not fake.disconnected
    runner.close()
    assert fake.disconnected


# ---------------------------------------------------------------------------
# wait_for_user
# ---------------------------------------------------------------------------

def test_wait_for_user_survives_an_exhausted_stdin(monkeypatch, capsys):
    # Both menu call sites sit outside their try blocks, so an EOF here used
    # to end the menu on a stack trace instead of a clean exit.
    from core.colors import wait_for_user

    def no_input(*_):
        raise EOFError

    monkeypatch.setattr("builtins.input", no_input)
    wait_for_user()                      # must not raise
    capsys.readouterr()
