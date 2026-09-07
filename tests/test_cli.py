"""
Non-interactive CLI tests.

Exit codes are the CLI's real contract — a cron job or a change-window script
branches on them — so they are what gets asserted here.
"""

from __future__ import annotations

import copy
import json

import pytest

import cli
from features import voss_parsers as vp
from features.validator import Snapshot, save_snapshot


@pytest.fixture
def snapshots(voss, tmp_path):
    """Write a (pre, post, identical) trio of snapshots and return their paths."""
    facts = {
        "ports": vp.parse_port_state(voss("show_interfaces_gigabitethernet_state")),
        "vlans": vp.parse_vlan_basic(voss("show_vlan_basic")),
        "mlts":  vp.parse_mlt(voss("show_mlt")),
    }
    pre = Snapshot("10.0.0.5", "extreme_vsp", "pre", "t0", facts=facts)

    damaged = copy.deepcopy(facts)
    damaged["ports"]["1/47"]["oper"] = "down"
    post = Snapshot("10.0.0.5", "extreme_vsp", "post", "t1", facts=damaged)

    same = Snapshot("10.0.0.5", "extreme_vsp", "post", "t1",
                    facts=copy.deepcopy(facts))

    return (
        save_snapshot(pre,  tmp_path / "pre.json"),
        save_snapshot(post, tmp_path / "post.json"),
        save_snapshot(same, tmp_path / "same.json"),
    )


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def test_a_subcommand_is_required():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


def test_run_accepts_repeated_commands_in_order():
    args = cli.build_parser().parse_args(
        ["run", "--targets", "all", "--command", "show mlt", "--command", "show vlan"])
    assert args.command == ["show mlt", "show vlan"]


def test_out_alone_implies_a_format(tmp_path, snapshots):
    pre, post, _same = snapshots
    out = tmp_path / "findings.json"
    assert cli.main(["compare", "--pre", str(pre), "--post", str(post),
                     "--out", str(out)]) == cli.EXIT_FINDINGS
    assert json.loads(out.read_text())[0]["category"] == "PORT"


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------

def test_compare_exits_1_on_a_critical_finding(snapshots, capsys):
    pre, post, _same = snapshots
    assert cli.main(["compare", "--pre", str(pre), "--post", str(post)]) == \
        cli.EXIT_FINDINGS
    assert "1/47" in capsys.readouterr().out


def test_compare_exits_0_when_nothing_changed(snapshots):
    pre, _post, same = snapshots
    assert cli.main(["compare", "--pre", str(pre), "--post", str(same)]) == \
        cli.EXIT_OK


def test_compare_exits_2_on_a_missing_snapshot(tmp_path, capsys):
    assert cli.main(["compare", "--pre", str(tmp_path / "nope.json"),
                     "--post", str(tmp_path / "nope.json")]) == cli.EXIT_ERROR


def test_fail_on_any_promotes_informational_findings(voss, tmp_path):
    facts = {"ports": vp.parse_port_state(
        voss("show_interfaces_gigabitethernet_state"))}
    pre = Snapshot("10.0.0.5", "extreme_vsp", "pre", "t0", facts=facts)

    improved = copy.deepcopy(facts)
    improved["ports"]["1/2"]["oper"] = "up"        # an INFO finding only
    post = Snapshot("10.0.0.5", "extreme_vsp", "post", "t1", facts=improved)

    pre_path  = save_snapshot(pre,  tmp_path / "a.json")
    post_path = save_snapshot(post, tmp_path / "b.json")

    assert cli.main(["compare", "--pre", str(pre_path),
                     "--post", str(post_path)]) == cli.EXIT_OK
    assert cli.main(["compare", "--pre", str(pre_path), "--post", str(post_path),
                     "--fail-on", "any"]) == cli.EXIT_FINDINGS


# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------

def test_inventory_lists_devices(capsys):
    assert cli.main(["inventory"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "core-router-01" in out
    assert "192.168.1.1" in out


def test_inventory_filters_by_tag(capsys):
    assert cli.main(["inventory", "--targets", "tag:core"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "core-router-01" in out
    assert "edge-junos-01" not in out


def test_inventory_exports(tmp_path):
    out = tmp_path / "inv.csv"
    assert cli.main(["inventory", "--out", str(out)]) == cli.EXIT_OK
    assert out.read_text().splitlines()[0] == "name,host,device_type,port,tags"


# ---------------------------------------------------------------------------
# Unattended credential handling
# ---------------------------------------------------------------------------

def test_a_non_tty_run_without_credentials_fails_instead_of_prompting(monkeypatch):
    # Hanging on a getpass prompt nothing will ever answer is the worst
    # outcome for a cron job, so this must return, not block.
    monkeypatch.delenv("SYSNET_PASS", raising=False)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli._resolve_credentials(None) is None


def test_credentials_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("SYSNET_USER", "netops")
    monkeypatch.setenv("SYSNET_PASS", "s3cret")
    from core.inventory import clear_credential_cache

    clear_credential_cache()
    assert cli._resolve_credentials(None) == ("netops", "s3cret")
    clear_credential_cache()


# ---------------------------------------------------------------------------
# "nothing ran" must never look like success
# ---------------------------------------------------------------------------

def test_run_exits_2_when_no_device_had_a_usable_profile(monkeypatch):
    # Reporting "0/0 device(s) reachable" with exit 0 is how a broken cron job
    # stays green forever: nothing was contacted, so this is "could not run".
    monkeypatch.setenv("SYSNET_USER", "u")
    monkeypatch.setenv("SYSNET_PASS", "p")
    monkeypatch.setattr("core.inventory.build_ad_hoc_profile",
                        lambda **_: (_ for _ in ()).throw(ValueError("nope")))
    assert cli.main(["run", "--targets", "all", "--command", "show version"]) == \
        cli.EXIT_ERROR


def test_run_exits_2_when_the_ssh_layer_contacts_nothing(monkeypatch):
    # run_bulk_ssh returns [] when Netmiko is missing entirely.
    monkeypatch.setenv("SYSNET_USER", "u")
    monkeypatch.setenv("SYSNET_PASS", "p")
    monkeypatch.setattr("features.ssh_runner.run_bulk_ssh", lambda *a, **k: [])
    assert cli.main(["run", "--targets", "all", "--command", "show version"]) == \
        cli.EXIT_ERROR
