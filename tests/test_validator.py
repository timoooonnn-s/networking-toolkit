"""
Pre/post change validator tests.

Snapshots are built from the real VOSS fixtures, then damaged in the specific
ways a change window goes wrong, so each assertion pins one finding the tool
exists to produce.
"""

from __future__ import annotations

import copy
import json

import pytest

from features import voss_parsers as vp
from features.validator import (
    Snapshot,
    commands_for,
    compare_snapshots,
    load_snapshot,
    save_snapshot,
)


@pytest.fixture
def facts(voss):
    """Structured facts for a healthy VOSS switch."""
    return {
        "ports":      vp.parse_port_state(voss("show_interfaces_gigabitethernet_state")),
        "vlans":      vp.parse_vlan_basic(voss("show_vlan_basic")),
        "vlan_isids": vp.parse_vlan_isid(voss("show_vlan_i_sid")),
        "members":    vp.parse_vlan_members(voss("show_vlan_members")),
        "mlts":       vp.parse_mlt(voss("show_mlt")),
        "lldp":       vp.parse_lldp_summary(voss("show_lldp_neighbor_summary")),
        "ist":        vp.parse_ist(voss("show_virtual_ist")),
    }


@pytest.fixture
def pair(facts):
    """A (pre, post) pair that starts out identical."""
    pre = Snapshot("10.0.0.5", "extreme_vsp", "pre", "2026-08-21T10:00:00",
                   facts=facts)
    post = Snapshot("10.0.0.5", "extreme_vsp", "post", "2026-08-21T10:30:00",
                    facts=copy.deepcopy(facts))
    return pre, post


def _findings(pre, post, category=None, severity=None):
    results = compare_snapshots(pre, post)
    if category:
        results = [f for f in results if f.category == category]
    if severity:
        results = [f for f in results if f.severity == severity]
    return results


# ---------------------------------------------------------------------------
# The quiet case
# ---------------------------------------------------------------------------

def test_identical_snapshots_produce_no_findings(pair):
    pre, post = pair
    assert compare_snapshots(pre, post) == []


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

def test_a_port_that_went_down_is_critical(pair):
    pre, post = pair
    post.facts["ports"]["1/47"]["oper"] = "down"
    post.facts["ports"]["1/47"]["reason"] = "LinkFail"

    findings = _findings(pre, post, category="PORT")
    assert len(findings) == 1
    assert findings[0].severity == "CRIT"
    assert findings[0].subject == "1/47"
    assert "LinkFail" in findings[0].detail


def test_a_port_that_came_up_is_informational(pair):
    pre, post = pair
    post.facts["ports"]["1/2"]["oper"] = "up"

    findings = _findings(pre, post, category="PORT")
    assert [f.severity for f in findings] == ["INFO"]


def test_an_admin_state_change_is_reported_separately(pair):
    pre, post = pair
    post.facts["ports"]["1/1"]["admin"] = "down"
    post.facts["ports"]["1/1"]["oper"] = "down"

    severities = sorted(f.severity for f in _findings(pre, post, category="PORT"))
    assert severities == ["CRIT", "WARN"]   # link went down AND was shut


# ---------------------------------------------------------------------------
# VLANs
# ---------------------------------------------------------------------------

def test_a_deleted_vlan_is_critical(pair):
    pre, post = pair
    del post.facts["vlans"]["200"]

    findings = [f for f in _findings(pre, post, category="VLAN")
                if f.subject == "200" and "no longer exists" in f.detail]
    assert len(findings) == 1
    assert findings[0].severity == "CRIT"


def test_a_lost_isid_binding_is_critical(pair):
    pre, post = pair
    post.facts["vlan_isids"]["100"]["isid"] = ""

    findings = [f for f in _findings(pre, post, category="VLAN")
                if "I-SID" in f.detail]
    assert len(findings) == 1
    assert findings[0].severity == "CRIT"
    assert "10100" in findings[0].detail


def test_a_port_leaving_a_vlans_active_set_is_critical(pair):
    pre, post = pair
    post.facts["members"]["100"]["active_members"] = ["1/1"]

    findings = [f for f in _findings(pre, post, category="VLAN")
                if "no longer active" in f.detail]
    assert len(findings) == 1
    assert "2/1/1" in findings[0].detail


# ---------------------------------------------------------------------------
# MLT / LLDP / IST
# ---------------------------------------------------------------------------

def test_an_mlt_losing_a_member_is_critical(pair):
    pre, post = pair
    post.facts["mlts"]["2"]["members"] = ["1/1"]

    findings = _findings(pre, post, category="MLT")
    assert len(findings) == 1
    assert findings[0].severity == "CRIT"
    assert "1/2" in findings[0].detail


def test_a_lost_lldp_neighbour_is_critical(pair):
    pre, post = pair
    del post.facts["lldp"]["1/1"]

    findings = _findings(pre, post, category="LLDP")
    assert [f.severity for f in findings] == ["CRIT"]
    assert "core-01" in findings[0].detail


def test_a_changed_lldp_neighbour_is_a_warning(pair):
    pre, post = pair
    post.facts["lldp"]["1/1"]["sysname"] = "someone-else"

    findings = _findings(pre, post, category="LLDP")
    assert [f.severity for f in findings] == ["WARN"]


def test_vist_going_down_is_critical(pair):
    pre, post = pair
    post.facts["ist"]["status"] = "down"

    findings = _findings(pre, post, category="IST")
    assert [f.severity for f in findings] == ["CRIT"]


def test_no_vist_on_either_side_is_not_a_finding(pair):
    pre, post = pair
    pre.facts["ist"] = {}
    post.facts["ist"] = {}
    assert _findings(pre, post, category="IST") == []


# ---------------------------------------------------------------------------
# Capture integrity
# ---------------------------------------------------------------------------

def test_a_command_that_stopped_working_is_itself_a_finding(pair):
    # Comparing against data that was never collected would report "no change"
    # for a device nobody actually checked.
    pre, post = pair
    post.failed.append("show mlt")

    findings = _findings(pre, post, category="CAPTURE")
    assert len(findings) == 1
    assert "show mlt" in findings[0].subject


def test_findings_are_sorted_most_severe_first(pair):
    pre, post = pair
    post.facts["ports"]["1/47"]["oper"] = "down"     # CRIT
    post.facts["ports"]["1/2"]["oper"] = "up"        # INFO
    post.facts["lldp"]["1/1"]["sysname"] = "other"   # WARN

    severities = [f.severity for f in compare_snapshots(pre, post)]
    assert severities == ["CRIT", "WARN", "INFO"]


# ---------------------------------------------------------------------------
# Non-VOSS fallback
# ---------------------------------------------------------------------------

def test_non_voss_devices_fall_back_to_a_raw_output_diff():
    pre = Snapshot("10.0.0.9", "cisco_ios", "pre", "t0",
                   raw={"show_ip_interface_brief": "Gi0/1 up up\nGi0/2 up up"})
    post = Snapshot("10.0.0.9", "cisco_ios", "post", "t1",
                    raw={"show_ip_interface_brief": "Gi0/1 up up\nGi0/2 down down"})

    findings = compare_snapshots(pre, post)
    assert len(findings) == 1
    assert findings[0].category == "OUTPUT"
    assert "show ip interface brief" in findings[0].subject


def test_unchanged_raw_output_is_not_a_finding():
    same = {"show_vlan_brief": "1 default active"}
    pre  = Snapshot("10.0.0.9", "cisco_ios", "pre", "t0", raw=dict(same))
    post = Snapshot("10.0.0.9", "cisco_ios", "post", "t1", raw=dict(same))
    assert compare_snapshots(pre, post) == []


# ---------------------------------------------------------------------------
# Command sets and round-tripping
# ---------------------------------------------------------------------------

def test_voss_gets_the_structured_command_set():
    commands = [c for c, _key, _req in commands_for("extreme_vsp")]
    assert "show vlan i-sid" in commands
    assert "show virtual-ist" in commands


def test_an_unknown_platform_falls_back_to_the_cisco_command_set():
    assert commands_for("something_new") == commands_for("cisco_ios")


def test_a_snapshot_round_trips_through_disk(pair, tmp_path):
    pre, _post = pair
    path = save_snapshot(pre, tmp_path / "pre.json")

    assert json.loads(path.read_text())["device_type"] == "extreme_vsp"
    restored = load_snapshot(path)
    assert restored.facts == pre.facts
    assert compare_snapshots(pre, restored) == []


def test_save_snapshot_accepts_a_string_path(pair, tmp_path):
    # The CLI's --out arrives as a plain string; str has no write_text().
    pre, _post = pair
    path = save_snapshot(pre, str(tmp_path / "nested" / "pre.json"))
    assert path.exists()
    assert load_snapshot(path).facts == pre.facts
