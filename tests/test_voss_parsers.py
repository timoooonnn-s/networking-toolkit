"""
Parser tests, pinned against real VOSS captures.

Each test names the trap it protects: the banner that pushes the real output
past a head-only scan, the footer whose first token is a bare number, the
wrapped VLAN column, the blank SYSNAME cell.  These are the shapes that break
a parser written against one clean sample.
"""

from __future__ import annotations

from features import voss_parsers as vp

# ---------------------------------------------------------------------------
# expand_port_list
# ---------------------------------------------------------------------------

def test_expand_port_list_expands_ranges_within_a_slot():
    assert vp.expand_port_list("1/1-1/3,1/10") == ["1/1", "1/2", "1/3", "1/10"]


def test_expand_port_list_keeps_cross_slot_ranges_as_endpoints():
    # Slot population differs per chassis, so guessing the members between
    # 1/47 and 2/2 would invent ports that may not exist.
    assert vp.expand_port_list("1/47-2/2") == ["1/47", "2/2"]


def test_expand_port_list_handles_none_and_junk():
    assert vp.expand_port_list("NONE") == []
    assert vp.expand_port_list("") == []
    assert vp.expand_port_list("not-a-port-list") == []


def test_expand_port_list_handles_channelised_ports():
    assert vp.expand_port_list("2/1/1-2/1/3") == ["2/1/1", "2/1/2", "2/1/3"]


# ---------------------------------------------------------------------------
# show interfaces gigabitEthernet state
# ---------------------------------------------------------------------------

def test_parse_port_state(voss):
    ports = vp.parse_port_state(voss("show_interfaces_gigabitethernet_state"))

    assert set(ports) == {"1/1", "1/2", "1/47", "1/48", "2/1/1"}
    assert ports["1/1"] == {"admin": "up", "oper": "up", "reason": "--"}
    # admin up but link down — the shape a post-change check cares about
    assert ports["1/2"]["admin"] == "up"
    assert ports["1/2"]["oper"] == "down"


def test_parse_port_state_keeps_the_down_reason(voss):
    ports = vp.parse_port_state(voss("show_interfaces_gigabitethernet_state"))
    assert ports["1/48"] == {"admin": "down", "oper": "down", "reason": "SSH"}


def test_parse_port_state_ignores_the_execution_time_banner(voss):
    output = voss("show_interfaces_gigabitethernet_state")
    assert "Command Execution Time" in output       # the trap is really there
    assert all("Command" not in port for port in vp.parse_port_state(output))


# ---------------------------------------------------------------------------
# show vlan basic / i-sid / members
# ---------------------------------------------------------------------------

def test_parse_vlan_basic(voss):
    vlans = vp.parse_vlan_basic(voss("show_vlan_basic"))
    assert set(vlans) == {"1", "100", "200", "300", "4000"}
    assert vlans["100"] == {"name": "Users", "type": "byPort"}
    assert vlans["4000"]["name"] == "vIST"


def test_parse_vlan_isid_covers_all_three_row_shapes(voss):
    vlans = vp.parse_vlan_isid(voss("show_vlan_i_sid"))

    # a VLAN with no I-SID prints its id alone
    assert vlans["1"] == {"isid": "", "isid_name": ""}
    # an I-SID with no name prints two columns
    assert vlans["200"] == {"isid": "10200", "isid_name": ""}
    # a named one prints three
    assert vlans["100"] == {"isid": "10100", "isid_name": "Server-VLAN-100"}


def test_parse_vlan_isid_ignores_the_numeric_footer(voss):
    # '5 out of 5 Total Num of Vlans displayed' starts with a bare number and
    # would otherwise be read as VLAN 5.
    vlans = vp.parse_vlan_isid(voss("show_vlan_i_sid"))
    assert "5" not in vlans
    assert len(vlans) == 5


def test_parse_vlan_members_reads_port_and_active_columns(voss):
    vlans = vp.parse_vlan_members(voss("show_vlan_members"))
    assert vlans["100"]["port_members"] == ["1/1", "1/2", "2/1/1"]
    # 1/2 is a static member but not active — exactly the gap worth reporting
    assert vlans["100"]["active_members"] == ["1/1", "2/1/1"]


def test_parse_vlan_members_handles_none(voss):
    vlans = vp.parse_vlan_members(voss("show_vlan_members"))
    assert vlans["1"] == {"port_members": [], "active_members": []}


# ---------------------------------------------------------------------------
# show mlt
# ---------------------------------------------------------------------------

def test_parse_mlt_reads_only_the_first_table(voss):
    mlts = vp.parse_mlt(voss("show_mlt"))
    assert set(mlts) == {"1", "2", "10"}
    assert mlts["1"]["name"] == "vIST-MLT"
    assert mlts["1"]["members"] == ["1/47", "1/48"]
    assert mlts["10"]["type"] == "access"


def test_parse_mlt_merges_wrapped_vlan_continuation_lines(voss):
    # MLT 2's VLAN IDS column wraps: '... 2266' then '2600 2601' on its own
    # line.  Dropping the continuation would under-report the MLT's VLANs.
    mlts = vp.parse_mlt(voss("show_mlt"))
    assert 2600 in mlts["2"]["vlans"]
    assert 2601 in mlts["2"]["vlans"]
    assert mlts["2"]["vlans"][:3] == [100, 200, 300]


# ---------------------------------------------------------------------------
# show lldp neighbor summary
# ---------------------------------------------------------------------------

def test_parse_lldp_summary(voss):
    neighbours = vp.parse_lldp_summary(voss("show_lldp_neighbor_summary"))
    assert neighbours["1/1"] == {
        "sysname": "core-01", "ip": "10.0.0.1", "remote_port": "1/47",
    }


def test_parse_lldp_summary_leaves_a_blank_sysname_blank(voss):
    # The server on 2/1/1 advertises no SYSNAME.  A whitespace split would
    # slide the SYSDESCR text into that cell and invent a neighbour name.
    neighbours = vp.parse_lldp_summary(voss("show_lldp_neighbor_summary"))
    assert neighbours["2/1/1"]["sysname"] == ""
    assert neighbours["2/1/1"]["ip"] == "10.0.0.9"
    assert "ProLiant" not in neighbours["2/1/1"]["sysname"]


def test_parse_lldp_summary_keeps_free_text_remote_ports(voss):
    neighbours = vp.parse_lldp_summary(voss("show_lldp_neighbor_summary"))
    assert neighbours["2/1/1"]["remote_port"] == "Embedded ALOM, Po~"


# ---------------------------------------------------------------------------
# show interfaces gigabitEthernet i-sid  /  show virtual-ist
# ---------------------------------------------------------------------------

def test_parse_port_isid(voss):
    ports = vp.parse_port_isid(voss("show_interfaces_gigabitethernet_i_sid"))
    assert ports["1/1"] == {"isid": "10100", "vlan": "100", "type": "ELAN"}
    assert ports["2/1/1"]["type"] == "CVLAN"


def test_parse_ist(voss):
    ist = vp.parse_ist(voss("show_virtual_ist"))
    assert ist == {
        "peer_ip": "192.168.255.2", "vlan": "4000",
        "enabled": "true", "status": "up",
    }


def test_parse_ist_returns_empty_on_a_box_without_vist():
    # An access switch legitimately has no vIST.  Absence is reported by the
    # caller, not raised here.
    assert vp.parse_ist("% Invalid input detected") == {}
    assert vp.parse_ist("") == {}


# ---------------------------------------------------------------------------
# Empty / hostile input
# ---------------------------------------------------------------------------

def test_every_parser_survives_empty_input():
    for parser in (
        vp.parse_port_state, vp.parse_vlan_basic, vp.parse_vlan_isid,
        vp.parse_vlan_members, vp.parse_mlt, vp.parse_lldp_summary,
        vp.parse_port_isid, vp.parse_ist,
    ):
        assert parser("") == {}


def test_every_parser_survives_a_rejection_message():
    rejection = "*" * 84 + "\n% Invalid input detected at '^' marker.\n"
    for parser in (
        vp.parse_port_state, vp.parse_vlan_basic, vp.parse_vlan_isid,
        vp.parse_vlan_members, vp.parse_mlt, vp.parse_lldp_summary,
        vp.parse_port_isid, vp.parse_ist,
    ):
        assert parser(rejection) == {}
