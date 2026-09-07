"""
SNMP engine tests.

The built-in engine is exercised end to end against a real UDP socket (see
tests/fake_agent.py), because a mock would agree with a broken encoder.  The
net-snmp path is tested at its parser, since the binaries are not guaranteed
to exist on any given machine — the captured output is the same shape those
tools emit.
"""

from __future__ import annotations

import pytest

from core.snmp import (
    SnmpCredentials,
    SnmpError,
    decode_oid,
    encode_oid,
    encode_set_value,
    parse_netsnmp_output,
    snmp_get,
    snmp_set,
    snmp_walk,
)
from tests.fake_agent import FakeAgent, counter64, integer, ip_address, octet_string


@pytest.fixture
def creds_for():
    """Credentials pointed at a running FakeAgent."""
    def build(agent, community="public"):
        return SnmpCredentials(version="2c", community=community,
                               port=agent.port, timeout_s=2, retries=1)
    return build


# ---------------------------------------------------------------------------
# OID codec
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("oid", [
    "1.3.6.1.2.1.1.1.0",
    "1.3.6.1.4.1.2272",                      # VOSS rapidCity root
    "1.0.8802.1.1.2.1.4.1.1.9",              # LLDP — first two arcs are 1.0
    "1.3.6.1.2.1.31.1.1.1.18.1000000",       # a sub-identifier over 127
    "2.100.3",                               # the 2.x arc the naive split breaks
    "0.0",
])
def test_oid_round_trips(oid):
    assert decode_oid(encode_oid(oid)) == oid


def test_sysdescr_matches_the_known_encoding():
    # sysDescr.0 is the one OID whose bytes everyone has seen in a capture.
    assert encode_oid("1.3.6.1.2.1.1.1.0").hex() == "2b06010201010100"


def test_the_first_two_arcs_share_one_sub_identifier():
    # 1.3 -> 40*1 + 3 = 43 = 0x2b
    assert encode_oid("1.3")[0] == 0x2B


def test_a_large_second_arc_is_not_split_on_the_first_byte():
    # 2.100 encodes to 180, which a naive 'first // 40' would read as 4.20.
    assert decode_oid(encode_oid("2.100.3")) == "2.100.3"


def test_a_malformed_oid_is_rejected():
    for bad in ("", "1", "1.2.three", "1.-2"):
        with pytest.raises(SnmpError):
            encode_oid(bad)


# ---------------------------------------------------------------------------
# SET value encoding
# ---------------------------------------------------------------------------

def test_set_value_encodings():
    assert encode_set_value("i", "1").hex() == "020101"
    assert encode_set_value("s", "up").hex() == "04027570"   # 04 02 'u' 'p'
    assert encode_set_value("a", "10.0.0.1").hex() == "40040a000001"
    assert encode_set_value("x", "de:ad:be:ef").hex() == "0404deadbeef"


def test_an_unknown_set_type_is_rejected_with_the_valid_list():
    with pytest.raises(SnmpError, match="unknown SET type"):
        encode_set_value("z", "1")


def test_an_odd_length_hex_value_is_rejected():
    with pytest.raises(SnmpError, match="odd number"):
        encode_set_value("x", "abc")


# ---------------------------------------------------------------------------
# Built-in engine, over a real socket
# ---------------------------------------------------------------------------

def test_get_returns_the_agents_value(creds_for):
    with FakeAgent({"1.3.6.1.2.1.1.5.0": octet_string("core-vsp-01")}) as agent:
        result = snmp_get("127.0.0.1", ["1.3.6.1.2.1.1.5.0"],
                          creds_for(agent), prefer_netsnmp=False)
    assert result.ok
    assert result.engine == "builtin"
    assert result.varbinds[0].value == "core-vsp-01"
    assert result.varbinds[0].type == "STRING"


def test_get_decodes_every_common_type(creds_for):
    table = {
        "1.3.6.1.2.1.1.5.0":            octet_string("sw"),
        "1.3.6.1.2.1.2.2.1.7.192":      integer(2),
        "1.3.6.1.2.1.31.1.1.1.6.192":   counter64(18_446_744_073_709_551_000),
        "1.3.6.1.2.1.4.20.1.1.10.0.0.1": ip_address("10.0.0.1"),
    }
    with FakeAgent(table) as agent:
        creds = creds_for(agent)
        values = {}
        for oid in table:
            result = snmp_get("127.0.0.1", [oid], creds, prefer_netsnmp=False)
            assert result.ok, result.error
            values[oid] = (result.varbinds[0].type, result.varbinds[0].value)

    assert values["1.3.6.1.2.1.2.2.1.7.192"] == ("INTEGER", 2)
    # Counter64 is unsigned; reading it signed would come back negative.
    assert values["1.3.6.1.2.1.31.1.1.1.6.192"][1] > 0
    assert values["1.3.6.1.2.1.4.20.1.1.10.0.0.1"] == ("IpAddress", "10.0.0.1")


def test_a_missing_object_is_reported_not_invented(creds_for):
    with FakeAgent({}) as agent:
        result = snmp_get("127.0.0.1", ["1.3.6.1.2.1.1.5.0"],
                          creds_for(agent), prefer_netsnmp=False)
    assert result.ok                       # the agent answered
    assert result.varbinds[0].type == "NoSuchObject"


def test_walk_returns_the_whole_subtree_and_stops_at_its_edge(creds_for):
    table = {
        "1.3.6.1.2.1.2.2.1.7.192": integer(1),
        "1.3.6.1.2.1.2.2.1.7.193": integer(2),
        "1.3.6.1.2.1.2.2.1.7.400": integer(1),
        "1.3.6.1.2.1.2.2.1.8.192": integer(1),   # the NEXT column — out of scope
    }
    with FakeAgent(table) as agent:
        result = snmp_walk("127.0.0.1", "1.3.6.1.2.1.2.2.1.7",
                           creds_for(agent), prefer_netsnmp=False)

    assert result.ok
    assert [v.oid for v in result.varbinds] == [
        "1.3.6.1.2.1.2.2.1.7.192",
        "1.3.6.1.2.1.2.2.1.7.193",
        "1.3.6.1.2.1.2.2.1.7.400",
    ]


def test_walk_of_an_empty_subtree_is_empty_not_an_error(creds_for):
    with FakeAgent({"1.3.6.1.2.1.1.5.0": octet_string("sw")}) as agent:
        result = snmp_walk("127.0.0.1", "1.3.6.1.4.1.2272",
                           creds_for(agent), prefer_netsnmp=False)
    assert result.ok
    assert result.varbinds == []


def test_walk_respects_its_row_ceiling(creds_for):
    table = {f"1.3.6.1.2.1.2.2.1.7.{i}": integer(1) for i in range(1, 60)}
    with FakeAgent(table) as agent:
        result = snmp_walk("127.0.0.1", "1.3.6.1.2.1.2.2.1.7",
                           creds_for(agent), prefer_netsnmp=False, max_rows=10)
    assert len(result.varbinds) == 10


def test_set_changes_the_value_on_the_agent(creds_for):
    with FakeAgent({"1.3.6.1.2.1.2.2.1.7.192": integer(2)}) as agent:
        result = snmp_set("127.0.0.1", "1.3.6.1.2.1.2.2.1.7.192", "i", "1",
                          creds_for(agent), prefer_netsnmp=False)
        assert result.ok, result.error
        # The agent's own table moved — the write really was applied.
        assert agent.table["1.3.6.1.2.1.2.2.1.7.192"][1] == b"\x01"


def test_a_read_only_agent_reports_notwritable_in_plain_words(creds_for):
    # error-status 17 is what a device with a read-only community answers.
    with FakeAgent({"1.3.6.1.2.1.1.5.0": octet_string("sw")},
                   error_status=17) as agent:
        result = snmp_set("127.0.0.1", "1.3.6.1.2.1.1.5.0", "s", "new",
                          creds_for(agent), prefer_netsnmp=False)
    assert not result.ok
    assert "notWritable" in result.error


def test_an_unauthorised_write_is_reported(creds_for):
    with FakeAgent({}, error_status=16) as agent:
        result = snmp_set("127.0.0.1", "1.3.6.1.2.1.1.5.0", "s", "x",
                          creds_for(agent), prefer_netsnmp=False)
    assert not result.ok
    assert "authorizationError" in result.error
    assert "write community" in result.error


def test_a_silent_agent_times_out_with_an_actionable_message(creds_for):
    with FakeAgent({}, drop_requests=99) as agent:
        creds = creds_for(agent)
        creds.timeout_s = 1
        creds.retries = 0
        result = snmp_get("127.0.0.1", ["1.3.6.1.2.1.1.5.0"], creds,
                          prefer_netsnmp=False)
    assert not result.ok
    assert "no response" in result.error
    assert "community" in result.error       # names the likely cause


def test_a_timeout_is_retried(creds_for):
    # One dropped datagram must not report a live device as unreachable.
    with FakeAgent({"1.3.6.1.2.1.1.5.0": octet_string("sw")},
                   drop_requests=1) as agent:
        creds = creds_for(agent)
        creds.timeout_s = 1
        creds.retries = 2
        result = snmp_get("127.0.0.1", ["1.3.6.1.2.1.1.5.0"], creds,
                          prefer_netsnmp=False)
    assert result.ok
    assert result.varbinds[0].value == "sw"


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def test_v2c_without_a_community_is_refused_before_any_packet():
    result = snmp_get("10.0.0.1", ["1.3.6.1.2.1.1.5.0"],
                      SnmpCredentials(version="2c", community=""),
                      prefer_netsnmp=False)
    assert not result.ok
    assert "community" in result.error


def test_v3_without_netsnmp_says_what_to_install(monkeypatch):
    monkeypatch.setattr("core.snmp.have_netsnmp", lambda: False)
    result = snmp_get("10.0.0.1", ["1.3.6.1.2.1.1.5.0"],
                      SnmpCredentials(version="3", user="netops"))
    assert not result.ok
    assert "net-snmp" in result.error
    assert "apt install snmp" in result.error


def test_the_v3_security_level_follows_the_keys_that_are_set():
    assert SnmpCredentials(version="3", user="u").security_level == "noAuthNoPriv"
    assert SnmpCredentials(version="3", user="u",
                           auth_key="a").security_level == "authNoPriv"
    assert SnmpCredentials(version="3", user="u", auth_key="a",
                           priv_key="p").security_level == "authPriv"


def test_privacy_without_authentication_is_refused():
    creds = SnmpCredentials(version="3", user="u", priv_key="p")
    assert "privacy requires authentication" in creds.validate()


def test_redacted_never_leaks_the_community():
    creds = SnmpCredentials(version="2c", community="s3cret-string")
    assert "s3cret" not in creds.redacted()
    assert "<hidden>" in creds.redacted()


def test_redacted_v3_names_the_level_but_no_keys():
    creds = SnmpCredentials(version="3", user="netops",
                            auth_key="authpass", priv_key="privpass")
    text = creds.redacted()
    assert "netops" in text and "authPriv" in text
    assert "authpass" not in text and "privpass" not in text


# ---------------------------------------------------------------------------
# net-snmp output parsing
# ---------------------------------------------------------------------------

def test_parses_a_typical_snmpwalk_capture():
    output = (
        '.1.3.6.1.2.1.1.5.0 = STRING: "core-vsp-01"\n'
        ".1.3.6.1.2.1.1.3.0 = Timeticks: (123456789) 14 days, 6:56:07.89\n"
        ".1.3.6.1.2.1.2.2.1.7.192 = INTEGER: up(1)\n"
        ".1.3.6.1.2.1.31.1.1.1.6.192 = Counter64: 184467440737\n"
        ".1.3.6.1.2.1.4.20.1.1.10.0.0.1 = IpAddress: 10.0.0.1\n"
    )
    varbinds = {v.oid: v for v in parse_netsnmp_output(output)}

    assert varbinds[".1.3.6.1.2.1.1.5.0"].value == "core-vsp-01"
    assert varbinds[".1.3.6.1.2.1.1.3.0"].value == 123456789
    # 'up(1)' must yield the number, not the word, so both engines agree.
    assert varbinds[".1.3.6.1.2.1.2.2.1.7.192"].value == 1
    assert varbinds[".1.3.6.1.2.1.31.1.1.1.6.192"].value == 184467440737
    assert varbinds[".1.3.6.1.2.1.4.20.1.1.10.0.0.1"].value == "10.0.0.1"


def test_an_empty_string_value_is_kept_as_an_empty_string():
    varbinds = parse_netsnmp_output('.1.3.6.1.2.1.31.1.1.1.18.192 = ""')
    assert varbinds[0].value == ""
    assert varbinds[0].type == "STRING"


def test_agent_exceptions_are_recognised():
    output = (
        ".1.3.6.1.4.1.9999.1 = No Such Object available on this agent at this OID\n"
        ".1.3.6.1.4.1.9999.2 = No Such Instance currently exists at this OID\n"
    )
    assert [v.type for v in parse_netsnmp_output(output)] == \
        ["NoSuchObject", "NoSuchInstance"]


def test_a_multi_line_string_is_joined_not_dropped():
    # sysDescr routinely wraps over several lines.
    output = (
        '.1.3.6.1.2.1.1.1.0 = STRING: VSP-7254XSQ (8.10.9.0)\n'
        "Extreme Networks\n"
        ".1.3.6.1.2.1.1.5.0 = STRING: core-01\n"
    )
    varbinds = parse_netsnmp_output(output)
    assert len(varbinds) == 2
    assert "Extreme Networks" in varbinds[0].value
    assert varbinds[1].value == "core-01"


def test_hex_strings_survive_parsing():
    varbinds = parse_netsnmp_output(
        ".1.3.6.1.2.1.2.2.1.6.192 = Hex-STRING: A4 25 1B 52 70 00")
    assert varbinds[0].type == "Hex-STRING"
    assert "A4 25" in varbinds[0].value


def test_unparseable_output_yields_nothing_rather_than_garbage():
    assert parse_netsnmp_output("Timeout: No Response from 10.0.0.1") == []
    assert parse_netsnmp_output("") == []
