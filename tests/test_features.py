"""
Feature-layer tests for the logic that used to be wrong.

Everything here is pure: target expansion, fping output parsing, config
normalisation, utilisation maths, rollback generation, the diagram cycle
guard and /proc/meminfo parsing.  No device and no network are touched.
"""

from __future__ import annotations

import pytest

from features.backup import RUNNING_CONFIG_COMMAND, normalise_config
from features.interface_health import (
    UTILISATION_CRIT_PCT,
    build_health_report,
    check_utilisation,
    utilisation_from_samples,
)
from features.multiping import _FPING_LINE, expand_targets
from features.rollback import ALL_OS_TYPES, VALID_STRATEGIES, RollbackEngine
from features.system_health import _read_meminfo

# ---------------------------------------------------------------------------
# multiping — target expansion
# ---------------------------------------------------------------------------

def test_expand_targets_handles_a_plain_list():
    assert expand_targets("10.0.0.1, host.example.com") == \
        ["10.0.0.1", "host.example.com"]


def test_expand_targets_expands_a_cidr():
    assert expand_targets("192.168.9.0/30") == ["192.168.9.1", "192.168.9.2"]


def test_expand_targets_handles_a_slash_32():
    # /32 has no hosts() to iterate — probing nothing would be silently wrong.
    assert expand_targets("10.1.1.5/32") == ["10.1.1.5"]


def test_expand_targets_expands_a_three_octet_prefix():
    hosts = expand_targets("192.168.1.")
    assert len(hosts) == 254
    assert hosts[0] == "192.168.1.1" and hosts[-1] == "192.168.1.254"


def test_expand_targets_expands_an_inclusive_range():
    assert expand_targets("10.0.0.5-10.0.0.8") == \
        ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]


def test_expand_targets_drops_duplicates_but_keeps_order():
    assert expand_targets("10.0.0.2, 10.0.0.1, 10.0.0.2") == \
        ["10.0.0.2", "10.0.0.1"]


# ---------------------------------------------------------------------------
# multiping — fping output
# ---------------------------------------------------------------------------

def test_fping_line_parses_a_reachable_host():
    match = _FPING_LINE.match(
        "10.0.0.1 : xmt/rcv/%loss = 1/1/0%, min/avg/max = 0.42/0.55/0.61")
    assert match.group("host") == "10.0.0.1"
    assert match.group("rcv") == "1"
    assert match.group("avg") == "0.55"


def test_fping_line_parses_an_unreachable_host():
    # An unreachable host has no min/avg/max section at all.
    match = _FPING_LINE.match("10.0.0.9 : xmt/rcv/%loss = 1/0/100%")
    assert match.group("rcv") == "0"
    assert match.group("avg") is None


def test_fping_line_ignores_unrelated_output():
    assert _FPING_LINE.match("fping: can't create socket") is None


# ---------------------------------------------------------------------------
# backup — change detection
# ---------------------------------------------------------------------------

def test_volatile_lines_do_not_count_as_a_config_change():
    before = (
        "*" * 84 + "\n"
        "   Command Execution Time: Thu Jul 16 13:53:55 2026 CEST\n"
        "vlan create 100 type port-mstprstp 0\n"
        "! Last configuration change at 10:00:00 UTC Mon Aug 3 2026\n"
        "ntp clock-period 17179860\n"
    )
    after = before.replace("Thu Jul 16 13:53:55", "Fri Jul 17 09:11:02") \
                  .replace("10:00:00", "11:30:00") \
                  .replace("17179860", "17179861")
    assert normalise_config(before) == normalise_config(after)


def test_a_real_config_change_is_detected():
    before = "vlan create 100 type port-mstprstp 0\n"
    after  = "vlan create 200 type port-mstprstp 0\n"
    assert normalise_config(before) != normalise_config(after)


def test_trailing_blank_lines_are_not_a_change():
    assert normalise_config("vlan create 100\n\n\n") == \
        normalise_config("vlan create 100\n")


def test_every_supported_platform_has_a_running_config_command():
    from core.inventory import SUPPORTED_OS
    for device_type in SUPPORTED_OS:
        assert device_type in RUNNING_CONFIG_COMMAND


# ---------------------------------------------------------------------------
# interface_health — utilisation
# ---------------------------------------------------------------------------

def test_utilisation_from_two_samples():
    # 12.5 MB in one second on a 1 Gbps link is 100 Mbit/s — 10%.
    rx, tx = utilisation_from_samples(
        {"speed": 1000},
        {"rx_octets": 0, "tx_octets": 0},
        {"rx_octets": 12_500_000, "tx_octets": 0},
        interval_secs=1.0,
    )
    assert rx == pytest.approx(10.0)
    assert tx == pytest.approx(0.0)


def test_utilisation_is_none_without_a_link_speed():
    # A virtual or unnegotiated port has no line rate to be a percentage of.
    assert utilisation_from_samples(
        {"speed": 0}, {"rx_octets": 0}, {"rx_octets": 10_000}, 1.0,
    ) == (None, None)


def test_a_counter_reset_reports_none_rather_than_zero():
    # A negative delta means the counter wrapped or was cleared; calling that
    # 0% would hide a real reset.
    rx, _tx = utilisation_from_samples(
        {"speed": 1000}, {"rx_octets": 5_000}, {"rx_octets": 10}, 1.0,
    )
    assert rx is None


def test_utilisation_is_capped_at_100_percent():
    rx, _tx = utilisation_from_samples(
        {"speed": 1}, {"rx_octets": 0}, {"rx_octets": 10_000_000}, 1.0,
    )
    assert rx == 100.0


def test_check_utilisation_flags_only_what_crosses_a_threshold():
    assert check_utilisation("1/1", 10.0, 10.0) == []

    anomalies = check_utilisation("1/1", UTILISATION_CRIT_PCT + 5, 75.0)
    assert [a.severity for a in anomalies] == ["CRIT", "WARN"]
    assert all(a.category == "UTILISATION" for a in anomalies)


def test_health_report_includes_utilisation_when_it_was_measured():
    interfaces = {"1/1": {"is_up": True, "is_enabled": True, "speed": 1000}}
    counters   = {"1/1": {"rx_errors": 0, "tx_errors": 0}}

    clean = build_health_report(interfaces, counters, host="sw")
    assert not clean.has_issues

    busy = build_health_report(interfaces, counters, host="sw",
                               utilisation={"1/1": (95.0, 1.0)})
    assert [a.category for a in busy.anomalies] == ["UTILISATION"]


def test_health_report_flags_an_admin_up_link_down_port():
    report = build_health_report(
        {"1/1": {"is_up": False, "is_enabled": True}}, {}, host="sw")
    assert [a.category for a in report.anomalies] == ["DOWN"]


# ---------------------------------------------------------------------------
# rollback
# ---------------------------------------------------------------------------

def test_destructive_default_interface_warning_is_its_own_comment_line():
    # A trailing '! Verify before applying' does not START with '!', so the
    # push() comment filter used to send the whole string to the device.
    script = RollbackEngine("cisco_ios").generate(["interface Gi0/1"])
    assert "default interface Gi0/1" in script

    executable = [c for c in script if not c.strip().startswith(("#", "!"))]
    assert all("Verify" not in command for command in executable)
    assert any("WARNING" in line for line in script if line.startswith("!"))


def test_junos_scripts_enter_configuration_mode_first():
    # rollback / show | compare / commit are configuration-mode commands and
    # fail outright from the operational mode a session lands in.
    for strategy in ("rollback", "commit_confirmed", "inversion"):
        script = RollbackEngine("juniper_junos").generate(
            ["set system host-name x"], strategy=strategy)
        executable = [c for c in script if not c.strip().startswith("#")]
        assert executable[0] == "configure", strategy


def test_commit_confirmed_note_interpolates_the_timeout():
    script = RollbackEngine("juniper_junos").generate(
        strategy="commit_confirmed", commit_confirmed=7)
    assert any("7 minutes" in line for line in script)
    assert not any("{minutes}" in line for line in script)


def test_ers_and_vsp_are_pushable_os_types():
    # They used to be 'strategies' of extreme_exos while being absent from
    # SUPPORTED_OS, so a generated script could never be pushed anywhere.
    from core.inventory import SUPPORTED_OS
    for os_type in ("extreme_vsp", "extreme_ers"):
        assert os_type in ALL_OS_TYPES
        assert os_type in SUPPORTED_OS
        assert RollbackEngine(os_type).generate(
            strategy=VALID_STRATEGIES[
                "vsp" if os_type == "extreme_vsp" else "ers"][0])


def test_an_unknown_strategy_raises_instead_of_silently_switching():
    with pytest.raises(ValueError, match="Unknown strategy"):
        RollbackEngine("cisco_ios").generate(["interface Gi0/1"], strategy="vsp")


def test_an_unknown_os_type_is_rejected_at_construction():
    with pytest.raises(ValueError, match="Unsupported os_type"):
        RollbackEngine("nonsense_os")


# ---------------------------------------------------------------------------
# config_tools — diagram cycle guard
# ---------------------------------------------------------------------------

def test_a_cyclic_topology_terminates(monkeypatch, capsys):
    # 'A -> B' plus 'B -> A' is how anyone describes a redundant link.  It
    # used to recurse until RecursionError after dumping ~1.9 MB of output.
    import features.config_tools as config_tools

    lines = iter(["A -> B", "B -> A", "B -> C", "DRAW"])
    monkeypatch.setattr("builtins.input", lambda *_: next(lines))

    config_tools.tool_diagram_gen()

    output = capsys.readouterr().out
    assert "loop, already shown" in output
    assert len(output) < 10_000
    assert output.count("[ C ]") == 1


# ---------------------------------------------------------------------------
# system_health — /proc/meminfo
# ---------------------------------------------------------------------------

def test_meminfo_is_parsed_by_key_not_by_line_number(tmp_path):
    # Reading lines[2] assumed MemAvailable was the third line; on a kernel
    # that omits it the tool read Buffers and claimed ~99% memory used.
    path = tmp_path / "meminfo"
    path.write_text(
        "MemTotal:       16000000 kB\n"
        "MemFree:          500000 kB\n"
        "Buffers:           20000 kB\n"
        "Cached:          4000000 kB\n"
        "MemAvailable:   12000000 kB\n"
    )
    values = _read_meminfo(str(path))
    assert values["MemAvailable"] == 12_000_000
    assert values["MemTotal"] == 16_000_000


def test_meminfo_of_a_missing_file_is_empty():
    assert _read_meminfo("/definitely/not/here") == {}


def test_a_real_voss_running_config_is_stable_across_captures(voss):
    # VOSS stamps the capture time into `show running-config` twice: once in
    # the execution-time banner and once as a bare '# Fri Jul 24 09:40:46
    # 2026 CEST'. Miss either and every device reports as changed every night.
    raw   = voss("show_running_config")
    later = raw.replace("Fri Jul 24 09:40:46 2026 CEST",
                        "Sat Jul 25 11:02:11 2026 CEST")
    assert normalise_config(raw) == normalise_config(later)


def test_a_real_edit_to_a_voss_running_config_is_detected(voss):
    raw    = voss("show_running_config")
    edited = raw.replace("config terminal",
                         "config terminal\nvlan create 999 type port-mstprstp 0", 1)
    assert normalise_config(raw) != normalise_config(edited)
