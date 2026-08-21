# Networking Toolkit ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![Version](https://img.shields.io/badge/version-2.3.0-green) ![Tests](https://img.shields.io/badge/tests-109%20offline-brightgreen)

**Modular CLI utility for system & network engineers.**
Two entry points over the same code: an interactive menu, and a non-interactive CLI for cron and CI.

```bash
python3 main_menu.py        # interactive menu
python3 cli.py --help       # unattended
```

---

## Quickstart

```bash
git clone https://github.com/timoooonnn-s/networking-toolkit.git
cd networking-toolkit
pip install -r requirements.txt      # every dependency is optional
python3 main_menu.py
```

Nothing needs installing to start: the toolkit runs on the standard library and each
device-facing tool checks for what it needs, printing the `pip install` line instead of
a stack trace. Menu option `d` shows the full dependency status.

Set up an inventory so the tools stop asking you to retype IPs:

```bash
cp inventory.example.json inventory.json   # git-ignored
export SYSNET_USER=netops                  # SYSNET_PASS too, for unattended runs
```

---

## Tool categories

| Category | Tools |
| --- | --- |
| **Diagnostics** | CIDR calculator, TCP port tester, SSL expiry, bulk DNS, public IP & geo, traceroute analyser, **multi-host reachability** |
| **System** | Resource snapshot, top processes, listening ports, log scanner |
| **Automation / config** | Config diff, Jinja2 renderer, interface parser, SSH bulk commander, rollback generator, snippet library, ASCII diagram |
| **Change management** | **Configuration backup**, **pre/post change validator** |
| **NAPALM & health** | NAPALM getters, interface health dashboard (with real utilisation) |
| **IP & hardware** | Next available IP, bandwidth monitor, VLAN planner, SNMP discovery |

Every tool that produces a table can export it to CSV or JSON, into `exports/`.

---

## The inventory

Devices live in `inventory.json` at the project root (override with `$SYSNET_INVENTORY`).
Any tool can then address them by name, by IP, by tag, or all at once:

```json
{
  "core-vsp-01": {
    "host": "10.0.0.1",
    "device_type": "extreme_vsp",
    "port": 22,
    "tags": ["core", "site-a"]
  },
  "edge-router-01": {
    "host": "192.168.1.1",
    "device_type": "cisco_ios",
    "secret_env": "CISCO_ENABLE",
    "tags": ["edge"]
  }
}
```

`secret_env` names an **environment variable** holding the enable secret, so the
inventory file itself never contains one.

Selectors accept `all`, `tag:core`, a device name, an IP, or any comma-separated mix.

Supported `device_type` values: `cisco_ios`, `cisco_xe`, `juniper_junos`,
`extreme_exos`, `extreme_vsp` (VOSS / Fabric Engine), `extreme_ers` (BOSS).

---

## Unattended CLI

```bash
python3 cli.py ping      --targets 192.168.1.0/24 --format csv
python3 cli.py inventory --targets tag:core
python3 cli.py backup    --targets all --git
python3 cli.py run       --targets tag:core --command "show sys-info"
python3 cli.py snapshot  --target core-vsp-01 --label pre
python3 cli.py compare   --pre snapshots/pre.json --post snapshots/post.json
```

Exit codes are meant to be branched on:

| Code | Meaning |
| --- | --- |
| `0` | success, nothing to report |
| `1` | the operation found a problem (host down, config changed, findings) |
| `2` | the operation could not run (bad arguments, no credentials, no targets) |

Credentials come from `$SYSNET_USER` / `$SYSNET_PASS`. When they are missing and stdin
is not a terminal, the CLI fails with a message naming those variables rather than
hanging forever on a prompt no cron job can answer.

---

## Change management

### Configuration backup

Pulls the running config from every matching device in parallel into a diffable tree,
and reports **which devices changed** — volatile lines (the VOSS execution-time banner,
IOS's "Last configuration change", NTP clock drift) are stripped before comparison, so
"3 of 12 changed" means something.

```
backups/core-vsp-01/20260821_141500.cfg
backups/core-vsp-01/latest.cfg
```

Nightly, via cron (the tool prints this line for you):

```cron
0 2 * * *  cd /path/to/toolkit && python3 cli.py backup --targets all --git >> logs/backup.cron.log 2>&1
```

### Pre / post change validator

Snapshot a device before a change, snapshot it after, and see exactly what moved.
Rollback tells you how to undo a change; this tells you whether you need to.

```bash
python3 cli.py snapshot --target core-vsp-01 --label pre
#   ... apply the change ...
python3 cli.py snapshot --target core-vsp-01 --label post
python3 cli.py compare  --pre snapshots/..._pre_....json --post snapshots/..._post_....json
```

```
CRIT     PORT      1/47      link up → down (reason: LinkFail)
CRIT     VLAN      200       VLAN 'Printers' no longer exists
CRIT     VLAN      100       ports no longer active in this VLAN: 2/1/1
CRIT     MLT       2         lost member port(s): 1/2
CRIT     LLDP      1/1       lost neighbour 'core-01'
CRIT     IST       10.0.0.2  vIST status up → down
```

On **VOSS** the output is parsed into structured facts (ports, VLANs, I-SID bindings,
VLAN membership, MLTs, LLDP neighbours, vIST), so findings name the exact port, VLAN or
neighbour. Every other platform falls back to a raw-output diff of the same command set:
less precise, but honest — the toolkit never pretends to understand output it cannot
parse.

---

## Talking to Extreme gear

VOSS and ERS are not "open a Netmiko session and send commands", and the failures that
follow from treating them that way look like something else entirely. `core/connection.py`
handles all of it once, for every tool:

* **The ERS Ctrl-Y login gate.** ERS/BOSS gate the CLI behind `Enter Ctrl-Y to begin`,
  and many units stay *silent* after SSH authentication until they receive a keystroke.
  Netmiko's stock handler reads before sending anything, times out, and reports
  `Pattern not detected: '(?:\#|>)'` — which reads like a cipher problem and is not one.
* **Legacy SSH algorithms.** Old ERS gear offers only SHA-1 kex, CBC ciphers and
  `ssh-rsa`/`ssh-dss` host keys. Those are *appended* to Paramiko's preference lists, never
  prepended, so modern devices negotiate exactly what they always did.
* **Privileged EXEC.** Both platforms log in at `>`, and on VOSS 8.x some `show` commands
  work there and some do not — so a missing `enable` looks like release variance. Junos
  is exempted: it has no enable mode, and sending one raises.
* **Verified paging disable.** A live pager stalls long output at `--More--` *and*
  swallows the next command's characters, so one missed paging command corrupts the rest
  of the session. The command's answer is checked, and VOSS gets a second spelling.
* **Retries that know the difference.** Authentication failures are never retried (that
  locks out the account on every box at once), and neither are device *rejections* —
  re-sending a command a release does not implement cannot produce a different answer.
  Only transport failures are, and two consecutive ones abandon the session instead of
  burning a full read timeout per remaining command.

The approach and the field notes behind it come from
[switch-migrator](https://github.com/timoooonnn-s/switch-migrator), where it is in
production use.

---

## Multi-host reachability

Uses `fping` when it is installed — one process for the whole subnet — and falls back to
the system `ping` across a thread pool when it is not. Same table, same export, either way.

```bash
python3 cli.py ping --targets "192.168.1.0/24"
python3 cli.py ping --targets "10.0.0.5-10.0.0.9, gw.example.com" --format json
```

Targets accept a comma-separated list, a CIDR, a three-octet prefix (`192.168.1.`) or an
inclusive range. Every probe is bounded by an explicit timeout, so an unreachable host
costs 800 ms rather than the OS default.

---

## Project layout

```
main_menu.py              # interactive menu
cli.py                    # non-interactive entry point
inventory.example.json    # copy to inventory.json
core/
  colors.py               # ANSI constants, ANSI-safe column padding, banner
  paths.py                # every on-disk location, anchored to the project root
  inventory.py            # inventory, credentials, platform maps
  prompts.py              # shared inventory-aware target selection
  connection.py           # VOSS/ERS-aware SSH session layer
  export.py               # CSV / JSON export
  dependency_check.py     # optional-dependency detection & install hints
  audit_logger.py         # per-session SSH audit trail -> logs/
features/
  diagnostics.py          # CIDR, TCP, traceroute, SSL, DNS, public IP
  system_health.py        # resources, processes, ports, log scanner
  config_tools.py         # diff, snippets, diagram, Jinja2, interface parser
  multiping.py            # multi-host reachability (fping / ping)
  ssh_runner.py           # persistent multi-command SSH bulk runner
  backup.py               # configuration backup + change detection
  validator.py            # pre/post change validation
  voss_parsers.py         # VOSS CLI output parsers
  napalm_interface.py     # NAPALM normalized getters
  rollback.py             # multi-vendor config rollback generator
  interface_health.py     # interface health dashboard
  ip_hardware.py          # SNMP, VLAN tracker, next-IP, bandwidth
tests/                    # offline pytest suite + real VOSS captures
```

Runtime data (`logs/`, `backups/`, `exports/`, `snapshots/`, the JSON stores) is written
next to the project and git-ignored. Every path is anchored to the project root, so
launching the toolkit from another directory no longer opens a second, empty database.

---

## Tests

```bash
pip install pytest
python3 -m pytest          # 109 tests, ~0.3s
ruff check .               # optional: pip install ruff
```

The suite runs **entirely offline**: no device, no network, no `fping`. The VOSS fixtures
under `tests/fixtures/voss/` are real command output, so a parser change that would break
against a live switch breaks here first.

---

## Notes

* Bandwidth monitoring is Linux-only (`/proc/net/dev`).
* NAPALM covers Cisco IOS/IOS-XE and Juniper Junos. It has **no** driver for any Extreme
  platform — use the SSH-based tools (bulk runner, backup, validator) for those. The
  toolkit says so rather than routing them to another vendor's driver.
* Every SSH session writes a per-session audit trail to `logs/`, one record per output
  line, so `grep`/`awk` can filter by device or command.
* Colour is switched off automatically when stdout is not a TTY, or when `NO_COLOR` is set.
EOF
echo done