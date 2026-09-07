# Networking Toolkit

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Version](https://img.shields.io/badge/version-2.4.0-green)
![Tests](https://img.shields.io/badge/tests-188%20offline-brightgreen)

A command-line toolbox for network and system engineers. 26 tools behind one menu,
plus a non-interactive CLI for cron jobs and scripts.

Built around Extreme VOSS / Fabric Engine and ERS, but the general tools work
against Cisco IOS/IOS-XE, Juniper Junos and anything that speaks SNMP.

---

## Contents

- [Install and run](#install-and-run)
- [First five minutes](#first-five-minutes)
- [The inventory](#the-inventory)
- [The tools](#the-tools)
- [The SNMP assistant](#the-snmp-assistant)
- [Unattended use](#unattended-use)
- [Talking to Extreme gear](#talking-to-extreme-gear)
- [Where files go](#where-files-go)
- [Development](#development)

---

## Install and run

You need Python 3.10 or newer. Nothing else is required to start.

```bash
git clone https://github.com/timoooonnn-s/networking-toolkit.git
cd networking-toolkit
python3 main_menu.py
```

That works immediately — every tool built on the Python standard library runs
with no installation at all. Tools that talk to devices need extra libraries:

```bash
pip install -r requirements.txt
```

If you skip that, nothing breaks. Each tool checks for what it needs and prints
the exact `pip install` line instead of a stack trace. Press `d` in the menu for
a full dependency status.

Two optional command-line programs make some tools better. Both are detected
automatically, and both have a working fallback if missing:

| Program | Used by | Install |
| --- | --- | --- |
| `fping` | multi-host reachability (much faster) | `apt install fping` / `brew install fping` |
| `net-snmp` | SNMP assistant (**required for SNMPv3**) | `apt install snmp` / `brew install net-snmp` |

---

## First five minutes

```bash
# 1. See what's there
python3 main_menu.py

# 2. Make an inventory so tools stop asking you to retype IPs
cp inventory.example.json inventory.json
$EDITOR inventory.json

# 3. Set credentials once per shell
export SYSNET_USER=netops
export SYSNET_PASS='...'          # SSH
export SNMP_COMMUNITY=public      # SNMP reads

# 4. Try something read-only
python3 cli.py inventory
python3 cli.py ping --targets 192.168.1.0/24
python3 cli.py snmp preset --target core-vsp-01 --preset sysname
```

---

## The inventory

Most tools can pull their targets from `inventory.json` in the project root
(override the location with `$SYSNET_INVENTORY`). Copy `inventory.example.json`
to get started — `inventory.json` is git-ignored.

```json
{
  "core-vsp-01": {
    "host": "10.0.0.1",
    "device_type": "extreme_vsp",
    "port": 22,
    "tags": ["core", "site-a"],
    "snmp_version": "2c",
    "snmp_community_env": "VOSS_SNMP_RO",
    "snmp_write_community_env": "VOSS_SNMP_RW"
  },
  "edge-router-01": {
    "host": "192.168.1.1",
    "device_type": "cisco_ios",
    "secret_env": "CISCO_ENABLE",
    "tags": ["edge"]
  }
}
```

**No secrets in this file.** Any key ending in `_env` holds the *name of an
environment variable*, not the value. `"secret_env": "CISCO_ENABLE"` means "read
the enable secret from `$CISCO_ENABLE`". The file is safe to commit to a private
repo; the secrets stay in your shell or password manager.

**Selectors.** Anywhere a tool asks for a target, you can give it:

| Selector | Means |
| --- | --- |
| `core-vsp-01` | that one device by name |
| `10.0.0.1` | that device by IP |
| `tag:core` | every device tagged `core` |
| `all` | every device in the inventory |
| `tag:core,edge-router-01` | any mix, comma-separated |

**Supported `device_type` values:** `cisco_ios`, `cisco_xe`, `juniper_junos`,
`extreme_exos`, `extreme_vsp` (VOSS / Fabric Engine), `extreme_ers` (BOSS).

---

## The tools

Every tool that produces a table can export it to CSV or JSON — the interactive
tools offer it when they finish, the CLI takes `--format csv|json`. Files land in
`exports/`.

### Diagnostics

**1. CIDR Subnet Calculator** — Type `192.168.1.5/24`, get the network address,
netmask, broadcast, usable host count and first/last usable address. Handles
`/31` point-to-point links and `/32` host routes correctly.

**2. TCP Port Tester** — Opens a TCP connection to one host and port with a
3-second timeout and reports open or closed. Answers "is it the firewall or the
service" in one step.

**3. SSL Expiry Checker** — Reports a certificate's expiry date and days
remaining, warning under 30. It retries *unverified* when the chain fails, so it
can still read expired and self-signed certificates — the exact cases you use an
expiry checker for — and tells you the chain was untrusted.

**4. Bulk DNS Resolver** — Resolves a comma-separated list of hostnames to IPs,
or IPs back to hostnames. One bad entry is reported and skipped rather than
ending the run.

**5. Public IP & Geo** — Your outside IP plus city, region, country and ISP, from
ipinfo.io. Useful for confirming which path traffic is actually taking.

**6. Traceroute Path Analyser** — Runs the system traceroute and colours hops
slower than 150 ms and timeouts, so a long path's problem hop is visible at a
glance.

**7. Multi-Host Reachability Check** — "Are these clients still there?" for a
whole list at once. Accepts hosts, a CIDR (`192.168.1.0/24`), a prefix
(`192.168.1.`) or a range (`10.0.0.5-10.0.0.9`), mixed freely. Uses `fping` when
installed — one process for the whole subnet, so a /24 takes seconds — and falls
back to the system ping across a thread pool. Every probe has an explicit
timeout, so unreachable hosts cost milliseconds, not the OS default.

### System

**8. System Resource Snapshot** — Load average, disk usage and memory for the
machine you are running on, colour-coded by how close to full it is.

**9. Top Process Hogger** — The ten processes using the most memory.

**10. Service Port Listener** — What is listening locally, via `lsof` with a
`netstat` fallback.

**11. Log Keyword Scanner** — Case-insensitive keyword search through a log file,
showing line numbers, capped at 20 hits.

### Automation and config

**12. Config File Diff** — Coloured unified diff of two config files. Additions
green, removals red.

**13. Jinja2 Config Renderer** — Renders a `.j2` template against a JSON data
file and optionally saves the output. For generating repetitive config from a
table of values. *(needs `jinja2`)*

**14. Interface Config Parser** — Pulls interface name, IP and description out of
a Cisco-style config file into a table.

**15. SSH Bulk Commander** — Runs a list of commands across many devices at once,
one persistent SSH session each, in parallel. Every command and its full response
goes to a per-session audit log in `logs/`. Targets come from the inventory.
*(needs `netmiko`)*

**16. Config Rollback Generator** — You give it the commands you applied; it
generates the commands to undo them, per vendor:

- **Cisco** — inverts commands (`no ...`), or restores from a flash archive
- **Junos** — converts `set` to `delete`, or uses `rollback N`, or
  `commit confirmed N` (which auto-reverts if you lose access)
- **Extreme EXOS / VSP / ERS** — save-and-restore config file workflows

It prints the script for review first. Pushing it to a device is a separate,
optional step, and every command's response is checked — a script the device
rejected is reported as incomplete, not as success.

**17. Config Snippet Library** — A small JSON-backed store of reusable config
blocks you can add, view and delete.

**18. ASCII Network Diagram** — Type connections as `core-01 -> access-07` and
get a tree diagram in the terminal. Redundant links (cycles) are drawn once and
marked, not followed forever.

### Change management

**19. Configuration Backup** — Pulls the running config from every matching
device in parallel into a diffable tree:

```
backups/core-vsp-01/20260907_020000.cfg
backups/core-vsp-01/latest.cfg
```

It reports **which devices changed** since their last backup. Volatile lines —
the VOSS command-execution banner, its `# Fri Jul 24 09:40:46` stamp, IOS's "Last
configuration change", NTP clock drift — are stripped before comparing, so "3 of
12 changed" means three configs actually changed. Optionally commits the tree to
git. *(needs `netmiko`)*

**20. Pre / Post Change Validator** — The companion to the rollback generator.
Rollback tells you *how* to undo a change; this tells you *whether you need to*.

Snapshot the device before your change, snapshot it after, compare:

```bash
python3 cli.py snapshot --target core-vsp-01 --label pre
#   ... make your change ...
python3 cli.py snapshot --target core-vsp-01 --label post
python3 cli.py compare  --pre snapshots/..._pre_....json \
                        --post snapshots/..._post_....json
```

```
CRIT     PORT      1/47      link up → down (reason: LinkFail)
CRIT     VLAN      200       VLAN 'Printers' no longer exists
CRIT     VLAN      100       ports no longer active in this VLAN: 2/1/1
CRIT     MLT       2         lost member port(s): 1/2
CRIT     LLDP      1/1       lost neighbour 'core-01'
CRIT     IST       10.0.0.2  vIST status up → down
```

On **VOSS** the device output is parsed into structured facts — ports, VLANs,
I-SID bindings, VLAN membership, MLTs, LLDP neighbours, vIST — so a finding names
the exact port, VLAN or neighbour that moved. Every other platform gets a
raw-output diff of the same commands: less precise, but it still answers the
question, and the toolkit never pretends to understand output it cannot parse.

A command that worked before the change and failed after is itself reported —
comparing against data nobody collected would otherwise show "no change".

### NAPALM and health

**21. NAPALM Multi-Vendor Getters** — Vendor-normalised interface, BGP, LLDP and
facts data in one schema. Covers Cisco IOS/IOS-XE and Juniper Junos.

NAPALM has **no driver for any Extreme platform** — use the SSH tools (bulk
runner, backup, validator) for those. The toolkit says so plainly rather than
routing them to another vendor's driver. *(needs `napalm`)*

**22. Interface Health Dashboard** — Flags interfaces that are admin-up but
link-down, have CRC/input errors or output drops above threshold, or flapped
recently. Optionally measures real utilisation by sampling counters twice a few
seconds apart — utilisation is a rate, so a single snapshot cannot produce it.
*(needs `napalm`)*

### IP and hardware

**23. Next Available IP** — Given a subnet and a list of used addresses, returns
the first free one.

**24. Bandwidth Monitor** — Live RX/TX throughput for one local interface, from
`/proc/net/dev`. Linux only.

**25. VLAN Planner / Tracker** — A JSON-backed VLAN registry: ID, name, subnet
and description, with add/list/delete.

**26. SNMP Assistant** — see below.

---

## The SNMP assistant

Menu option 26, or `python3 cli.py snmp`. Three things it gives you over raw
`snmpget`:

### 1. Saved presets

A library of named operations, so you do not have to remember that
`ifAdminStatus` is `1.3.6.1.2.1.2.2.1.7` and that "up" is `1`.

```bash
python3 cli.py snmp presets                    # list them all
python3 cli.py snmp presets --writes-only      # just the ones that write
```

30 built-ins cover the everyday questions: system identity, per-port admin and
link state, port descriptions, error counters, 64-bit traffic counters, LLDP
neighbours, IP addresses, the bridge MAC table, and chassis/optic inventory with
serial numbers.

```bash
python3 cli.py snmp preset --target core-vsp-01 --preset if-oper-status
```

```
OID                       Type       Value
1.3.6.1.2.1.2.2.1.8.192   INTEGER    1 (up)
1.3.6.1.2.1.2.2.1.8.193   INTEGER    2 (down)
```

Status numbers are spelled out — `2 (down)` rather than `2` — because at 02:00
the number alone is not something you should have to translate.

### 2. Port names, not ifIndex numbers

SNMP addresses ports by ifIndex, and the mapping is **not** guessable: on a VOSS
switch, port `1/1` is ifIndex `192` and `2/1/1` is `400`. The assistant walks
`ifName` once and lets you use the name you actually know:

```bash
python3 cli.py snmp preset --target core-vsp-01 --preset port-up --port 1/1 --yes
```
```
1/1 → ifIndex 192
```

Matching is anchored, so `1/1` can never quietly resolve to `Port11/1` and shut
the wrong port. An ambiguous name resolves to nothing rather than a guess.

### 3. Writes you can trust yourself with

Every write shows exactly what will be sent and requires explicit confirmation —
`--yes` on the CLI, typing `yes` in the menu — and lands in the audit log in
`logs/`. Without it, nothing is sent:

```
This preset WRITES to the device:
  device : 10.0.0.1:161  (v2c community=<hidden>)
  oid    : 1.3.6.1.2.1.2.2.1.7.192
  value  : 1   [INTEGER]
  preset : port-up — Bring a port up (ifAdminStatus=up). The break-glass one.
Re-run with --yes to send it.
```

Community strings and v3 keys are never printed or logged.

### Manual operations

```bash
python3 cli.py snmp get  --target core-vsp-01 --oid 1.3.6.1.2.1.1.5.0
python3 cli.py snmp walk --target core-vsp-01 --oid 1.3.6.1.2.1.2.2.1.7
python3 cli.py snmp set  --target core-vsp-01 --oid 1.3.6.1.2.1.1.6.0 \
                         --type s --value "Rack 4, DC-2" --yes
```

Type codes match net-snmp's: `i` integer, `u` unsigned, `s` string, `x` hex,
`a` IP address, `o` OID, `t` timeticks, `c` counter.

### Credentials

```bash
export SNMP_COMMUNITY=public            # reads
export SNMP_WRITE_COMMUNITY='...'       # writes — kept separate deliberately
```

Or per device in the inventory via `snmp_community_env` /
`snmp_write_community_env`. For v3, set `snmp_version: "3"` plus `snmp_v3_user`,
`snmp_v3_auth_protocol`, `snmp_v3_priv_protocol` and the `_key_env` pairs.

### Two engines

| Situation | What runs | Supports |
| --- | --- | --- |
| `net-snmp` installed | `snmpget` / `snmpwalk` / `snmpset` | v1, v2c, **v3 with auth+priv** |
| not installed | a built-in engine, pure standard library | v2c only |

SNMPv3's cryptography is delegated to net-snmp rather than hand-rolled, because
getting USM authentication and AES privacy subtly wrong is worse than not
offering them. If you ask for v3 without net-snmp you get the install command,
never a silent downgrade to something weaker.

Both engines return identical output, so nothing else in the toolkit cares which
one ran.

### Vendor OIDs, and why there are none built in

The built-in presets are **all standard MIB OIDs** (MIB-2, IF-MIB, ENTITY-MIB,
LLDP-MIB, BRIDGE-MIB) — RFC-defined, the same on every vendor, verifiable
anywhere.

VOSS private objects live under **rapidCity, `1.3.6.1.4.1.2272`**. This toolkit
ships **no guessed OIDs** from that tree. A wrong OID in a break-glass preset is
worse than no preset at all, because you would be trusting it at exactly the
moment you cannot verify it.

Instead, find the real ones on your own switch and save them:

```
Menu 26 → 3. Discover vendor OIDs and save them as presets
```

That walks `1.3.6.1.4.1.2272` (or the ExtremeXOS tree, or any subtree you name),
shows what is there, and lets you save an entry as a named preset. Anything saved
this way is marked `unverified` until you confirm what it does. Presets live in
`snmp_presets.json`; reusing a built-in name overrides it, so your corrections
survive an upgrade.

### The break-glass case, honestly

The motivating scenario is "I broke SSH on a switch and cannot get back in". Two
things have to be true for SNMP to rescue you, and both are worth arranging
*before* you need them:

- **SNMP write access must already be configured.** A device with a read-only
  community answers every read and refuses every write with `notWritable` or
  `noAccess`. Set up a write community, or a v3 user with a write view, while you
  can still log in.
- **The object you need must exist.** `ifAdminStatus` is standard and writable,
  so **bouncing a port always works** — that alone recovers a wedged uplink or a
  port you shut by accident:

  ```bash
  python3 cli.py snmp preset --target sw --preset port-down --port 1/1 --yes
  python3 cli.py snmp preset --target sw --preset port-up   --port 1/1 --yes
  ```

  Re-enabling an SSH *daemon* needs a vendor-private object. Discover and pin
  that OID from your own switch first, while everything still works.

If neither applies, the console or an out-of-band management port is your
recovery path, and no SNMP tool changes that.

---

## Unattended use

`cli.py` runs the same tools from cron, CI or a script.

```bash
python3 cli.py --help                # every subcommand
python3 cli.py inventory --targets tag:core
python3 cli.py ping      --targets 192.168.1.0/24 --format csv
python3 cli.py backup    --targets all --git
python3 cli.py run       --targets tag:core --command "show sys-info"
python3 cli.py snapshot  --target core-vsp-01 --label pre
python3 cli.py compare   --pre snapshots/a.json --post snapshots/b.json
python3 cli.py snmp      preset --target core-vsp-01 --preset if-oper-status
```

**Exit codes** are the contract — branch on them:

| Code | Meaning |
| --- | --- |
| `0` | success, nothing to report |
| `1` | it ran and found a problem (host down, config changed, findings) |
| `2` | it could not run (bad arguments, no credentials, no targets reached) |

The `1` versus `2` split matters: a job that contacted nothing returns `2`, never
`0`, so a broken cron job cannot look green forever.

**Credentials** come from `$SYSNET_USER` / `$SYSNET_PASS` (SSH) and
`$SNMP_COMMUNITY` / `$SNMP_WRITE_COMMUNITY` (SNMP). When they are missing and
stdin is not a terminal, the CLI fails immediately naming the variables, rather
than hanging on a prompt no cron job can answer.

**Nightly backups:**

```cron
0 2 * * *  cd /path/to/toolkit && python3 cli.py backup --targets all --git >> logs/backup.cron.log 2>&1
```

---

## Talking to Extreme gear

VOSS and ERS are not "open an SSH session and send commands", and the failures
from treating them that way look like something else entirely.
`core/connection.py` handles all of it once, for every tool:

- **The ERS Ctrl-Y login gate.** ERS/BOSS gate the CLI behind `Enter Ctrl-Y to
  begin`, and many units stay *silent* after SSH authentication until they get a
  keystroke. Netmiko's stock handler reads before sending anything, times out,
  and reports `Pattern not detected: '(?:\#|>)'` — which reads like a cipher
  problem and is not one.
- **Legacy SSH algorithms.** Old ERS gear offers only SHA-1 key exchange, CBC
  ciphers and `ssh-rsa`/`ssh-dss` host keys. Those are *appended* to Paramiko's
  preference list, never prepended, so modern devices negotiate exactly what they
  always did. (This is why `requirements.txt` pins `paramiko<4` — v4 dropped
  `ssh-dss`, which the oldest ERS units still present.)
- **Privileged EXEC.** Both platforms log in at `>`, and on VOSS 8.x some `show`
  commands work there and some do not — so a missing `enable` looks like release
  variance. Junos is exempted: it has no enable mode.
- **Verified paging disable.** A live pager stalls long output at `--More--`
  *and* swallows the next command's characters, so one missed paging command
  corrupts the rest of the session. The device's answer is checked, and VOSS gets
  a second spelling if the first is refused.
- **Retries that know the difference.** Authentication failures are never retried
  — that locks the account out on every box at once — and neither are device
  *rejections*, since re-sending a command a release does not implement cannot
  produce a different answer. Only transport failures are, and two consecutive
  ones abandon the session rather than burning a full timeout per remaining
  command.

The approach and the field notes behind it come from
[switch-migrator](https://github.com/timoooonnn-s/switch-migrator).

---

## Where files go

Everything the toolkit writes lives next to the project and is git-ignored. Paths
are anchored to the project root, so running from another directory does not
quietly create a second, empty database.

```
logs/                  per-session SSH and SNMP audit trails
backups/               configuration backups, one directory per device
snapshots/             pre/post change snapshots (JSON)
exports/               CSV and JSON exports from any tool
inventory.json         your devices
snmp_presets.json      your saved SNMP presets
sysnet_vlans.json      the VLAN tracker's database
sysnet_snippets.json   the config snippet library
```

Set `$SYSNET_DATA_DIR` to move all of it elsewhere.

### Project layout

```
main_menu.py              interactive menu
cli.py                    non-interactive entry point
inventory.example.json    copy to inventory.json
core/
  colors.py               ANSI constants, ANSI-safe column padding, banner
  paths.py                every on-disk location
  inventory.py            inventory, credentials, platform maps
  prompts.py              shared target selection
  connection.py           VOSS/ERS-aware SSH session layer
  snmp.py                 SNMP transport (net-snmp + built-in v2c)
  export.py               CSV / JSON export
  dependency_check.py     optional-dependency detection
  audit_logger.py         per-session audit trail
features/
  diagnostics.py          CIDR, TCP, traceroute, SSL, DNS, public IP
  system_health.py        resources, processes, ports, log scanner
  config_tools.py         diff, snippets, diagram, Jinja2, interface parser
  multiping.py            multi-host reachability
  ssh_runner.py           SSH bulk commander
  backup.py               configuration backup
  validator.py            pre/post change validation
  voss_parsers.py         VOSS CLI output parsers
  snmp_assistant.py       SNMP assistant
  snmp_presets.py         SNMP preset library
  napalm_interface.py     NAPALM getters
  rollback.py             rollback generator
  interface_health.py     interface health dashboard
  ip_hardware.py          VLAN tracker, next-IP, bandwidth
tests/                    offline test suite + real VOSS captures
```

---

## Development

```bash
pip install pytest ruff
python3 -m pytest          # 188 tests, ~3s
ruff check .
```

The suite runs **entirely offline**: no switch, no network, no `fping`, no
net-snmp.

- The VOSS fixtures in `tests/fixtures/voss/` are real captured command output,
  so a parser change that would break against a live switch breaks here first.
- The SNMP engine is driven end to end against a real UDP socket —
  `tests/fake_agent.py` is a small agent that speaks the actual wire protocol, so
  a broken encoder fails instead of agreeing with a mock.

**Not verified against real gear:** the net-snmp command-line path (no binaries
in CI) and the SSH session layer (no switch in CI). Both are tested at their
parsers against captured output.
