"""
features/voss_parsers.py
------------------------
Parsers for VOSS / Fabric Engine (ex-Avaya VSP) CLI output.

Written against real captures from VOSS 8.x–9.4.x (see
``tests/fixtures/voss/``).  Every parser here is deliberately tolerant and
**anchors on stable tokens** — port ids, integer VLAN ids, up/down keywords —
rather than on character offsets, because VOSS shifts its column layout
between releases and blanks columns for ports with no media.  The one
deliberate exception is ``parse_lldp_summary``, which derives its offsets
*from the header line at runtime* precisely so that an empty SYSNAME cell
cannot be filled in from the neighbouring column's text.

Two things every parser has to survive:

  * a ``Command Execution Time:`` banner framed by 84-character rules, printed
    before the actual output;
  * ``All N out of M Total Num of ... displayed`` footers, one per sub-table,
    whose first token is sometimes a bare number and therefore looks like a
    data row.

Consumed by features/validator.py to build pre- and post-change snapshots.
"""

from __future__ import annotations

import re

# 1/1  1/1/1 (VSP channelized)  49  2/49 (stack)
PORT_RE = re.compile(r"^\d+(?:/\d+){0,2}$")

# Port lists as they appear in member columns: 1/1-1/2, 1/47,1/48, 49-50
PORT_LIST_RE = re.compile(r"^\d+(?:/\d+){0,2}(?:[,\-]\d+(?:/\d+){0,2})*$")

_UPDOWN_TOKEN = re.compile(r"^(up|down|testing)$", re.IGNORECASE)

_VLAN_TYPES = ("byport", "byprotocolid", "bysrcmac", "byipsubnet", "byids")

_MLT_TYPES  = ("access", "trunk")
_MLT_STATES = ("norm", "smlt", "ist")

# 'All 5 out of 5 Total Num of Vlans displayed' / '5 out of 5 Total Num ...'
_FOOTER_RE = re.compile(r"\bout of\b.*\bdisplayed\b", re.IGNORECASE)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_noise(line: str) -> bool:
    """True for banner rules, separators, footers and blank lines."""
    stripped = line.strip()
    if not stripped:
        return True
    if set(stripped) <= set("=-*"):          # ==== / ---- / **** rules
        return True
    return bool(_FOOTER_RE.search(stripped))


def expand_port_list(raw: str) -> list[str]:
    """
    Expand '1/1-1/3,1/10' -> ['1/1', '1/2', '1/3', '1/10'].

    Ranges expand only within the last element (the port number).  A range
    that crosses slots or units is kept as its two endpoints rather than
    guessed, because slot population differs per chassis.
    """
    ports: list[str] = []
    raw = (raw or "").strip()
    if not raw or raw.upper() == "NONE" or not PORT_LIST_RE.match(raw):
        return ports

    for chunk in raw.split(","):
        if "-" not in chunk:
            ports.append(chunk)
            continue
        start, end = chunk.split("-", 1)
        s_parts, e_parts = start.split("/"), end.split("/")
        same_prefix = (
            len(s_parts) == len(e_parts)
            and s_parts[:-1] == e_parts[:-1]
            and s_parts[-1].isdigit()
            and e_parts[-1].isdigit()
        )
        if not same_prefix:
            ports.extend([start, end])
            continue
        prefix = "/".join(s_parts[:-1])
        first, last = int(s_parts[-1]), int(e_parts[-1])
        if last < first:
            first, last = last, first
        for num in range(first, last + 1):
            ports.append(f"{prefix}/{num}" if prefix else str(num))
    return ports


def _updown(token: str) -> str:
    """Normalise an ADMINSTATUS / PORTSTATE token to 'up' / 'down'."""
    return token.strip().lower()


# ---------------------------------------------------------------------------
# show interfaces gigabitEthernet state
# ---------------------------------------------------------------------------

def parse_port_state(output: str) -> dict[str, dict[str, str]]:
    """
    ``show interfaces gigabitEthernet state`` -> {port: {admin, oper, reason}}.

    Layout::

        PORT NUM   ADMINSTATUS  PORTSTATE   REASON        DATE
        1/1        up           up          --            03/08/26 08:13:38
        1/48       down         down        SSH           05/13/26 15:54:53

    ADMINSTATUS and PORTSTATE are the first two up/down/testing tokens after
    the port id.  REASON is free text ('--', 'SSH', …) and is captured as-is
    because it is what explains *why* a port went down between two snapshots.
    """
    ports: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        if _is_noise(line):
            continue
        tokens = line.split()
        if not tokens or not PORT_RE.match(tokens[0]) or tokens[0] in ports:
            continue
        rest   = tokens[1:]
        states: list[str]  = []
        second_at: int | None = None
        for i, token in enumerate(rest):
            if _UPDOWN_TOKEN.match(token):
                states.append(token)
                if len(states) == 2:
                    second_at = i
                    break
        if second_at is None:
            continue
        # REASON is the token following PORTSTATE, when the line carries one.
        reason = rest[second_at + 1] if len(rest) > second_at + 1 else ""
        ports[tokens[0]] = {
            "admin":  _updown(states[0]),
            "oper":   _updown(states[1]),
            "reason": reason,
        }
    return ports


# ---------------------------------------------------------------------------
# show vlan basic
# ---------------------------------------------------------------------------

def parse_vlan_basic(output: str) -> dict[str, dict[str, str]]:
    """
    ``show vlan basic`` -> {vlan_id: {name, type}}.

    Data rows are recognised by carrying a VLAN TYPE token (byPort,
    byProtocolId, …), which no banner, separator or footer line ever does.
    """
    vlans: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        if _is_noise(line):
            continue
        tokens = line.split()
        if len(tokens) < 3 or not tokens[0].isdigit():
            continue
        vlan_id = int(tokens[0])
        if not 1 <= vlan_id <= 4094:
            continue
        vlan_type = next(
            (t for t in tokens[1:] if t.lower() in _VLAN_TYPES), ""
        )
        if not vlan_type:
            continue
        name = tokens[1] if tokens[1].lower() not in _VLAN_TYPES else ""
        vlans[str(vlan_id)] = {"name": name, "type": vlan_type}
    return vlans


# ---------------------------------------------------------------------------
# show vlan i-sid
# ---------------------------------------------------------------------------

def parse_vlan_isid(output: str) -> dict[str, dict[str, str]]:
    """
    ``show vlan i-sid`` -> {vlan_id: {isid, isid_name}}.

    Layout::

        VLAN_ID    I-SID                I-SID NAME
        1
        100        10100                Server-VLAN-100
        200        10200
        4000

    Three shapes on purpose: a VLAN with no I-SID prints its id alone, an
    I-SID with no name prints two columns, a named one prints three.  The
    ``5 out of 5 Total Num of Vlans displayed`` footer also starts with a bare
    number, so it is filtered before the digit check rather than after.
    """
    vlans: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        if _is_noise(line):
            continue
        tokens = line.split()
        if not tokens or not tokens[0].isdigit():
            continue
        vlan_id = int(tokens[0])
        if not 1 <= vlan_id <= 4094:
            continue

        if len(tokens) == 1:
            vlans[str(vlan_id)] = {"isid": "", "isid_name": ""}
            continue
        if not tokens[1].isdigit():          # not an I-SID column: not a data row
            continue
        vlans[str(vlan_id)] = {
            "isid":      tokens[1],
            "isid_name": " ".join(tokens[2:]),
        }
    return vlans


# ---------------------------------------------------------------------------
# show vlan members
# ---------------------------------------------------------------------------

def parse_vlan_members(output: str) -> dict[str, dict[str, list[str]]]:
    """
    ``show vlan members`` -> {vlan_id: {port_members, active_members}}.

    Layout::

        VLAN     PORT             ACTIVE           STATIC           NOT_ALLOW
        ID       MEMBER           MEMBER           MEMBER           MEMBER
        1        NONE             NONE             NONE             NONE
        100      1/1-1/2,2/1/1    1/1,2/1/1        1/1-1/2,2/1/1

    ACTIVE MEMBER is the column that matters for a change window: a port that
    silently left a VLAN's active set is exactly what a post-change check is
    looking for.  Trailing columns are often absent, so only what is present
    is read.
    """
    vlans: dict[str, dict[str, list[str]]] = {}
    for line in output.splitlines():
        if _is_noise(line):
            continue
        tokens = line.split()
        if len(tokens) < 2 or not tokens[0].isdigit():
            continue
        vlan_id = int(tokens[0])
        if not 1 <= vlan_id <= 4094:
            continue
        if tokens[1].upper() != "NONE" and not PORT_LIST_RE.match(tokens[1]):
            continue
        columns = tokens[1:]
        vlans[str(vlan_id)] = {
            "port_members":   expand_port_list(columns[0]),
            "active_members": expand_port_list(columns[1]) if len(columns) > 1 else [],
        }
    return vlans


# ---------------------------------------------------------------------------
# show mlt
# ---------------------------------------------------------------------------

def parse_mlt(output: str) -> dict[str, dict]:
    """
    ``show mlt`` -> {mlt_id: {name, type, members, vlans}}.

    The bare command prints four tables (Mlt Info, LACP, data-path members,
    ENCAP) plus a footer after each, and the trailing VLAN IDS column wraps
    onto continuation lines for long VLAN lists.  Only the first table carries
    what a change check needs, so a row is accepted only when it shows a TYPE
    (access/trunk) or an ADMIN/CURRENT state (norm/smlt/ist) token — which the
    other tables, the footers and the wrapped continuation lines never do —
    and each MLT id is kept once (Mlt Info comes first, so first wins).
    """
    mlts: dict[str, dict] = {}
    current: dict | None = None      # last Mlt Info row, for VLAN continuations

    for line in output.splitlines():
        if _is_noise(line):
            current = None
            continue
        tokens = line.split()

        # A line of bare VLAN ids continues the previous row's VLAN IDS column.
        if (current is not None and tokens
                and all(t.isdigit() and 1 <= int(t) <= 4094 for t in tokens)):
            for token in tokens:
                if int(token) not in current["vlans"]:
                    current["vlans"].append(int(token))
            continue
        current = None

        if len(tokens) < 3 or not tokens[0].isdigit():
            continue
        mlt_id = tokens[0]
        rest   = tokens[1:]
        if rest and rest[0].isdigit():       # optional IFINDEX column
            rest = rest[1:]
        if not rest:
            continue

        mlt_type = next((t for t in rest if t.lower() in _MLT_TYPES), "")
        states   = [t for t in rest if t.lower() in _MLT_STATES]
        if (not mlt_type and not states) or mlt_id in mlts:
            continue

        name = rest[0]
        members: list[str] = []
        members_at: int | None = None
        for i, token in enumerate(rest[1:], start=1):
            if "/" in token and PORT_LIST_RE.match(token):
                members    = expand_port_list(token)
                members_at = i
                break

        vlans = (
            [int(t) for t in rest[members_at + 1:]
             if t.isdigit() and 1 <= int(t) <= 4094]
            if members_at is not None else []
        )
        mlts[mlt_id] = {
            "name":    name,
            "type":    mlt_type,
            "members": members,
            "vlans":   vlans,
        }
        current = mlts[mlt_id]
    return mlts


# ---------------------------------------------------------------------------
# show lldp neighbor summary
# ---------------------------------------------------------------------------

def _clean_ip(value: str) -> str:
    """Return a usable neighbour IP, or '' for placeholders ('--', 0.0.0.0)."""
    text = value.strip()
    if not text or text in ("-", "--"):
        return ""
    if _IPV4_RE.match(text):
        return "" if text == "0.0.0.0" else text
    if ":" in text and re.fullmatch(r"[0-9a-fA-F:]+", text):
        return "" if not any(part.strip("0") for part in text.split(":")) else text
    return ""


def _header_columns(header: str) -> dict[str, tuple[int, int | None]]:
    """
    Map column names to (start, end) character offsets within a header line.

    Each column runs from its own header word to the start of the next, so a
    blank cell stays blank instead of borrowing the neighbouring column's
    text.  'PORT' appears twice on the LLDP summary header: the first is the
    LOCAL PORT the data row starts with, the second the REMOTE PORT.
    """
    words  = [(m.group(), m.start()) for m in re.finditer(r"\S+", header)]
    starts = sorted(start for _, start in words)

    def bound(name: str, occurrence: int = 0) -> tuple[int, int | None]:
        seen = 0
        for word, start in words:
            if word.upper() != name:
                continue
            if seen == occurrence:
                after = [s for s in starts if s > start]
                return start, (min(after) if after else None)
            seen += 1
        return -1, None

    return {
        "ADDR":        bound("ADDR"),
        "REMOTE_PORT": bound("PORT", occurrence=1),
        "SYSNAME":     bound("SYSNAME"),
        "SYSDESCR":    bound("SYSDESCR"),
    }


def _cell(line: str, columns: dict[str, tuple[int, int | None]], name: str) -> str:
    """Slice one column out of a fixed-width data row."""
    start, end = columns.get(name, (-1, None))
    if start < 0:
        return ""
    return (line[start:end] if end is not None else line[start:]).strip()


def parse_lldp_summary(output: str) -> dict[str, dict[str, str]]:
    """
    ``show lldp neighbor summary`` -> {local_port: {sysname, ip, remote_port}}.

    This is the one fixed-width table in the set, and it has to be cut by
    character offset rather than by token: a neighbour that advertises no
    SYSNAME (an iLO card, say) leaves that cell blank, and splitting on
    whitespace would silently shift SYSDESCR text into it.  The offsets are
    taken from the header line that carries SYSNAME, so the layout is read
    from the device at runtime instead of hard-coded per release.
    """
    neighbours: dict[str, dict[str, str]] = {}
    columns: dict[str, tuple[int, int | None]] | None = None

    for line in output.splitlines():
        if columns is None:
            if re.search(r"sysname", line, re.IGNORECASE):
                columns = _header_columns(line)
            continue

        tokens = line.split()
        if not tokens or not PORT_RE.match(tokens[0]) or tokens[0] in neighbours:
            continue

        sysname_cell = _cell(line, columns, "SYSNAME")
        # REMOTE PORT is not always a port id — a server NIC advertises free
        # text like 'Embedded ALOM, Po~' — so the cell is kept verbatim.
        neighbours[tokens[0]] = {
            "sysname":     sysname_cell.split()[0] if sysname_cell else "",
            "ip":          _clean_ip(_cell(line, columns, "ADDR")),
            "remote_port": _cell(line, columns, "REMOTE_PORT"),
        }
    return neighbours


# ---------------------------------------------------------------------------
# show interfaces gigabitEthernet i-sid
# ---------------------------------------------------------------------------

def parse_port_isid(output: str) -> dict[str, dict[str, str]]:
    """
    ``show interfaces gigabitEthernet i-sid`` -> {port: {isid, vlan, type}}.

    Catches flex-UNI / switched-UNI services, which do not appear in
    ``show vlan i-sid`` at all.  Layout::

        PORTNUM IFINDEX ISID_ID  VLANID C-VID  TYPE   ORIGIN ...
        1/1     192     10100    100    N/A    ELAN   C  ---  -  ...

    The ORIGIN column is a run of flag characters, so only the columns before
    it are read positionally; everything after is ignored.
    """
    ports: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        if _is_noise(line):
            continue
        tokens = line.split()
        if len(tokens) < 4 or not PORT_RE.match(tokens[0]) or tokens[0] in ports:
            continue
        # PORTNUM IFINDEX ISID VLANID
        if not (tokens[1].isdigit() and tokens[2].isdigit()):
            continue
        vlan = tokens[3] if tokens[3].isdigit() else ""
        isid_type = next(
            (t for t in tokens[4:] if t.upper() in ("ELAN", "CVLAN", "ELINE", "TRANSPARENT")),
            "",
        )
        ports[tokens[0]] = {
            "isid": tokens[2],
            "vlan": vlan,
            "type": isid_type,
        }
    return ports


# ---------------------------------------------------------------------------
# show virtual-ist
# ---------------------------------------------------------------------------

def parse_ist(output: str) -> dict[str, str]:
    """
    ``show virtual-ist`` -> {peer_ip, vlan, enabled, status}.

    Returns an empty dict on a box with no vIST configured — that is an
    ordinary access switch, not a failure, so the caller reports absence
    rather than an error.  The command is also rejected outright on
    non-vIST-capable releases, which the caller treats the same way.
    """
    for line in output.splitlines():
        if _is_noise(line):
            continue
        tokens = line.split()
        if len(tokens) < 4 or not _IPV4_RE.match(tokens[0]):
            continue
        if not tokens[1].isdigit():
            continue
        return {
            "peer_ip": tokens[0],
            "vlan":    tokens[1],
            "enabled": tokens[2].lower(),
            "status":  tokens[3].lower(),
        }
    return {}
