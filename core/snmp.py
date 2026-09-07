"""
core/snmp.py
------------
The SNMP transport layer — one interface, two engines.

Why two engines
---------------
SNMPv3 is not a protocol you hand-roll on a deadline: USM engine discovery,
HMAC authentication and AES privacy are a lot of security-critical code that
cannot be verified without real gear.  net-snmp already does it correctly and
is on every network engineer's jump host, so when ``snmpget`` and friends are
on PATH they are used for everything, v1 through v3.

But requiring an external binary for a *read* would make the toolkit useless
on a locked-down box, and the v2c wire format is small enough to implement
honestly.  So there is also a built-in engine: pure standard library, BER
encode and decode, covering GET / GETNEXT / SET / WALK over SNMPv2c.  It is
what runs when net-snmp is missing.

    net-snmp present  ->  v1, v2c, v3 (auth + priv)
    net-snmp absent   ->  v2c only, built in; v3 fails with a clear message

Both engines return the same VarBind rows, so callers never branch on which
one ran.  This mirrors the fping/ping split in features/multiping.py.

Usage
-----
    from core.snmp import SnmpCredentials, snmp_get, snmp_walk, snmp_set

    creds  = SnmpCredentials(version="2c", community="public")
    result = snmp_get("10.0.0.1", ["1.3.6.1.2.1.1.5.0"], creds)
    if result.ok:
        print(result.varbinds[0].value)

Security note
-------------
Community strings and v3 keys are passed to net-snmp as argv, which is
visible in the process list to other users on the same host.  That is a
property of net-snmp itself, not of this wrapper; the built-in engine does
not have the issue.  Nothing here ever prints or logs a credential.
"""

from __future__ import annotations

import os
import random
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Any

DEFAULT_PORT      = 161
DEFAULT_TIMEOUT_S = 3
DEFAULT_RETRIES   = 1

# Rows per GETBULK request, for net-snmp's bulkwalk.  The built-in engine
# walks with a GETNEXT loop instead and ignores this.
BULK_REPETITIONS  = 25

# A walk has to stop somewhere: a device that answers GETNEXT in a loop (a
# buggy agent, or a table that grows while it is read) would otherwise spin
# forever.  Raise it for genuinely huge tables such as a full FDB.
MAX_WALK_ROWS = 10_000


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

@dataclass
class SnmpCredentials:
    """
    Everything needed to authenticate one SNMP conversation.

    Only *version* and the fields that version uses are ever read, so a v2c
    credential does not need the v3 fields filled in and vice versa.
    """
    version:        str = "2c"        # "1" | "2c" | "3"
    community:      str = ""          # v1 / v2c
    user:           str = ""          # v3
    auth_protocol:  str = ""          # v3: MD5 | SHA | SHA-224 | SHA-256 | ...
    auth_key:       str = ""
    priv_protocol:  str = ""          # v3: DES | AES | AES-192 | AES-256
    priv_key:       str = ""
    port:           int = DEFAULT_PORT
    timeout_s:      int = DEFAULT_TIMEOUT_S
    retries:        int = DEFAULT_RETRIES

    @property
    def security_level(self) -> str:
        """v3 security level, derived from which keys are actually set."""
        if self.auth_key and self.priv_key:
            return "authPriv"
        if self.auth_key:
            return "authNoPriv"
        return "noAuthNoPriv"

    def validate(self) -> str:
        """Return an error message if these credentials cannot be used."""
        if self.version not in ("1", "2c", "3"):
            return f"unsupported SNMP version '{self.version}' (use 1, 2c or 3)"
        if self.version in ("1", "2c") and not self.community:
            return f"SNMPv{self.version} needs a community string"
        if self.version == "3":
            if not self.user:
                return "SNMPv3 needs a security user name"
            if self.priv_key and not self.auth_key:
                return "SNMPv3 privacy requires authentication as well"
        return ""

    def redacted(self) -> str:
        """A one-line description safe to print or log."""
        if self.version == "3":
            return (f"v3 user={self.user} level={self.security_level} "
                    f"auth={self.auth_protocol or '-'} priv={self.priv_protocol or '-'}")
        return f"v{self.version} community=<hidden>"


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass
class VarBind:
    """One OID and its value, normalised across both engines."""
    oid:   str
    type:  str      # STRING, INTEGER, Counter32, Timeticks, OID, IpAddress, ...
    value: Any

    def as_row(self) -> dict[str, Any]:
        return {"oid": self.oid, "type": self.type, "value": self.value}


@dataclass
class SnmpResult:
    """The outcome of one SNMP operation."""
    ok:       bool
    varbinds: list[VarBind] = field(default_factory=list)
    error:    str = ""
    engine:   str = ""

    def rows(self) -> list[dict[str, Any]]:
        return [vb.as_row() for vb in self.varbinds]


class SnmpError(Exception):
    """Raised for a caller mistake — bad credentials, a malformed OID."""


# ---------------------------------------------------------------------------
# BER primitives (built-in engine)
# ---------------------------------------------------------------------------

# Universal tags
_T_INTEGER   = 0x02
_T_OCTETSTR  = 0x04
_T_NULL      = 0x05
_T_OID       = 0x06
_T_SEQUENCE  = 0x30

# Application tags
_T_IPADDRESS = 0x40
_T_COUNTER32 = 0x41
_T_GAUGE32   = 0x42
_T_TIMETICKS = 0x43
_T_OPAQUE    = 0x44
_T_COUNTER64 = 0x46

# Context tags — exception values that replace a varbind's value in v2c
_T_NOSUCHOBJECT   = 0x80
_T_NOSUCHINSTANCE = 0x81
_T_ENDOFMIBVIEW   = 0x82

# PDU tags
_PDU_GET     = 0xA0
_PDU_GETNEXT = 0xA1
_PDU_RESPONSE = 0xA2
_PDU_SET     = 0xA3

_TYPE_NAMES = {
    _T_INTEGER:   "INTEGER",
    _T_OCTETSTR:  "STRING",
    _T_NULL:      "NULL",
    _T_OID:       "OID",
    _T_IPADDRESS: "IpAddress",
    _T_COUNTER32: "Counter32",
    _T_GAUGE32:   "Gauge32",
    _T_TIMETICKS: "Timeticks",
    _T_OPAQUE:    "Opaque",
    _T_COUNTER64: "Counter64",
}

# RFC 3416 error-status values, in the wording an operator needs.
_ERROR_STATUS = {
    0:  "",
    1:  "tooBig — the response would not fit in one packet",
    2:  "noSuchName — the agent does not implement that OID",
    3:  "badValue — the agent rejected the value's type or form",
    4:  "readOnly — that object is not writable",
    5:  "genErr — the agent hit a general error",
    6:  "noAccess — the community/user has no access to that object",
    7:  "wrongType — wrong value type for that object",
    8:  "wrongLength — value is the wrong length",
    9:  "wrongEncoding — value is encoded wrongly",
    10: "wrongValue — that value is not allowed for this object",
    11: "noCreation — that row cannot be created",
    12: "inconsistentValue — the value conflicts with the device's state",
    13: "resourceUnavailable — the agent could not allocate resources",
    14: "commitFailed — the write was attempted and failed",
    15: "undoFailed — the write failed AND could not be rolled back",
    16: "authorizationError — not authorised (check the write community)",
    17: "notWritable — that object is not writable",
    18: "inconsistentName — that row name is inconsistent",
}


def _encode_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    body = []
    while length:
        body.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(body)] + body)


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(payload)) + payload


def _encode_int_bytes(value: int) -> bytes:
    """Minimal two's-complement encoding, the way BER wants integers."""
    if value == 0:
        return b"\x00"
    length = max(1, (value.bit_length() + 8) // 8)
    while True:
        try:
            return value.to_bytes(length, "big", signed=True)
        except OverflowError:
            length += 1


def _base128(number: int) -> bytes:
    """Encode one OID sub-identifier with continuation bits."""
    if number < 128:
        return bytes([number])
    chunks: list[int] = []
    while number:
        chunks.insert(0, (number & 0x7F) | 0x80)
        number >>= 7
    chunks[-1] &= 0x7F
    return bytes(chunks)


def encode_oid(oid: str) -> bytes:
    """
    Encode a dotted OID string.

    The first two arcs share one sub-identifier as 40*a + b — which is why
    the LLDP tree (1.0.8802...) encodes its leading '1.0' as a single 40.
    """
    try:
        parts = [int(p) for p in oid.strip().strip(".").split(".")]
    except ValueError as exc:
        raise SnmpError(f"malformed OID '{oid}'") from exc
    if len(parts) < 2:
        raise SnmpError(f"OID '{oid}' is too short to encode")
    if any(p < 0 for p in parts):
        raise SnmpError(f"OID '{oid}' has a negative arc")

    out = bytearray(_base128(parts[0] * 40 + parts[1]))
    for part in parts[2:]:
        out += _base128(part)
    return bytes(out)


def decode_oid(data: bytes) -> str:
    """
    Decode an OID body back to a dotted string.

    Every sub-identifier is decoded first, then the leading one is split.
    Doing the split on the raw first *byte* is the classic bug: it breaks for
    the 2.x arcs, where the combined value exceeds one byte.
    """
    subs: list[int] = []
    current = 0
    for byte in data:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            subs.append(current)
            current = 0
    if not subs:
        return ""

    first = subs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(p) for p in head + subs[1:])


def _read_tlv(data: bytes, index: int) -> tuple[int, bytes, int]:
    """Return (tag, value_bytes, next_index) for the TLV starting at *index*."""
    if index >= len(data):
        raise SnmpError("truncated SNMP message")
    tag = data[index]
    index += 1
    if index >= len(data):
        raise SnmpError("truncated SNMP length")

    first = data[index]
    index += 1
    if first < 128:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or index + count > len(data):
            raise SnmpError("unsupported or truncated SNMP length")
        length = int.from_bytes(data[index:index + count], "big")
        index += count

    if index + length > len(data):
        raise SnmpError("SNMP value runs past the end of the message")
    return tag, data[index:index + length], index + length


def _decode_value(tag: int, body: bytes) -> tuple[str, Any]:
    """Turn one varbind value TLV into (type name, Python value)."""
    if tag == _T_INTEGER:
        return "INTEGER", int.from_bytes(body, "big", signed=True)
    if tag in (_T_COUNTER32, _T_GAUGE32, _T_TIMETICKS, _T_COUNTER64):
        return _TYPE_NAMES[tag], int.from_bytes(body, "big", signed=False)
    if tag == _T_OCTETSTR:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            # Binary payloads (a MAC address in ifPhysAddress, say) are shown
            # the way net-snmp shows them, so both engines agree.
            return "Hex-STRING", " ".join(f"{b:02X}" for b in body)
        if any(ord(c) < 32 and c not in "\t\n\r" for c in text):
            return "Hex-STRING", " ".join(f"{b:02X}" for b in body)
        return "STRING", text
    if tag == _T_IPADDRESS:
        return "IpAddress", ".".join(str(b) for b in body) if len(body) == 4 else ""
    if tag == _T_OID:
        return "OID", decode_oid(body)
    if tag == _T_NULL:
        return "NULL", None
    if tag == _T_NOSUCHOBJECT:
        return "NoSuchObject", None
    if tag == _T_NOSUCHINSTANCE:
        return "NoSuchInstance", None
    if tag == _T_ENDOFMIBVIEW:
        return "EndOfMibView", None
    return f"Unknown(0x{tag:02X})", body.hex()


# --- SET value encoding -----------------------------------------------------

# The single-letter type codes net-snmp's snmpset uses, so a preset written
# for one engine works on the other unchanged.
SET_TYPE_CODES = {
    "i": "INTEGER",
    "u": "Gauge32/Unsigned32",
    "s": "STRING",
    "x": "Hex STRING",
    "a": "IpAddress",
    "o": "OID",
    "t": "TimeTicks",
    "c": "Counter32",
}


def encode_set_value(type_code: str, value: str) -> bytes:
    """Encode a SET payload from a net-snmp style type code plus text value."""
    code = (type_code or "").strip().lower()
    text = str(value)

    if code == "i":
        return _tlv(_T_INTEGER, _encode_int_bytes(int(text)))
    if code == "u":
        return _tlv(_T_GAUGE32, _encode_int_bytes(int(text)))
    if code == "c":
        return _tlv(_T_COUNTER32, _encode_int_bytes(int(text)))
    if code == "t":
        return _tlv(_T_TIMETICKS, _encode_int_bytes(int(text)))
    if code == "s":
        return _tlv(_T_OCTETSTR, text.encode("utf-8"))
    if code == "x":
        cleaned = re.sub(r"[^0-9a-fA-F]", "", text)
        if len(cleaned) % 2:
            raise SnmpError(f"hex value '{value}' has an odd number of digits")
        return _tlv(_T_OCTETSTR, bytes.fromhex(cleaned))
    if code == "a":
        octets = text.split(".")
        if len(octets) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            raise SnmpError(f"'{value}' is not an IPv4 address")
        return _tlv(_T_IPADDRESS, bytes(int(o) for o in octets))
    if code == "o":
        return _tlv(_T_OID, encode_oid(text))

    raise SnmpError(
        f"unknown SET type '{type_code}'. Use one of: "
        + ", ".join(f"{k} ({v})" for k, v in SET_TYPE_CODES.items())
    )


# ---------------------------------------------------------------------------
# Built-in engine — SNMPv2c over UDP
# ---------------------------------------------------------------------------

def _build_message(
    community: str,
    pdu_tag: int,
    varbinds: list[tuple[str, bytes]],
    request_id: int,
) -> bytes:
    """Assemble a complete SNMPv2c message."""
    encoded = b""
    for oid, value_tlv in varbinds:
        encoded += _tlv(_T_SEQUENCE, _tlv(_T_OID, encode_oid(oid)) + value_tlv)
    varbind_list = _tlv(_T_SEQUENCE, encoded)

    pdu_body = (
        _tlv(_T_INTEGER, _encode_int_bytes(request_id))
        + _tlv(_T_INTEGER, b"\x00")      # error-status
        + _tlv(_T_INTEGER, b"\x00")      # error-index
        + varbind_list
    )
    pdu = _tlv(pdu_tag, pdu_body)

    message = (
        _tlv(_T_INTEGER, b"\x01")        # version 1 == SNMPv2c
        + _tlv(_T_OCTETSTR, community.encode("utf-8"))
        + pdu
    )
    return _tlv(_T_SEQUENCE, message)


def _parse_response(data: bytes, request_id: int) -> SnmpResult:
    """Decode a response message into varbinds, or into an agent error."""
    tag, body, _ = _read_tlv(data, 0)
    if tag != _T_SEQUENCE:
        return SnmpResult(False, error="reply is not an SNMP message",
                          engine="builtin")

    index = 0
    _, _version, index = _read_tlv(body, index)     # version
    _, _community, index = _read_tlv(body, index)   # community
    pdu_tag, pdu, _ = _read_tlv(body, index)
    if pdu_tag != _PDU_RESPONSE:
        return SnmpResult(False, error=f"unexpected PDU type 0x{pdu_tag:02X}",
                          engine="builtin")

    index = 0
    _, rid_bytes, index = _read_tlv(pdu, index)
    _, status_bytes, index = _read_tlv(pdu, index)
    _, idx_bytes, index = _read_tlv(pdu, index)
    _, varbind_list, _ = _read_tlv(pdu, index)

    reply_id = int.from_bytes(rid_bytes, "big", signed=True)
    if reply_id != request_id:
        # A stale datagram from an earlier, timed-out request. Treating it as
        # this request's answer would attribute one OID's value to another.
        return SnmpResult(False, engine="builtin",
                          error="reply carried a different request id "
                                "(stale packet) — retry")

    status = int.from_bytes(status_bytes, "big", signed=True)
    if status:
        error_index = int.from_bytes(idx_bytes, "big", signed=True)
        detail = _ERROR_STATUS.get(status, f"error-status {status}")
        return SnmpResult(False, engine="builtin",
                          error=f"agent returned {detail}"
                                + (f" (varbind {error_index})" if error_index else ""))

    varbinds: list[VarBind] = []
    index = 0
    while index < len(varbind_list):
        _, pair, index = _read_tlv(varbind_list, index)
        inner = 0
        _, oid_bytes, inner = _read_tlv(pair, inner)
        value_tag, value_bytes, _ = _read_tlv(pair, inner)
        type_name, value = _decode_value(value_tag, value_bytes)
        varbinds.append(VarBind(decode_oid(oid_bytes), type_name, value))

    return SnmpResult(True, varbinds=varbinds, engine="builtin")


def _builtin_request(
    host: str,
    creds: SnmpCredentials,
    pdu_tag: int,
    varbinds: list[tuple[str, bytes]],
) -> SnmpResult:
    """Send one PDU and wait for its answer, retrying on timeout."""
    last_error = "no reply"
    for _attempt in range(max(1, creds.retries + 1)):
        request_id = random.randint(1, 0x7FFFFFFF)
        try:
            packet = _build_message(creds.community, pdu_tag, varbinds, request_id)
        except SnmpError as exc:
            return SnmpResult(False, error=str(exc), engine="builtin")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(creds.timeout_s)
        try:
            sock.sendto(packet, (host, creds.port))
            reply, _ = sock.recvfrom(65535)
        except TimeoutError:
            last_error = (f"no response from {host}:{creds.port} within "
                          f"{creds.timeout_s}s — check the IP, the community "
                          f"string, and whether SNMP is permitted from here")
            continue
        except OSError as exc:
            return SnmpResult(False, error=f"socket error: {exc}", engine="builtin")
        finally:
            sock.close()

        try:
            return _parse_response(reply, request_id)
        except SnmpError as exc:
            last_error = f"could not decode the reply: {exc}"

    return SnmpResult(False, error=last_error, engine="builtin")


# ---------------------------------------------------------------------------
# net-snmp engine
# ---------------------------------------------------------------------------

def have_netsnmp() -> bool:
    """True when the net-snmp command-line tools are on PATH."""
    return shutil.which("snmpget") is not None


# 'OID = TYPE: value'  /  'OID = ""'  /  'OID = No Such Object ...'
_NETSNMP_LINE = re.compile(r"^(?P<oid>[.\d]+)\s*=\s*(?P<rest>.*)$")
_NETSNMP_TYPED = re.compile(r"^(?P<type>[A-Za-z0-9-]+):\s?(?P<value>.*)$", re.DOTALL)
_TIMETICKS_VALUE = re.compile(r"^\((?P<ticks>\d+)\)")


def parse_netsnmp_output(text: str) -> list[VarBind]:
    """
    Parse ``snmpget``/``snmpwalk`` output into VarBinds.

    A STRING value can wrap onto following lines, so a line that does not
    start a new ``OID =`` record is appended to the previous value rather
    than dropped.
    """
    varbinds: list[VarBind] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue

        match = _NETSNMP_LINE.match(line.strip())
        if not match:
            if varbinds and isinstance(varbinds[-1].value, str):
                varbinds[-1].value += "\n" + line
            continue

        oid  = "." + match.group("oid").lstrip(".")
        rest = match.group("rest").strip()

        typed = _NETSNMP_TYPED.match(rest)
        if not typed:
            # Untyped forms: an empty string, or an agent exception.
            if rest in ('""', "''", ""):
                varbinds.append(VarBind(oid, "STRING", ""))
            elif "No Such Object" in rest:
                varbinds.append(VarBind(oid, "NoSuchObject", None))
            elif "No Such Instance" in rest:
                varbinds.append(VarBind(oid, "NoSuchInstance", None))
            elif "No more variables" in rest or "End of MIB" in rest:
                varbinds.append(VarBind(oid, "EndOfMibView", None))
            else:
                varbinds.append(VarBind(oid, "STRING", rest))
            continue

        type_name = typed.group("type")
        value: Any = typed.group("value").strip()

        if type_name in ("INTEGER", "Counter32", "Counter64", "Gauge32", "UInteger32"):
            number = re.match(r"^-?\d+", str(value))
            # INTEGER often reads 'up(1)' for an enum; keep the number.
            enum = re.search(r"\((-?\d+)\)", str(value))
            if enum:
                value = int(enum.group(1))
            elif number:
                value = int(number.group(0))
        elif type_name == "Timeticks":
            ticks = _TIMETICKS_VALUE.match(str(value))
            if ticks:
                value = int(ticks.group("ticks"))
        elif type_name == "STRING":
            value = str(value).strip('"')

        varbinds.append(VarBind(oid, type_name, value))
    return varbinds


def _netsnmp_auth_args(creds: SnmpCredentials) -> list[str]:
    """Build the version/authentication argv fragment for net-snmp."""
    if creds.version == "3":
        args = ["-v", "3", "-l", creds.security_level, "-u", creds.user]
        if creds.auth_key:
            args += ["-a", creds.auth_protocol or "SHA", "-A", creds.auth_key]
        if creds.priv_key:
            args += ["-x", creds.priv_protocol or "AES", "-X", creds.priv_key]
        return args
    return ["-v", creds.version, "-c", creds.community]


def _run_netsnmp(command: list[str], timeout_s: int) -> tuple[bool, str, str]:
    """Run one net-snmp binary, returning (ok, stdout, stderr)."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(10, timeout_s * 4),
            # net-snmp reads ~/.snmp/snmp.conf, which can silently change
            # output formatting.  A predictable environment keeps the parser
            # honest across machines.
            env={**os.environ, "SNMPCONFPATH": os.environ.get("SNMPCONFPATH", "")},
        )
    except subprocess.TimeoutExpired:
        return False, "", "net-snmp did not finish in time"
    except OSError as exc:
        return False, "", f"could not run {command[0]}: {exc}"
    return completed.returncode == 0, completed.stdout, completed.stderr


def _netsnmp_operation(
    binary: str,
    host: str,
    creds: SnmpCredentials,
    trailing: list[str],
    extra_flags: list[str] | None = None,
) -> SnmpResult:
    """Shared shape for every net-snmp call."""
    if shutil.which(binary) is None:
        return SnmpResult(False, engine="net-snmp",
                          error=f"{binary} is not installed")

    command = [
        binary,
        *_netsnmp_auth_args(creds),
        # -On keeps OIDs numeric so no MIB files are needed; -t/-r match the
        # built-in engine's timeout and retry behaviour.
        "-On",
        "-t", str(creds.timeout_s),
        "-r", str(creds.retries),
        *(extra_flags or []),
        f"{host}:{creds.port}",
        *trailing,
    ]
    ok, stdout, stderr = _run_netsnmp(command, creds.timeout_s)
    varbinds = parse_netsnmp_output(stdout)

    if not ok and not varbinds:
        detail = (stderr or stdout).strip().splitlines()
        return SnmpResult(False, engine="net-snmp",
                          error=detail[0] if detail else f"{binary} failed")
    return SnmpResult(True, varbinds=varbinds, engine="net-snmp")


# ---------------------------------------------------------------------------
# Public API — engine selection lives here and nowhere else
# ---------------------------------------------------------------------------

def _choose_engine(creds: SnmpCredentials, prefer_netsnmp: bool = True) -> str:
    """
    Decide which engine handles this request.

    net-snmp wins when present: it speaks every version and handles types the
    built-in engine does not.  v3 has no fallback at all — hand-rolling USM
    crypto that cannot be verified here would be worse than saying no.
    """
    if prefer_netsnmp and have_netsnmp():
        return "net-snmp"
    if creds.version == "3":
        return "unavailable"
    return "builtin"


def _unavailable() -> SnmpResult:
    return SnmpResult(
        False, engine="none",
        error="SNMPv3 needs the net-snmp tools (snmpget/snmpwalk/snmpset). "
              "Install them (Debian/Ubuntu: apt install snmp; macOS: brew "
              "install net-snmp) or use SNMPv2c, which is built in.",
    )


def snmp_get(
    host: str,
    oids: list[str],
    creds: SnmpCredentials,
    prefer_netsnmp: bool = True,
) -> SnmpResult:
    """GET one or more OIDs in a single request."""
    problem = creds.validate()
    if problem:
        return SnmpResult(False, error=problem)
    if not oids:
        return SnmpResult(False, error="no OID given")

    engine = _choose_engine(creds, prefer_netsnmp)
    if engine == "unavailable":
        return _unavailable()
    if engine == "net-snmp":
        return _netsnmp_operation("snmpget", host, creds,
                                  [_normalise_oid(o) for o in oids])

    return _builtin_request(
        host, creds, _PDU_GET,
        [(_normalise_oid(o), _tlv(_T_NULL, b"")) for o in oids],
    )


def snmp_walk(
    host: str,
    root: str,
    creds: SnmpCredentials,
    prefer_netsnmp: bool = True,
    max_rows: int = MAX_WALK_ROWS,
) -> SnmpResult:
    """
    Walk the subtree under *root*.

    net-snmp uses bulkwalk for v2c/v3 (far fewer round trips); the built-in
    engine issues a GETNEXT loop, stopping the moment the agent returns an
    OID outside the subtree, an endOfMibView, or an OID that did not advance
    — the three ways a walk turns into an infinite loop.
    """
    problem = creds.validate()
    if problem:
        return SnmpResult(False, error=problem)

    root = _normalise_oid(root)
    engine = _choose_engine(creds, prefer_netsnmp)
    if engine == "unavailable":
        return _unavailable()

    if engine == "net-snmp":
        binary = "snmpwalk" if creds.version == "1" else "snmpbulkwalk"
        if shutil.which(binary) is None:
            binary = "snmpwalk"
        flags = [] if binary == "snmpwalk" else ["-Cr", str(BULK_REPETITIONS)]
        return _netsnmp_operation(binary, host, creds, [root], extra_flags=flags)

    collected: list[VarBind] = []
    current = root
    prefix = root.rstrip(".") + "."
    while len(collected) < max_rows:
        step = _builtin_request(
            host, creds, _PDU_GETNEXT,
            [(current, _tlv(_T_NULL, b""))],
        )
        if not step.ok:
            if collected:
                # Partial data plus the reason beats throwing the walk away.
                return SnmpResult(True, varbinds=collected, engine="builtin",
                                  error=step.error)
            return step
        if not step.varbinds:
            break

        varbind = step.varbinds[0]
        if varbind.type in ("EndOfMibView", "NoSuchObject", "NoSuchInstance"):
            break
        if not (varbind.oid == root or varbind.oid.startswith(prefix)):
            break            # walked out of the subtree
        if varbind.oid == current:
            break            # agent is not advancing; stop rather than spin

        collected.append(varbind)
        current = varbind.oid

    return SnmpResult(True, varbinds=collected, engine="builtin")


def snmp_set(
    host: str,
    oid: str,
    type_code: str,
    value: str,
    creds: SnmpCredentials,
    prefer_netsnmp: bool = True,
) -> SnmpResult:
    """
    SET one OID.

    Callers are expected to have confirmed the write with the operator
    already — this function does no asking of its own.
    """
    problem = creds.validate()
    if problem:
        return SnmpResult(False, error=problem)

    oid = _normalise_oid(oid)
    engine = _choose_engine(creds, prefer_netsnmp)
    if engine == "unavailable":
        return _unavailable()

    if engine == "net-snmp":
        return _netsnmp_operation("snmpset", host, creds,
                                  [oid, type_code, str(value)])

    try:
        payload = encode_set_value(type_code, value)
    except SnmpError as exc:
        return SnmpResult(False, error=str(exc), engine="builtin")
    return _builtin_request(host, creds, _PDU_SET, [(oid, payload)])


def _normalise_oid(oid: str) -> str:
    """Strip a leading dot and surrounding whitespace, keeping digits only."""
    cleaned = (oid or "").strip()
    if not cleaned:
        raise SnmpError("empty OID")
    return cleaned.lstrip(".")


def engine_description() -> str:
    """One line naming the engine that will actually be used, for the UI."""
    if have_netsnmp():
        return "net-snmp (v1/v2c/v3, including auth+priv)"
    return "built-in (SNMPv2c only — install net-snmp for v3)"
