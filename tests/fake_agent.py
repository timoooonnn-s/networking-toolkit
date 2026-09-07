"""
A tiny in-process SNMPv2c agent, for testing without a device.

It speaks the real wire protocol over a real UDP socket on loopback, so the
built-in engine is exercised end to end — encode, send, receive, decode —
rather than against a mock that would happily agree with a broken encoder.

    with FakeAgent({"1.3.6.1.2.1.1.5.0": octet_string("core-01")}) as agent:
        creds = SnmpCredentials(version="2c", community="public",
                                port=agent.port, timeout_s=2)
        result = snmp_get("127.0.0.1", ["1.3.6.1.2.1.1.5.0"], creds,
                          prefer_netsnmp=False)
"""

from __future__ import annotations

import socket
import threading

from core import snmp as S


def octet_string(text: str) -> tuple[int, bytes]:
    return S._T_OCTETSTR, text.encode("utf-8")


def integer(value: int) -> tuple[int, bytes]:
    return S._T_INTEGER, S._encode_int_bytes(value)


def counter64(value: int) -> tuple[int, bytes]:
    return S._T_COUNTER64, value.to_bytes(8, "big")


def timeticks(value: int) -> tuple[int, bytes]:
    return S._T_TIMETICKS, S._encode_int_bytes(value)


def ip_address(text: str) -> tuple[int, bytes]:
    return S._T_IPADDRESS, bytes(int(o) for o in text.split("."))


def _oid_key(oid: str) -> list[int]:
    """Numeric ordering — '1.3.6.1.2.1.2.2.1.7.400' sorts after '...193'."""
    return [int(part) for part in oid.split(".")]


class FakeAgent:
    """
    A UDP responder backed by a dict of {oid: (tag, value_bytes)}.

    Supports GET, GETNEXT (so walks work) and SET (which mutates the table,
    letting a test assert the write actually landed).  Set *error_status* to
    make every request fail the way a read-only agent does.
    """

    def __init__(
        self,
        table: dict[str, tuple[int, bytes]] | None = None,
        error_status: int = 0,
        community: str = "public",
        drop_requests: int = 0,
    ) -> None:
        self.table = dict(table or {})
        self.error_status = error_status
        self.community = community
        self.drop_requests = drop_requests      # for timeout tests
        self.requests: list[str] = []           # OIDs asked for, in order

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        # Short, so tearing an agent down does not add half a second per test.
        self._sock.settimeout(0.05)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    # -- lifecycle ------------------------------------------------------

    def __enter__(self) -> FakeAgent:
        self._thread.start()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()

    # -- protocol -------------------------------------------------------

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except (TimeoutError, OSError):
                continue
            try:
                reply = self._handle(data)
            except Exception:       # noqa: BLE001 — a test agent must not die
                continue
            if reply is not None:
                self._sock.sendto(reply, addr)

    def _handle(self, data: bytes) -> bytes | None:
        _, body, _ = S._read_tlv(data, 0)
        index = 0
        _, _version, index = S._read_tlv(body, index)
        _, _community, index = S._read_tlv(body, index)
        pdu_tag, pdu, _ = S._read_tlv(body, index)

        index = 0
        _, request_id, index = S._read_tlv(pdu, index)
        _, _status, index = S._read_tlv(pdu, index)
        _, _err_index, index = S._read_tlv(pdu, index)
        _, varbind_list, _ = S._read_tlv(pdu, index)

        _, pair, _ = S._read_tlv(varbind_list, 0)
        inner = 0
        _, oid_bytes, inner = S._read_tlv(pair, inner)
        value_tag, value_body, _ = S._read_tlv(pair, inner)
        oid = S.decode_oid(oid_bytes)
        self.requests.append(oid)

        if self.drop_requests > 0:
            self.drop_requests -= 1
            return None                       # silence, to force a timeout

        rid = int.from_bytes(request_id, "big", signed=True)
        if self.error_status:
            return self._error_reply(rid, oid)

        if pdu_tag == S._PDU_GETNEXT:
            following = [k for k in sorted(self.table, key=_oid_key)
                         if _oid_key(k) > _oid_key(oid)]
            if not following:
                out = [(oid, S._T_ENDOFMIBVIEW, b"")]
            else:
                out = [(following[0], *self.table[following[0]])]
        elif pdu_tag == S._PDU_SET:
            self.table[oid] = (value_tag, value_body)
            out = [(oid, value_tag, value_body)]
        else:                                  # GET
            entry = self.table.get(oid)
            out = [(oid, *entry)] if entry else [(oid, S._T_NOSUCHOBJECT, b"")]

        return S._build_message(
            self.community, S._PDU_RESPONSE,
            [(o, S._tlv(t, v)) for o, t, v in out], rid,
        )

    def _error_reply(self, request_id: int, oid: str) -> bytes:
        """A response PDU carrying a non-zero error-status."""
        varbind = S._tlv(
            S._T_SEQUENCE,
            S._tlv(S._T_OID, S.encode_oid(oid)) + S._tlv(S._T_NULL, b""),
        )
        pdu_body = (
            S._tlv(S._T_INTEGER, S._encode_int_bytes(request_id))
            + S._tlv(S._T_INTEGER, S._encode_int_bytes(self.error_status))
            + S._tlv(S._T_INTEGER, S._encode_int_bytes(1))
            + S._tlv(S._T_SEQUENCE, varbind)
        )
        message = (
            S._tlv(S._T_INTEGER, b"\x01")
            + S._tlv(S._T_OCTETSTR, self.community.encode())
            + S._tlv(S._PDU_RESPONSE, pdu_body)
        )
        return S._tlv(S._T_SEQUENCE, message)
