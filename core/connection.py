"""
core/connection.py
------------------
The single choke point for every SSH command the toolkit sends to a device.

Why this module exists
----------------------
Talking to Extreme gear is not "open a Netmiko session and send commands".
VOSS and ERS each have a login ritual, a privilege step and a paging quirk
that, when skipped, produce failures that look like something else entirely:

  * ERS/BOSS gate the CLI behind "Enter Ctrl-Y to begin" and many units stay
    completely silent after SSH authentication until they receive a keystroke.
    Netmiko's stock handler reads *before* sending anything, so it times out
    and reports ``Pattern not detected: '(?:\\#|>)'`` — which reads like a
    cipher problem and is not one.
  * Old ERS units offer only SHA-1 key exchange, CBC ciphers and
    ssh-rsa/ssh-dss host keys.  Modern Paramiko refuses them by default.
  * Both platforms log in at user EXEC ('>').  On VOSS 8.x some `show`
    commands work there and some do not, so a missing `enable` looks like
    release variance rather than a privilege problem.
  * A pager left active stalls long output at ``--More--`` *and* swallows the
    next command's characters, so one missed paging command corrupts the rest
    of the session rather than just one output.

Every one of those is handled once, here, instead of in each feature module.

Contract
--------
    with SshRunner(profile) as runner:
        output = runner.run("show sys-info")     # raw text, or CommandError

    runner.setup_warnings   # session-setup problems worth reporting
    runner.command_log      # every command sent, in order, with outcome

Two exception types with very different meanings:

    ConnectionFailed   raised during connect — the device was never usable.
                       Retried for timeouts, NEVER for authentication.
    CommandError       raised by run() — either the device rejected the
                       command, or the transport died.  A device *rejection*
                       is never retried: re-sending a command a box does not
                       implement cannot produce a different answer.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

from core.inventory import NO_ENABLE_MODE, PAGING_DISABLE

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
CONN_TIMEOUT_SECS       = 20    # SSH establishment
READ_TIMEOUT_SECS       = 60    # per-command read ceiling
CONNECT_RETRIES         = 1     # reconnects after a *timeout* (never auth)
COMMAND_RETRIES         = 1     # re-sends of a command that died on transport
MAX_TRANSPORT_FAILURES  = 2     # consecutive transport failures → abandon

_CTRL_Y = "\x19"
_CTRL_C = "\x03"


# ---------------------------------------------------------------------------
# Error detection
# ---------------------------------------------------------------------------
# Rejection wording across VOSS 8.x–9.4.x, ERS/BOSS, IOS and Junos.
_ERROR_MARKERS = (
    "% invalid input",
    "% incomplete command",
    "% unrecognized command",
    "% cannot modify",
    "error: invalid",
    "invalid command",
    "ambiguous command",
    "syntax error",
)

_ERROR_LINE_KEYWORDS = (
    "invalid", "incomplete", "unrecognized", "ambiguous",
    "not allowed", "cannot modify",
)


def looks_like_error(output: str) -> bool:
    """
    Return True when *output* is a device rejection rather than data.

    Two passes, because a head-only scan is wrong on VOSS: it prints a
    ``Command Execution Time:`` banner framed by 84-character rules — well
    over 200 characters — *before* the error, so the marker never lands in
    the head.  The second pass therefore checks every line, but only accepts
    a '%'-prefixed one: that is what keeps ordinary table data containing a
    percent sign ("utilization: 42 %") from being read as a failure.
    """
    head = output.strip().lower()[:200]
    if any(marker in head for marker in _ERROR_MARKERS):
        return True
    for line in output.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("%") and any(k in stripped for k in _ERROR_LINE_KEYWORDS):
            return True
    return False


def command_slug(command: str) -> str:
    """'show vlan i-sid' -> 'show_vlan_i_sid' — the raw-capture filename key."""
    return re.sub(r"[^a-z0-9]+", "_", command.lower()).strip("_")


class ConnectionFailed(Exception):
    """The device could not be reached, authenticated or driven to a prompt."""


class CommandError(Exception):
    """One command failed; the session itself may still be usable."""

    def __init__(self, command: str, output: str = "", transport: bool = False):
        super().__init__(
            f"device rejected command '{command}'" if not transport
            else f"transport failure running '{command}': {output}"
        )
        self.command   = command
        self.output    = output
        self.transport = transport


@dataclass
class CommandRecord:
    """One command as it was actually sent — the raw material for reports."""
    command:  str
    ok:       bool
    attempts: int = 1
    error:    str = ""


# ---------------------------------------------------------------------------
# Legacy SSH algorithms (old ERS/BOSS gear)
# ---------------------------------------------------------------------------
_LEGACY_KEX = (
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
)
_LEGACY_CIPHERS = ("aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc")
_LEGACY_KEYS    = ("ssh-rsa", "ssh-dss")

_legacy_enabled = False
_legacy_lock    = threading.Lock()


def enable_legacy_ssh_algorithms() -> list[str]:
    """
    Append the legacy SSH algorithms old ERS/BOSS gear needs (SHA-1 kex, CBC
    ciphers, ssh-rsa/ssh-dss host keys) to Paramiko's client preference lists,
    when this Paramiko build implements them.

    Appended to the END, never prepended: modern algorithms keep priority, so
    connections to current devices negotiate exactly what they would have
    anyway and only a server offering nothing better falls back to these.
    Purely client-side and process-wide — no device or OS crypto policy is
    touched.  Idempotent and thread-safe (runners are built from a pool).

    Returns the algorithms that were newly enabled.
    """
    global _legacy_enabled
    try:
        from paramiko.transport import Transport
    except ImportError:          # paramiko absent → nothing to widen
        return []

    added: list[str] = []
    with _legacy_lock:
        if _legacy_enabled:
            return added

        def extend(attr: str, wanted: tuple[str, ...], implemented) -> None:
            current = list(getattr(Transport, attr))
            for algo in wanted:
                if algo not in current and algo in implemented:
                    current.append(algo)
                    added.append(algo)
            setattr(Transport, attr, tuple(current))

        extend("_preferred_kex",     _LEGACY_KEX,     Transport._kex_info)
        extend("_preferred_ciphers", _LEGACY_CIPHERS, Transport._cipher_info)
        extend("_preferred_keys",    _LEGACY_KEYS,    Transport._key_info)
        _legacy_enabled = True

    if added:
        log.info("legacy SSH algorithms enabled: %s", ", ".join(added))
    return added


# ---------------------------------------------------------------------------
# ERS login gate
# ---------------------------------------------------------------------------

def _patient_ers_class():
    """
    Netmiko's ExtremeErsSSH with a robust "Enter Ctrl-Y to begin" login.

    Netmiko only dispatches drivers by string name, so this subclass has to be
    instantiated directly rather than through ConnectHandler.  Returns None if
    this Netmiko build cannot be subclassed, and the caller falls back to the
    stock class — a Netmiko layout change degrades instead of crashing.
    """
    try:
        from netmiko.extreme.extreme_ers_ssh import ExtremeErsSSH
    except Exception:            # unexpected netmiko layout: use stock class
        return None

    class PatientExtremeErs(ExtremeErsSSH):
        def special_login_handler(self, delay_factor: float = 1.0) -> None:
            prompt  = getattr(self, "prompt_pattern", r"(?m:[>#]\s*$)")
            pattern = (r"(?:sername|ssword|[Cc]trl-?[Yy]|Press [Ee][Nn][Tt][Ee][Rr]"
                       rf"|Menu|{prompt})")
            self.write_channel(self.RETURN)   # wake boxes waiting for a keystroke
            for _ in range(6):
                try:
                    chunk = self.read_until_pattern(pattern=pattern, read_timeout=6.0)
                except Exception:             # silent so far: nudge with Ctrl-Y
                    self.write_channel(_CTRL_Y)
                    time.sleep(0.3 * delay_factor)
                    self.write_channel(self.RETURN)
                    continue
                if re.search(prompt, chunk):
                    return
                if re.search(r"[Cc]trl-?[Yy]", chunk):
                    self.write_channel(_CTRL_Y)
                    time.sleep(0.3 * delay_factor)
                    self.write_channel(self.RETURN)
                elif re.search(r"Press [Ee][Nn][Tt][Ee][Rr]", chunk):
                    self.write_channel(self.RETURN)
                elif "Menu" in chunk:
                    # A unit defaulting to 'cmd-interface menu' is a known dead
                    # end: Ctrl-C is tried, but the toolkit does not navigate a
                    # menu UI.  Fix on the device with 'cmd-interface cli'.
                    self.write_channel(_CTRL_C)
                elif "sername" in chunk:
                    self.write_channel((self.username or "") + self.RETURN)
                elif "ssword" in chunk:
                    self.write_channel((self.password or "") + self.RETURN)
                else:
                    self.write_channel(self.RETURN)
            # Deliberately no hard failure: session_preparation() retries prompt
            # detection and raises the friendlier connect error if it truly won't.

        def session_preparation(self) -> None:
            last_exc: Exception | None = None
            for attempt in range(3):
                try:
                    self.set_base_prompt()
                    last_exc = None
                    break
                except Exception as exc:      # ReadTimeout / ValueError
                    last_exc = exc
                    try:
                        self.clear_buffer()
                        self.write_channel(_CTRL_Y)
                        time.sleep(0.3)
                        self.write_channel(self.RETURN)
                        time.sleep(0.5 + attempt * 0.5)
                        self.clear_buffer()
                    except Exception:         # best-effort re-nudge
                        pass
            if last_exc is not None:
                raise last_exc
            self.set_terminal_width()
            self.disable_paging()

    return PatientExtremeErs


# ---------------------------------------------------------------------------
# SshRunner
# ---------------------------------------------------------------------------

@dataclass
class _RunnerState:
    dead:               bool = False
    transport_failures: int  = 0


class SshRunner:
    """
    One persistent, platform-aware SSH session against one device.

    Parameters
    ----------
    profile : dict
        A Netmiko connection dict — build it with
        core.inventory.build_ad_hoc_profile().
    audit : AuditLogger | None
        When given, every command and response is written to the audit trail.
    name : str
        Label used in log lines (defaults to the profile's host).
    """

    def __init__(
        self,
        profile: dict[str, Any],
        audit: Any = None,
        name: str = "",
        legacy_algorithms: bool = True,
    ) -> None:
        self.profile        = dict(profile)
        self.device_type    = self.profile.get("device_type", "cisco_ios")
        self.host           = self.profile.get("host", "unknown")
        self.name           = name or self.host
        self.audit          = audit
        self.setup_warnings: list[str] = []
        self.command_log:    list[CommandRecord] = []
        self._state         = _RunnerState()
        self._conn          = None

        if legacy_algorithms:
            enable_legacy_ssh_algorithms()

        self._connect()
        self._ensure_privileged()
        self._ensure_paging_disabled()

    # ------------------------------------------------------------------
    # Phase 1 — connect
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        from netmiko import ConnectHandler
        from netmiko.exceptions import (
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
        )

        kwargs = dict(self.profile)
        kwargs.setdefault("conn_timeout", CONN_TIMEOUT_SECS)
        # Slow boxes print long MOTDs before the prompt appears.
        kwargs.setdefault("banner_timeout", max(15, kwargs["conn_timeout"]))
        kwargs.setdefault("auth_timeout",   max(15, kwargs["conn_timeout"]))
        kwargs.setdefault("fast_cli", False)

        # Netmiko dispatches drivers by string name only, so the patient ERS
        # subclass has to be instantiated directly.
        connect_cls = None
        if self.device_type == "extreme_ers":
            connect_cls = _patient_ers_class()

        last_exc: Exception | None = None
        for attempt in range(CONNECT_RETRIES + 1):
            try:
                if connect_cls is not None:
                    driver_kwargs = {k: v for k, v in kwargs.items()
                                     if k != "device_type"}
                    self._conn = connect_cls(**driver_kwargs)
                else:
                    self._conn = ConnectHandler(**kwargs)
                return

            except NetmikoAuthenticationException as exc:
                # Never retried: retrying bad credentials across an inventory
                # locks the account out on every box at once.
                raise ConnectionFailed(
                    f"authentication failed for {self.host}: {_first_line(exc)}"
                ) from exc

            except (NetmikoTimeoutException, OSError) as exc:
                last_exc = exc
                if attempt < CONNECT_RETRIES:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise ConnectionFailed(
                    f"could not reach {self.host}: {_first_line(exc)}"
                ) from exc

            except Exception as exc:
                # Algorithm mismatch, prompt never appeared, … — retrying an
                # algorithm mismatch is pure waiting.
                raise ConnectionFailed(
                    f"could not open a session to {self.host}: {_first_line(exc)}"
                ) from exc

        raise ConnectionFailed(f"could not reach {self.host}: {last_exc}")

    # ------------------------------------------------------------------
    # Phase 2 — privileged EXEC
    # ------------------------------------------------------------------

    def _ensure_privileged(self) -> None:
        """
        Enter privileged EXEC when the platform has one.

        Both VOSS and ERS log in at user EXEC ('>'), and Netmiko's drivers for
        them do not send `enable` on their own.  On Junos there is no enable
        mode at all — sending it raises, because the prompt never becomes '#'.
        A failure here is a warning, not a fatal error: the commands that do
        work in user EXEC still produce useful data.
        """
        if self.device_type in NO_ENABLE_MODE:
            return
        try:
            if self._conn.find_prompt().strip().endswith("#"):
                return
            self._conn.enable()
            if not self._conn.find_prompt().strip().endswith("#"):
                self.setup_warnings.append(
                    "could not enter privileged EXEC via 'enable' — check the "
                    "account's access level; privileged-only commands will fail"
                )
        except Exception as exc:
            self.setup_warnings.append(
                f"could not enter privileged EXEC via 'enable' ({_first_line(exc)}) "
                f"— check the account's access level"
            )

    # ------------------------------------------------------------------
    # Phase 3 — disable paging, and verify it
    # ------------------------------------------------------------------

    def _ensure_paging_disabled(self) -> None:
        """
        Send the platform's paging-disable command and check the device's
        actual answer.

        Netmiko sends one too, but it verifies only the command *echo*, not
        acceptance, and it runs before the session is privileged.  VOSS gets a
        second, field-verified spelling if the first is rejected.
        """
        commands = PAGING_DISABLE.get(self.device_type, ())
        for command in commands:
            try:
                output = self._conn.send_command_timing(command)
            except Exception:
                continue
            if not looks_like_error(output):
                return
        if commands:
            self.setup_warnings.append(
                f"device rejected {' / '.join(repr(c) for c in commands)} — "
                f"long outputs may stall at --More--"
            )

    # ------------------------------------------------------------------
    # Phase 4 — run commands
    # ------------------------------------------------------------------

    def run(self, command: str, read_timeout: int = READ_TIMEOUT_SECS) -> str:
        """
        Send *command* and return its raw output.

        Raises CommandError when the device rejects the command (never
        retried — the answer will not change) or when the transport dies
        repeatedly.
        """
        if self._state.dead:
            record = CommandRecord(command, ok=False, error="session abandoned")
            self.command_log.append(record)
            raise CommandError(command, "session abandoned", transport=True)

        attempts = 0
        last_error = ""
        for attempt in range(COMMAND_RETRIES + 1):
            attempts = attempt + 1
            try:
                output = self._conn.send_command(command, read_timeout=read_timeout)
            except Exception as exc:
                last_error = _first_line(exc)
                self._recover_channel()
                if attempt < COMMAND_RETRIES:
                    time.sleep(1 * (attempt + 1))
                    continue
                self._state.transport_failures += 1
                if self._state.transport_failures >= MAX_TRANSPORT_FAILURES:
                    # Circuit breaker: a box that died mid-run costs seconds,
                    # not a full read_timeout per remaining command.
                    self._state.dead = True
                    log.warning("%s: abandoning session after %d consecutive "
                                "transport failures", self.name,
                                self._state.transport_failures)
                self.command_log.append(
                    CommandRecord(command, ok=False, attempts=attempts,
                                  error=last_error)
                )
                if self.audit is not None:
                    self.audit.log_error(command=command, error=last_error)
                raise CommandError(command, last_error, transport=True) from exc
            break

        # A success means the session is answering again.
        self._state.transport_failures = 0

        if self.audit is not None:
            self.audit.log(command=command, output=output)

        if looks_like_error(output):
            self.command_log.append(
                CommandRecord(command, ok=False, attempts=attempts,
                              error="device rejected the command")
            )
            raise CommandError(command, output)

        self.command_log.append(CommandRecord(command, ok=True, attempts=attempts))
        return output

    def run_timing(self, command: str) -> str:
        """
        Send *command* without waiting for a specific prompt, and check the
        answer the same way run() does.

        This is the one to use for a sequence that *changes the prompt* —
        `configure terminal`, `end`, Junos's `configure`.  ``send_command``
        matches against the base prompt captured at login, so the first
        config-mode command leaves it waiting for a prompt that will not come
        until the session exits config mode again.  ``send_command_timing``
        reads on a delay instead, which is what a mode-switching script needs.

        Raises CommandError on a device rejection, so a script the device
        refused line by line cannot be reported as applied.
        """
        try:
            output = self._conn.send_command_timing(command)
        except Exception as exc:
            self.command_log.append(
                CommandRecord(command, ok=False, error=_first_line(exc)))
            if self.audit is not None:
                self.audit.log_error(command=command, error=_first_line(exc))
            raise CommandError(command, _first_line(exc), transport=True) from exc

        if self.audit is not None:
            self.audit.log(command=command, output=output)

        if looks_like_error(output):
            self.command_log.append(
                CommandRecord(command, ok=False,
                              error="device rejected the command"))
            raise CommandError(command, output)

        self.command_log.append(CommandRecord(command, ok=True))
        return output

    def _recover_channel(self) -> None:
        """
        Quit a stuck pager and drain the buffer.

        A read timeout is most often a ``--More--`` waiting for a keystroke;
        quitting it is what stops the *next* command's output from being eaten.
        """
        try:
            self._conn.write_channel("q\n")
            time.sleep(0.5)
            self._conn.clear_buffer()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Phase 5 — close
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Best-effort teardown — it must never mask the real result."""
        if self._conn is None:
            return
        try:
            self._conn.disconnect()
        except Exception:
            pass
        finally:
            self._conn = None

    def __enter__(self) -> SshRunner:
        return self

    def __exit__(self, *_) -> None:
        self.close()


def _first_line(exc: object) -> str:
    """
    Netmiko's ReadTimeout is a multi-paragraph "Things you might try…" blob.
    Reports get the first meaningful line; the rest belongs in the log.
    """
    text = str(exc).strip()
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return text or exc.__class__.__name__
