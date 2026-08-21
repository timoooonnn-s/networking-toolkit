"""
features/diagnostics.py
-----------------------
Network Diagnostics Tools
==========================
All tools in this module are stateless functions that read from stdin and
write to stdout.  They depend on nothing in features/ — only on core.

Tools
-----
    tool_cidr_calc()         — CIDR subnet calculator
    tool_tcp_tester()        — TCP port reachability tester
    tool_traceroute_analyze() — Traceroute path analyser with latency flagging
    tool_ssl_expiry()        — SSL certificate expiry checker
    tool_bulk_dns()          — Bulk forward/reverse DNS resolver
    tool_public_ip()         — Public IP + geo lookup via ipinfo.io
"""

from __future__ import annotations

import ipaddress
import json
import platform
import re
import socket
import ssl
import subprocess
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from core.colors import C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW
from core.export import offer_export

# A hop slower than this is flagged in the traceroute analyser.
HIGH_LATENCY_MS = 150.0


# ---------------------------------------------------------------------------
# CIDR Calculator
# ---------------------------------------------------------------------------

def tool_cidr_calc() -> None:
    """Calculate subnet details from a CIDR notation string."""
    print(f"{C_BOLD}--- CIDR Subnet Calculator ---{C_RESET}")
    cidr_input = input("Enter IP/CIDR (e.g., 192.168.1.5/24): ").strip()
    try:
        network = ipaddress.IPv4Network(cidr_input, strict=False)
        hosts   = list(network.hosts())
        print(f"\n{C_GREEN}Network:  {C_RESET} {network.network_address}")
        print(f"{C_GREEN}Netmask:  {C_RESET} {network.netmask}")
        print(f"{C_GREEN}Broadcast:{C_RESET} {network.broadcast_address}")
        # len(hosts) rather than num_addresses - 2: a /32 is one host and a
        # /31 is a two-host point-to-point link (RFC 3021), so the blanket
        # "minus network and broadcast" printed "-1 usable" and "0 usable".
        print(f"{C_GREEN}Hosts:    {C_RESET} {len(hosts)} usable")
        if hosts:
            print(f"{C_GREEN}Range:    {C_RESET} {hosts[0]} – {hosts[-1]}")
    except ValueError as exc:
        print(f"{C_RED}Error: Invalid CIDR format — {exc}{C_RESET}")
    except IndexError:
        print(f"{C_RED}Error: Network too small to contain host addresses.{C_RESET}")


# ---------------------------------------------------------------------------
# TCP Port Tester
# ---------------------------------------------------------------------------

def tool_tcp_tester() -> None:
    """Test TCP reachability to a specific host:port."""
    print(f"{C_BOLD}--- TCP Port Reachability Tester ---{C_RESET}")
    target = input("Target IP or Hostname: ").strip()
    port_str = input("Target Port: ").strip()

    try:
        port = int(port_str)
    except ValueError:
        print(f"{C_RED}Invalid port number.{C_RESET}")
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            print(f"\n{C_GREEN}[OPEN]   Port {port} on {target} is reachable.{C_RESET}")
        else:
            print(f"\n{C_RED}[CLOSED] Port {port} on {target} is unreachable (errno {result}).{C_RESET}")
    except Exception as exc:
        print(f"{C_RED}Socket error: {exc}{C_RESET}")


# ---------------------------------------------------------------------------
# Traceroute Path Analyser
# ---------------------------------------------------------------------------

def tool_traceroute_analyze() -> None:
    """Run a system traceroute and flag high-latency hops."""
    print(f"{C_BOLD}--- Traceroute Path Analyser ---{C_RESET}")
    target = input("Target IP/Domain: ").strip()

    if platform.system().lower() == "windows":
        cmd = ["tracert", "-d", target]
    else:
        cmd = ["traceroute", "-n", "-w", "2", target]

    print(f"\n{C_CYAN}Running traceroute to {target} … (Ctrl+C to abort){C_RESET}\n")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in process.stdout:
            line = line.rstrip()
            # Capture the WHOLE number, fraction included.  r"(\d+)\s*ms"
            # matched only the digits directly before 'ms', so '12.345 ms'
            # parsed as 345 (a false HIGH LATENCY) and '210.5 ms' as 5 (a
            # missed one).
            ms_values = [float(m) for m in re.findall(r"(\d+(?:\.\d+)?)\s*ms", line)]
            if ms_values and max(ms_values) > HIGH_LATENCY_MS:
                print(f"{C_RED}{line}  ← HIGH LATENCY{C_RESET}")
            elif "*" in line:
                print(f"{C_YELLOW}{line}  ← TIMEOUT{C_RESET}")
            else:
                print(line)
        process.wait()

    except FileNotFoundError:
        print(f"{C_RED}Error: traceroute/tracert not found on PATH.{C_RESET}")
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}Traceroute cancelled.{C_RESET}")


# ---------------------------------------------------------------------------
# SSL Certificate Expiry Checker
# ---------------------------------------------------------------------------

def _decode_cert(der: bytes) -> dict:
    """
    Decode a DER certificate into the same dict shape getpeercert() returns.

    Needed because ``getpeercert()`` yields nothing on an *unverified*
    connection, which is exactly the connection an expired or self-signed
    certificate forces.  ``cryptography`` is used when it is installed (it
    comes in with Netmiko via Paramiko); otherwise the certificate is written
    out as PEM and decoded by the ssl module's own decoder.
    """
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        expires = cert.not_valid_after_utc
        return {"notAfter": expires.strftime("%b %d %H:%M:%S %Y GMT")}
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:      # noqa: BLE001
        # Deliberately wider than ImportError: a cryptography install with a
        # broken native backend raises pyo3's PanicException, which is not an
        # Exception at all.  The stdlib fallback below still does the job, so
        # a broken optional dependency must not take the tool down with it.
        pass

    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "peer.pem"
        path.write_text(pem)
        return ssl._ssl._test_decode_cert(str(path))     # noqa: SLF001


def _fetch_cert(hostname: str, port: int = 443) -> tuple[dict, str]:
    """
    Return (certificate dict, verification note) for *hostname*.

    A verifying context is tried first, so a healthy certificate is also
    confirmed as trusted.  When verification fails the connection is retried
    *unverified* — an expired or self-signed certificate is precisely what
    this tool exists to report, and refusing the handshake made it unable to
    check the only cases that matter.
    """
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((hostname, port), timeout=5) as raw,
            context.wrap_socket(raw, server_hostname=hostname) as tls,
        ):
            return tls.getpeercert(), ""
    except ssl.SSLCertVerificationError as exc:
        note = f"chain NOT trusted: {exc.verify_message or exc.reason}"

    unverified = ssl._create_unverified_context()
    with (
        socket.create_connection((hostname, port), timeout=5) as raw,
        unverified.wrap_socket(raw, server_hostname=hostname) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    return _decode_cert(der), note


def tool_ssl_expiry() -> None:
    """Check the TLS certificate expiry date for a domain."""
    print(f"{C_BOLD}--- SSL Certificate Expiry Checker ---{C_RESET}")
    raw_host = input("Domain (e.g., google.com, or host:port): ").strip()
    if not raw_host:
        print(f"{C_RED}No domain given.{C_RESET}")
        return

    hostname, _, port_str = raw_host.partition(":")
    port = int(port_str) if port_str.isdigit() else 443

    try:
        cert, note = _fetch_cert(hostname, port)
        expire_date = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        remaining = expire_date - datetime.now(timezone.utc)

        print(f"\n{C_CYAN}Certificate for {hostname}:{port}{C_RESET}")
        print(f"  Expires On: {expire_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if note:
            print(f"  {C_YELLOW}{note}{C_RESET}")

        if remaining.days < 0:
            print(f"  {C_RED}Status: EXPIRED ({abs(remaining.days)} days ago){C_RESET}")
        elif remaining.days < 30:
            print(f"  {C_YELLOW}Status: WARNING — {remaining.days} days remaining{C_RESET}")
        else:
            print(f"  {C_GREEN}Status: OK — {remaining.days} days remaining{C_RESET}")

    except (KeyError, ValueError) as exc:
        print(f"{C_RED}Could not read the certificate's expiry date: {exc}{C_RESET}")
    except Exception as exc:
        print(f"{C_RED}Connection/TLS error: {exc}{C_RESET}")


# ---------------------------------------------------------------------------
# Bulk DNS Resolver
# ---------------------------------------------------------------------------

def tool_bulk_dns() -> None:
    """Resolve multiple hostnames → IPs or IPs → hostnames."""
    print(f"{C_BOLD}--- Bulk DNS Resolver ---{C_RESET}")
    print("  1. Resolve hostnames → IPs")
    print("  2. Reverse-resolve IPs → hostnames")
    mode = input("> ").strip()

    rows: list[dict[str, str]] = []

    if mode == "1":
        raw   = input("Hostnames (comma-separated): ").strip()
        hosts = [h.strip() for h in raw.split(",") if h.strip()]
        print(f"\n{C_BOLD}{'Hostname':<30} {'Resolved IP'}{C_RESET}")
        print("─" * 52)
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                print(f"{host:<30} {C_GREEN}{ip}{C_RESET}")
                rows.append({"query": host, "result": ip, "status": "ok"})
            except (socket.gaierror, OSError) as exc:
                print(f"{host:<30} {C_RED}Resolution failed{C_RESET}")
                rows.append({"query": host, "result": "",
                             "status": f"failed ({exc.__class__.__name__})"})

    elif mode == "2":
        raw = input("IPs (comma-separated): ").strip()
        ips = [ip.strip() for ip in raw.split(",") if ip.strip()]
        print(f"\n{C_BOLD}{'IP Address':<20} {'Resolved Hostname'}{C_RESET}")
        print("─" * 52)
        for ip in ips:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"{ip:<20} {C_GREEN}{hostname}{C_RESET}")
                rows.append({"query": ip, "result": hostname, "status": "ok"})
            except (socket.herror, socket.gaierror, OSError) as exc:
                # gaierror fires on a malformed entry ("192.168.1"), and used
                # to escape this handler and kill the whole session over one
                # bad line in a pasted list.
                print(f"{ip:<20} {C_RED}Resolution failed ({exc.__class__.__name__}){C_RESET}")
                rows.append({"query": ip, "result": "",
                             "status": f"failed ({exc.__class__.__name__})"})
    else:
        print(f"{C_RED}Invalid option.{C_RESET}")
        return

    offer_export(rows, "dns_resolution")


# ---------------------------------------------------------------------------
# Public IP & Geo Lookup
# ---------------------------------------------------------------------------

def tool_public_ip() -> None:
    """Retrieve the current public IP and geo information via ipinfo.io."""
    print(f"{C_BOLD}--- Public IP & Geo Lookup ---{C_RESET}")
    print("Querying ipinfo.io …")
    try:
        with urllib.request.urlopen("https://ipinfo.io/json", timeout=5) as resp:
            data = json.loads(resp.read().decode())

        print(f"\n{C_GREEN}Public IP:{C_RESET} {data.get('ip', 'N/A')}")
        print(f"{C_GREEN}City:     {C_RESET} {data.get('city', 'N/A')}")
        print(f"{C_GREEN}Region:   {C_RESET} {data.get('region', 'N/A')}")
        print(f"{C_GREEN}Country:  {C_RESET} {data.get('country', 'N/A')}")
        print(f"{C_GREEN}Org:      {C_RESET} {data.get('org', 'N/A')}")
    except Exception as exc:
        print(f"{C_RED}Could not reach IP API: {exc}{C_RESET}")
