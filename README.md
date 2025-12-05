# Networking Toolkit ![Python](https://img.shields.io/badge/python-3.x-blue) ![Version](https://img.shields.io/badge/version-2.0.0-green)

**Modular CLI Utility for System & Network Engineers**

---

## Quickstart

1. **Clone Repository**

```bash
git clone https://github.com/timoooonnn/networking-toolkit.git
cd sysnet-toolkit
```

2. **Install Optional Dependencies**

```bash
pip install netmiko jinja2
```

3. **Run the Toolkit**

```bash
python3 sysnet.py
```

* Navigate the menu by entering the corresponding number
* Press `Ctrl+C` to cancel operations safely

---

## Tool Categories & Quick Reference

| Category                | Tools                                                                       |
| ----------------------- | --------------------------------------------------------------------------- |
| **Network Diagnostics** | CIDR Calculator, TCP Port Tester, SSL Expiry, Bulk DNS, Public IP & Geo     |
| **System Health**       | System Resource Snapshot, Top Processes, Service Port Listener, Log Scanner |
| **Automation / Config** | Config Diff, Jinja2 Renderer, Interface Parser, SSH Bulk Command            |
| **IP & Hardware**       | MAC Vendor Lookup, Next Available IP, LAN Ping Sweep, Bandwidth Monitor     |

<br>

### Menu Preview
```bas

  _   _      _                      _    _                  _____           _ _    _ _   
 | \ | | ___| |___      _____  _ __| | _(_)_ __   __ _     |_   _|__   ___ | | | _(_) |_ 
 |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / | '_ \ / _` |      | |/ _ \ / _ \| | |/ / | __|
 | |\  |  __/ |_ \ V  V / (_) | |  |   <| | | | | (_| |      | | (_) | (_) | |   <| | |_ 
 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\_|_| |_|\__, |      |_|\___/ \___/|_|_|\_\_|\__|
                                                 |___/                                   
╔════════════════════════════════════════════════════════════════╗
║                            VERSION                             ║
║                              v1.0                              ║
╚════════════════════════════════════════════════════════════════╝

--- DIAGNOSTICS ---
[ 1] CIDR Subnet Calculator
[ 2] TCP Port Tester
[ 3] SSL Expiry Checker
[ 4] Bulk DNS Resolver
[ 5] Public IP & Geo

--- SYSTEM ---
[ 6] System Resource Snapshot
[ 7] Top Process Hogger
[ 8] Service Port Listener
[ 9] Log Keyword Scanner

--- AUTOMATION ---
[10] Config File Diff
[11] Jinja2 Config Renderer
[12] Interface Config Parser
[13] SSH Bulk Commander

--- IP & HARDWARE ---
[14] MAC Vendor Lookup
[15] Next Available IP
[16] LAN Ping Sweep
[17] Bandwidth Monitor
------------------------------
[ q] Exit

Enter Choice > 

```

---

## Features

* Cross-platform (Linux/macOS preferred) CLI toolkit
* Multi-threaded SSH command execution and ping sweeps
* Log and config analysis with color-coded outputs
* Network utilities including subnetting, TCP checks, and SSL expiry
* Optional template rendering with `Jinja2` and device automation via `Netmiko`

---

## Dependencies

* **Standard:** `socket`, `ssl`, `subprocess`, `ipaddress`, `shutil`, `json`
* **Optional:** `netmiko`, `jinja2`

---

## Notes

* Bandwidth monitoring is Linux-only (`/proc/net/dev`)
* SSH automation requires proper credentials and supported device types
* Input validation is recommended for IPs, subnets, and ports
