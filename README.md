# Networking Toolkit ![Python](https://img.shields.io/badge/python-3.x-blue) ![Version](https://img.shields.io/badge/version-2.2.0-green)

**Modular CLI Utility for System & Network Engineers**

---

## Quickstart

1. **Clone Repository**

```bash
git clone https://github.com/timoooonnn-s/networking-toolkit.git
cd networking-toolkit
```

2. **Install Optional Dependencies**

```bash
pip install -r requirements.txt
```

3. **Run the Toolkit**

```bash
python3 main_menu.py
```

* Navigate the menu by entering the corresponding number
* Press `Ctrl+C` to cancel operations safely

---

## Tool Categories & Quick Reference

| Category                | Tools                                                                                                    |
| ----------------------- | -------------------------------------------------------------------------------------------------------- |
| **Network Diagnostics** | CIDR Calculator, TCP Port Tester, SSL Expiry, Bulk DNS, Public IP & Geo, Traceroute Path Analyser         |
| **System Health**       | System Resource Snapshot, Top Processes, Service Port Listener, Log Scanner                               |
| **Automation / Config** | Config Diff, Jinja2 Renderer, Interface Parser, SSH Bulk Commander, Rollback Generator, Snippet Library, ASCII Network Diagram |
| **NAPALM & Health**     | NAPALM Multi-Vendor Getters, Interface Health Dashboard                                                   |
| **IP & Hardware**       | MAC Vendor Lookup, Next Available IP, LAN Ping Sweep, Bandwidth Monitor, VLAN Planner, SNMP Discovery     |

<br>

### Menu Preview
```bas
 _______             __                             __    .__                   ___________                .__    __    .__   __       
 ╲      ╲    ____  _╱  │_ __  _  __  ____  _______ │  │ __│__│  ____     ____   ╲__    ___╱  ____    ____  │  │  │  │ __│__│_╱  │_     
 ╱   │   ╲ _╱ __ ╲ ╲   __╲╲ ╲╱ ╲╱ ╱ ╱  _ ╲ ╲_  __ ╲│  │╱ ╱│  │ ╱    ╲   ╱ ___╲    │    │    ╱  _ ╲  ╱  _ ╲ │  │  │  │╱ ╱│  │╲   __╲    
╱    │    ╲╲  ___╱  │  │   ╲     ╱ (  <_> ) │  │ ╲╱│    < │  ││   │  ╲ ╱ ╱_╱  >   │    │   (  <_> )(  <_> )│  │__│    < │  │ │  │      
╲____│__  ╱ ╲___  > │__│    ╲╱╲_╱   ╲____╱  │__│   │__│_ ╲│__││___│  ╱ ╲___  ╱    │____│    ╲____╱  ╲____╱ │____╱│__│_ ╲│__│ │__│      
        ╲╱      ╲╱                                      ╲╱         ╲╱ ╱_____╱                                         ╲╱               
                                                                                                                                       
                                                                                        by timmy        |       v2.1                   
                                                                                                                                       
                                                                                                                                       

--- DIAGNOSTICS ---
  [ 1]  CIDR Subnet Calculator
  [ 2]  TCP Port Tester
  [ 3]  SSL Expiry Checker
  [ 4]  Bulk DNS Resolver
  [ 5]  Public IP & Geo
  [ 6]  Traceroute Path Analyser

--- SYSTEM ---
  [ 7]  System Resource Snapshot
  [ 8]  Top Process Hogger
  [ 9]  Service Port Listener
  [10]  Log Keyword Scanner

--- AUTOMATION & CONFIG ---
  [11]  Config File Diff
  [12]  Jinja2 Config Renderer
  [13]  Interface Config Parser
  [14]  SSH Bulk Commander  ★ NEW
  [15]  Config Rollback Generator  ★ NEW
  [16]  Config Snippet Library
  [17]  ASCII Network Diagram

--- NAPALM & HEALTH ---
  [18]  NAPALM Multi-Vendor Getters  ★
  [19]  Interface Health Dashboard  ★

--- IP & HARDWARE ---
  [20]  MAC Vendor Lookup
  [21]  Next Available IP
  [22]  LAN Ping Sweep
  [23]  Bandwidth Monitor
  [24]  VLAN Planner / Tracker
  [25]  SNMP Device Discovery

───────────────────────────────────
  [ d]  Dependency status check
  [ q]  Exit

Enter choice > 

```

---

## Project Layout

```
main_menu.py              # entry point — menu wiring only
requirements.txt          # optional dependencies
core/
  colors.py               # ANSI constants, print_header(), wait_for_user()
  inventory.py            # device inventory, credential + profile helpers
  dependency_check.py     # optional-dependency detection & install hints
  audit_logger.py         # per-session SSH audit trail writer -> logs/
features/
  diagnostics.py          # CIDR, TCP, traceroute, SSL, DNS, public IP
  system_health.py        # resources, processes, ports, log scanner
  config_tools.py         # diff, snippets, diagram, Jinja2, interface parser
  ssh_runner.py           # persistent multi-command SSH bulk runner
  napalm_interface.py     # NAPALM normalized getters
  rollback.py             # multi-vendor config rollback generator
  interface_health.py     # interface health dashboard
  ip_hardware.py          # MAC, SNMP, VLAN, next-IP, ping sweep, bandwidth
sysnet.py                 # legacy single-file version (superseded by main_menu.py)
```

---

## Features

* Cross-platform (Linux/macOS preferred) CLI toolkit
* Multi-threaded SSH command execution and ping sweeps
* Log and config analysis with color-coded outputs
* Network utilities including subnetting, TCP checks, and SSL expiry
* Optional template rendering with `Jinja2` and device automation via `Netmiko` / `NAPALM`
* Per-session SSH audit trail written to `logs/`

---

## Dependencies

* **Standard:** `socket`, `ssl`, `subprocess`, `ipaddress`, `shutil`, `json`
* **Optional:** `netmiko`, `napalm`, `jinja2`, `ntc-templates` (see `requirements.txt`)

---

## Notes

* Bandwidth monitoring is Linux-only (`/proc/net/dev`)
* SSH automation requires proper credentials and supported device types
* Input validation is recommended for IPs, subnets, and ports
* Snippet and VLAN data are stored locally in `sysnet_snippets.json` / `sysnet_vlans.json` (git-ignored)
