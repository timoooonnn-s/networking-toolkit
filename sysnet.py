#!/usr/bin/env python3
"""
SysNet Toolkit - A modular CLI utility for System and Network Engineers.
Author: Timon
Dependencies: Standard Python 3 libraries only.
OS Support: Best on Linux/macOS (some system tools rely on Unix-style paths/commands).
"""

import os
import sys
import socket
import ssl
import subprocess
import time
import json
import urllib.request
import ipaddress
import platform
import shutil
import re
import threading
import struct
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import difflib 

# --- External Dependencies Check ---
try:
    from netmiko import ConnectHandler
    from netmiko.ssh_exception import NetmikoTimeoutException, NetmikoAuthenticationException
    HAS_NETMIKO = True
except ImportError:
    HAS_NETMIKO = False

try:
    from jinja2 import Environment, FileSystemLoader
    HAS_JINJA = True
except ImportError:
    HAS_JINJA = False


# --- Configuration & Colors ---
VERSION = "2.1.0"
# ANSI Colors
C_RESET  = "\033[0m"
C_RED    = "\033[91m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE   = "\033[94m"
C_MAGENTA= "\033[95m"
C_CYAN   = "\033[96m"
C_BOLD   = "\033[1m"

# --- Storage Constants ---
SNIPPET_FILE = "sysnet_snippets.json"
VLAN_DB_FILE = "sysnet_vlans.json"

def print_header(C_CYAN="\033[96m", C_BOLD="\033[1m", C_RESET="\033[0m", VERSION="2.1"):
    """
    Prints a fixed ASCII art banner for the SYSNET ENGINEER TOOLKIT.
    """
    os.system('cls' if os.name == 'nt' else 'clear')
    
    BOX_WIDTH = 66
    
    print(f"{C_CYAN}{C_BOLD}")
    print(f"  _   _      _                      _    _                  _____           _ _    _ _   ")
    print(f" | \ | | ___| |___      _____  _ __| | _(_)_ __   __ _     |_   _|__   ___ | | | _(_) |_ ")
    print(f" |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / | '_ \ / _` |      | |/ _ \ / _ \| | |/ / | __|")
    print(f" | |\  |  __/ |_ \ V  V / (_) | |  |   <| | | | | (_| |      | | (_) | (_) | |   <| | |_ ")
    print(f" |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\_|_| |_|\__, |      |_|\___/ \___/|_|_|\_\_|\__|")
    print(f"                                                 |___/                                   ")
    
    print("╔" + "═" * (BOX_WIDTH - 2) + "╗")
    
    VERSION_TITLE = "SYSNET TOOLKIT"
    padding_name = BOX_WIDTH - 2 - len(VERSION_TITLE)
    left_pad_name = padding_name // 2
    right_pad_name = padding_name - left_pad_name
    print(f"║{' ' * left_pad_name}{VERSION_TITLE}{' ' * right_pad_name}║")

    VERSION_STR = f"v{VERSION}"
    padding_version = BOX_WIDTH - 2 - len(VERSION_STR)
    left_pad_version = padding_version // 2
    right_pad_version = padding_version - left_pad_version
    print(f"║{' ' * left_pad_version}{VERSION_STR}{' ' * right_pad_version}║")
    
    print("╚" + "═" * (BOX_WIDTH - 2) + "╝")
    print(f"{C_RESET}")


def wait_for_user():
    input(f"\n{C_YELLOW}Press Enter to return to main menu...{C_RESET}")

# --- Category A: Network Diagnostics ---

def tool_cidr_calc():
    print(f"{C_BOLD}--- CIDR Subnet Calculator ---{C_RESET}")
    cidr_input = input("Enter IP/CIDR (e.g., 192.168.1.5/24): ").strip()
    try:
        network = ipaddress.IPv4Network(cidr_input, strict=False)
        print(f"\n{C_GREEN}Network:{C_RESET}   {network.network_address}")
        print(f"{C_GREEN}Netmask:{C_RESET}   {network.netmask}")
        print(f"{C_GREEN}Broadcast:{C_RESET} {network.broadcast_address}")
        print(f"{C_GREEN}Hosts:{C_RESET}     {network.num_addresses - 2} usable")
        print(f"{C_GREEN}Range:{C_RESET}     {list(network.hosts())[0]} - {list(network.hosts())[-1]}")
    except ValueError as e:
        print(f"{C_RED}Error: Invalid CIDR format. {e}{C_RESET}")
    except IndexError:
        print(f"{C_RED}Error: Network too small to host addresses.{C_RESET}")

def tool_tcp_tester():
    print(f"{C_BOLD}--- TCP Port Reachability Tester ---{C_RESET}")
    target = input("Target IP or Hostname: ").strip()
    port = input("Target Port: ").strip()
    
    try:
        port = int(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"\n{C_GREEN}[SUCCESS] Port {port} on {target} is OPEN.{C_RESET}")
        else:
            print(f"\n{C_RED}[CLOSED/FILTERED] Port {port} on {target} is unreachable (Err: {result}).{C_RESET}")
        sock.close()
    except ValueError:
        print(f"{C_RED}Invalid port number.{C_RESET}")
    except Exception as e:
        print(f"{C_RED}Error: {e}{C_RESET}")

def tool_traceroute_analyze():
    """ND-01: Traceroute Path Analyzer"""
    print(f"{C_BOLD}--- Traceroute Path Analyzer ---{C_RESET}")
    target = input("Target IP/Domain: ").strip()
    
    # Determine command based on OS
    if platform.system().lower() == "windows":
        cmd = ["tracert", "-d", target]
    else:
        cmd = ["traceroute", "-n", "-w", "2", target]
        
    print(f"\n{C_CYAN}Running system traceroute to {target}... (This may take a minute){C_RESET}\n")
    
    try:
        # Run command and capture output live
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                line = line.strip()
                # Simple parsing logic for high latency
                # Look for ms values. If > 150ms, color red.
                ms_values = re.findall(r'(\d+)\s*ms', line)
                is_slow = False
                for ms in ms_values:
                    if int(ms) > 150:
                        is_slow = True
                        break
                
                if is_slow:
                    print(f"{C_RED}{line}  <-- HIGH LATENCY DETECTED{C_RESET}")
                elif "*" in line:
                    print(f"{C_YELLOW}{line}  <-- TIMEOUT{C_RESET}")
                else:
                    print(line)
                    
    except FileNotFoundError:
        print(f"{C_RED}Error: Traceroute command not found on system path.{C_RESET}")
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}Traceroute cancelled.{C_RESET}")

def tool_ssl_expiry():
    print(f"{C_BOLD}--- SSL Certificate Expiry Checker ---{C_RESET}")
    hostname = input("Enter Domain (e.g., google.com): ").strip()
    port = 443
    
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date_str = cert['notAfter']
                expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                remaining = expire_date - datetime.utcnow()
                
                print(f"\n{C_CYAN}Certificate for {hostname}:{C_RESET}")
                print(f"Expires On: {expire_date}")
                if remaining.days < 0:
                     print(f"{C_RED}Status: EXPIRED ({abs(remaining.days)} days ago){C_RESET}")
                elif remaining.days < 30:
                    print(f"{C_YELLOW}Status: WARNING ({remaining.days} days remaining){C_RESET}")
                else:
                    print(f"{C_GREEN}Status: OK ({remaining.days} days remaining){C_RESET}")
    except Exception as e:
        print(f"{C_RED}Connection failed: {e}{C_RESET}")

def tool_bulk_dns():
    print(f"{C_BOLD}--- Bulk DNS Resolver ---{C_RESET}")
    print("Enter hostnames separated by comma (e.g., google.com, yahoo.com):")
    raw = input("> ").strip()
    hosts = [h.strip() for h in raw.split(',')]
    
    print(f"\n{C_BOLD}{'Hostname':<30} {'Resolved IP':<20}{C_RESET}")
    print("-" * 50)
    for host in hosts:
        try:
            ip = socket.gethostbyname(host)
            print(f"{host:<30} {C_GREEN}{ip:<20}{C_RESET}")
        except socket.gaierror:
            print(f"{host:<30} {C_RED}Resolution Failed{C_RESET}")

def tool_public_ip():
    print(f"{C_BOLD}--- Public IP & Geo ---{C_RESET}")
    print("Querying external API...")
    try:
        with urllib.request.urlopen("https://ipinfo.io/json", timeout=5) as url:
            data = json.loads(url.read().decode())
            print(f"\n{C_GREEN}Public IP:{C_RESET} {data.get('ip')}")
            print(f"{C_GREEN}City:{C_RESET}      {data.get('city')}")
            print(f"{C_GREEN}Region:{C_RESET}    {data.get('region')}")
            print(f"{C_GREEN}Country:{C_RESET}   {data.get('country')}")
            print(f"{C_GREEN}Org:{C_RESET}       {data.get('org')}")
    except Exception as e:
        print(f"{C_RED}Could not reach IP API: {e}{C_RESET}")

# --- Category B: System Health ---

def tool_sys_resource():
    print(f"{C_BOLD}--- System Resources ---{C_RESET}")
    if hasattr(os, 'getloadavg'):
        load = os.getloadavg()
        print(f"Load Avg (1, 5, 15m): {C_CYAN}{load}{C_RESET}")
    
    total, used, free = shutil.disk_usage("/")
    print(f"Disk Usage (/):       {C_CYAN}{used // (2**30)}GB Used / {total // (2**30)}GB Total{C_RESET}")
    
    if platform.system() == "Linux" and os.path.exists('/proc/meminfo'):
        with open('/proc/meminfo') as f:
            lines = f.readlines()
        mem_total = int(lines[0].split()[1]) // 1024
        mem_avail = int(lines[2].split()[1]) // 1024
        print(f"Memory:               {C_CYAN}{mem_total - mem_avail}MB Used / {mem_total}MB Total{C_RESET}")
    else:
        print(f"Memory:               {C_YELLOW}(Memory details unavailable on this OS w/o psutil){C_RESET}")

def tool_top_process():
    print(f"{C_BOLD}--- Top Process Hoggers ---{C_RESET}")
    if platform.system() not in ["Linux", "Darwin"]:
        print(f"{C_RED}Tool only supports Linux/macOS.{C_RESET}")
        return

    try:
        cmd = "ps -eo pid,ppid,%mem,%cpu,comm --sort=-%mem | head -n 6"
        output = subprocess.check_output(cmd, shell=True).decode()
        print(f"{C_CYAN}{output}{C_RESET}")
    except Exception as e:
        print(f"{C_RED}Error running ps: {e}{C_RESET}")

def tool_port_listener():
    print(f"{C_BOLD}--- Local Listening Ports ---{C_RESET}")
    if platform.system() not in ["Linux", "Darwin"]:
         print(f"{C_RED}Tool only supports Linux/macOS.{C_RESET}")
         return
    
    try:
        print("Scanning ports (requires sudo for full details)...")
        cmd = "lsof -i -P -n | grep LISTEN"
        output = subprocess.check_output(cmd, shell=True).decode()
        print(f"\n{C_CYAN}{output}{C_RESET}")
    except subprocess.CalledProcessError:
        print(f"{C_YELLOW}lsof failed or found nothing. Trying netstat...{C_RESET}")
        try:
            cmd = "netstat -tuln"
            output = subprocess.check_output(cmd, shell=True).decode()
            print(f"\n{C_CYAN}{output}{C_RESET}")
        except:
             print(f"{C_RED}Could not fetch stats.{C_RESET}")

# --- Category C: Log Analysis ---

def tool_log_scanner():
    print(f"{C_BOLD}--- Log Keyword Scanner ---{C_RESET}")
    filepath = input("Path to log file: ").strip()
    keyword = input("Keyword to search (e.g., 'Error'): ").strip()
    
    if not os.path.isfile(filepath):
        print(f"{C_RED}File not found.{C_RESET}")
        return

    print(f"\nScanning {filepath} for '{keyword}'...")
    count = 0
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for i, line in enumerate(f):
                if keyword.lower() in line.lower():
                    print(f"{C_CYAN}Line {i+1}:{C_RESET} {line.strip()[:100]}...")
                    count += 1
                    if count >= 20:
                        print(f"{C_YELLOW}...Stopping after 20 matches.{C_RESET}")
                        break
        if count == 0:
            print(f"{C_GREEN}No matches found.{C_RESET}")
    except Exception as e:
        print(f"{C_RED}Error reading file: {e}{C_RESET}")

# --- Category D: Configuration & Automation ---

def tool_config_diff():
    print(f"{C_BOLD}--- Config Contextual Diff ---{C_RESET}")
    print("Paste the path to two files to compare.")
    f1_path = input("File 1 (Old/Candidate): ").strip()
    f2_path = input("File 2 (New/Running): ").strip()

    if not os.path.exists(f1_path) or not os.path.exists(f2_path):
        print(f"{C_RED}One or both files not found.{C_RESET}")
        return

    try:
        with open(f1_path, 'r') as f1, open(f2_path, 'r') as f2:
            f1_lines = f1.readlines()
            f2_lines = f2.readlines()

        diff = difflib.unified_diff(
            f1_lines, f2_lines, 
            fromfile='File1', tofile='File2', 
            lineterm=''
        )
        
        print(f"\n{C_BOLD}--- Diff Output ---{C_RESET}")
        found_diff = False
        for line in diff:
            found_diff = True
            if line.startswith('+') and not line.startswith('+++'):
                print(f"{C_GREEN}{line}{C_RESET}")
            elif line.startswith('-') and not line.startswith('---'):
                print(f"{C_RED}{line}{C_RESET}")
            elif line.startswith('^'):
                print(f"{C_CYAN}{line}{C_RESET}")
            else:
                print(line)
        
        if not found_diff:
            print(f"{C_GREEN}Files are identical.{C_RESET}")

    except Exception as e:
        print(f"{C_RED}Error processing diff: {e}{C_RESET}")

def tool_rollback_gen():
    """CM-03: Configuration Rollback Generator"""
    print(f"{C_BOLD}--- Configuration Rollback Generator ---{C_RESET}")
    print("Enter commands to reverse (one per line). Enter 'END' to finish.")
    print("Supported logic: Cisco IOS (no), Juniper (delete/set), Extreme.")
    
    commands = []
    while True:
        line = input("> ").strip()
        if line == "END":
            break
        if line:
            commands.append(line)
    
    if not commands:
        return

    print(f"\n{C_BOLD}--- Generated Rollback Script ---{C_RESET}")
    for cmd in commands:
        parts = cmd.split()
        if not parts: continue
        
        # Simple heuristic logic
        if parts[0] == "no":
            # Reverse 'no' -> remove 'no'
            print(f"{C_CYAN}{' '.join(parts[1:])}{C_RESET}")
        elif parts[0] == "set":
            # Juniper/VyOS 'set' -> 'delete'
            print(f"{C_CYAN}delete {' '.join(parts[1:])}{C_RESET}")
        elif parts[0] == "delete":
            # Juniper 'delete' -> we can't easily know the value to restore without state,
            # but we can flag it.
            print(f"{C_YELLOW}! Cannot auto-reverse delete without previous value: {cmd}{C_RESET}")
        elif parts[0].startswith("int"):
             # Interface config mode - usually no direct reverse without context
             print(f"{C_CYAN}default interface {parts[1] if len(parts)>1 else ''}{C_RESET} (Check syntax)")
        else:
            # Default Cisco assumption: prepend 'no'
            print(f"{C_CYAN}no {cmd}{C_RESET}")

def tool_snippet_lib():
    """CM-04: Configuration Snippet Library"""
    print(f"{C_BOLD}--- Configuration Snippet Library ---{C_RESET}")
    
    snippets = {}
    if os.path.exists(SNIPPET_FILE):
        try:
            with open(SNIPPET_FILE, 'r') as f:
                snippets = json.load(f)
        except:
            print(f"{C_RED}Error loading existing snippets.{C_RESET}")
    
    print(f"Stored Snippets: {len(snippets)}")
    print("1. List/View Snippet")
    print("2. Add Snippet")
    print("3. Delete Snippet")
    
    choice = input("Choice: ").strip()
    
    if choice == "1":
        if not snippets:
            print("No snippets found.")
            return
        print("\nAvailable Snippets:")
        for k in snippets.keys():
            print(f"- {k}")
        name = input("Enter name to view: ").strip()
        if name in snippets:
            print(f"\n{C_GREEN}--- {name} ---{C_RESET}")
            print(snippets[name])
            print(f"{C_GREEN}----------------{C_RESET}")
        else:
            print(f"{C_RED}Snippet not found.{C_RESET}")
            
    elif choice == "2":
        name = input("Snippet Name (e.g., 'cisco_vlan_basic'): ").strip()
        print("Enter content (End with a line containing 'EOF'):")
        lines = []
        while True:
            line = input()
            if line.strip() == "EOF":
                break
            lines.append(line)
        snippets[name] = "\n".join(lines)
        with open(SNIPPET_FILE, 'w') as f:
            json.dump(snippets, f, indent=4)
        print(f"{C_GREEN}Snippet saved.{C_RESET}")
        
    elif choice == "3":
        name = input("Snippet Name to delete: ").strip()
        if name in snippets:
            del snippets[name]
            with open(SNIPPET_FILE, 'w') as f:
                json.dump(snippets, f, indent=4)
            print(f"{C_GREEN}Snippet deleted.{C_RESET}")
        else:
            print(f"{C_RED}Not found.{C_RESET}")

def tool_diagram_gen():
    """DI-03: Network Diagram Generator"""
    print(f"{C_BOLD}--- ASCII Network Diagram Generator ---{C_RESET}")
    print("Enter connections in format: Source -> Destination")
    print("Example: Core -> SwitchA")
    print("Enter 'DRAW' to generate.")
    
    connections = []
    while True:
        line = input("> ").strip()
        if line.upper() == "DRAW":
            break
        if "->" in line:
            parts = line.split("->")
            src = parts[0].strip()
            dst = parts[1].strip()
            connections.append((src, dst))
    
    if not connections:
        return
        
    print(f"\n{C_BOLD}--- Topology ---{C_RESET}")
    # Very simple hierarchical renderer
    nodes = set()
    adj = {}
    for s, d in connections:
        nodes.add(s)
        nodes.add(d)
        if s not in adj: adj[s] = []
        adj[s].append(d)
        
    # Find root nodes (nodes that are not destinations)
    dests = set(d for s, d in connections)
    roots = [n for n in nodes if n not in dests]
    
    if not roots:
        roots = [list(nodes)[0]] # Circular or unknown, pick one

    def print_tree(node, prefix="", is_last=True):
        connector = "└── " if is_last else "├── "
        print(f"{prefix}{connector}[ {C_CYAN}{node}{C_RESET} ]")
        
        if node in adj:
            children = adj[node]
            for i, child in enumerate(children):
                is_last_child = (i == len(children) - 1)
                new_prefix = prefix + ("    " if is_last else "│   ")
                print_tree(child, new_prefix, is_last_child)

    for root in roots:
        print_tree(root)

def tool_jinja_render():
    print(f"{C_BOLD}--- Jinja2 Template Renderer ---{C_RESET}")
    if not HAS_JINJA:
        print(f"{C_RED}Error: 'jinja2' library missing. Run: pip install jinja2{C_RESET}")
        return

    template_path = input("Path to .j2 Template file: ").strip()
    data_path = input("Path to .json Data file: ").strip()

    if not os.path.exists(template_path) or not os.path.exists(data_path):
        print(f"{C_RED}Files not found.{C_RESET}")
        return

    try:
        with open(data_path, 'r') as f:
            data = json.load(f)

        env_path, template_file = os.path.split(template_path)
        env = Environment(loader=FileSystemLoader(env_path or '.'))
        template = env.get_template(template_file)
        
        output = template.render(data)
        
        print(f"\n{C_BOLD}--- Rendered Configuration ---{C_RESET}")
        print(f"{C_CYAN}{output}{C_RESET}")
        
        save = input("\nSave to file? (y/n): ").lower()
        if save == 'y':
            out_file = input("Output filename: ").strip()
            with open(out_file, 'w') as f:
                f.write(output)
            print(f"{C_GREEN}Saved to {out_file}{C_RESET}")

    except Exception as e:
        print(f"{C_RED}Rendering failed: {e}{C_RESET}")

def tool_intf_parser():
    print(f"{C_BOLD}--- Interface Config Parser ---{C_RESET}")
    print("This tool extracts Interface, Description, and IP from a config file.")
    path = input("Path to config file: ").strip()
    
    if not os.path.exists(path):
        print(f"{C_RED}File not found.{C_RESET}")
        return

    interfaces = []
    current_intf = {}

    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith("interface "):
                    if current_intf:
                        interfaces.append(current_intf)
                    current_intf = {"name": line.split()[1], "desc": "N/A", "ip": "N/A"}
                
                elif line.startswith("description ") and current_intf:
                    current_intf["desc"] = " ".join(line.split()[1:])
                
                elif line.startswith("ip address ") and current_intf:
                    parts = line.split()
                    if len(parts) >= 3:
                        current_intf["ip"] = parts[2]

            if current_intf:
                interfaces.append(current_intf)

        print(f"\n{C_BOLD}{'Interface':<20} {'IP Address':<18} {'Description'}{C_RESET}")
        print("-" * 70)
        for intf in interfaces:
            print(f"{intf['name']:<20} {C_GREEN}{intf['ip']:<18}{C_RESET} {intf['desc']}")

    except Exception as e:
        print(f"{C_RED}Error parsing file: {e}{C_RESET}")

def tool_ssh_bulk():
    print(f"{C_BOLD}--- SSH Bulk Command Runner (Netmiko) ---{C_RESET}")
    if not HAS_NETMIKO:
        print(f"{C_RED}Error: 'netmiko' library missing. Run: pip install netmiko{C_RESET}")
        return

    print("Enter target IPs separated by comma (e.g. 192.168.1.1, 192.168.1.2)")
    target_input = input("Targets: ").strip()
    targets = [t.strip() for t in target_input.split(',')]
    
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    device_type = input("Device Type (cisco_ios, arista_eos, juniper_junos, linux): ").strip() or "cisco_ios"
    command = input("Command to run (e.g. show version): ").strip()

    print(f"\n{C_YELLOW}Starting threaded execution on {len(targets)} devices...{C_RESET}\n")

    def worker(ip):
        device = {
            'device_type': device_type,
            'host': ip,
            'username': username,
            'password': password,
            'timeout': 10
        }
        try:
            net_connect = ConnectHandler(**device)
            output = net_connect.send_command(command)
            net_connect.disconnect()
            
            header = f"--- {ip} ---"
            return f"{C_GREEN}{header}{C_RESET}\n{output}\n"
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            return f"{C_RED}--- {ip} FAILED ---{C_RESET}\nError: {e}\n"
        except Exception as e:
            return f"{C_RED}--- {ip} ERROR ---{C_RESET}\n{e}\n"

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(worker, targets)
        
    for res in results:
        print(res)

# --- Category E: IP & Identifiers ---

def tool_mac_oui():
    print(f"{C_BOLD}--- MAC Address Vendor Lookup ---{C_RESET}")
    mac = input("Enter MAC Address (any format): ").strip()
    
    clean_mac = re.sub(r'[.:-]', '', mac).upper()
    
    if len(clean_mac) < 6:
        print(f"{C_RED}Invalid MAC length.{C_RESET}")
        return

    print("Querying macvendors.co API...")
    try:
        url = f"https://macvendors.co/api/{clean_mac}"
        req = urllib.request.Request(url, headers={'User-Agent': 'SysNet Tool'})
        
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            
            result = data.get('result', {})
            company = result.get('company')
            address = result.get('address')
            
            if company:
                print(f"\n{C_GREEN}Vendor:{C_RESET}  {company}")
                print(f"{C_GREEN}Address:{C_RESET} {address}")
                print(f"{C_GREEN}MAC Prefix:{C_RESET} {result.get('mac_prefix')}")
            else:
                 print(f"\n{C_YELLOW}Vendor not found.{C_RESET}")

    except Exception as e:
        print(f"{C_RED}API Error: {e}{C_RESET}")

def tool_snmp_discovery():
    """DI-01: SNMP Device Discovery (Standard Lib only)"""
    print(f"{C_BOLD}--- SNMP Device Discovery (SysDescr) ---{C_RESET}")
    # Requires constructing a basic SNMP v2c Get request packet manually
    # OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
    
    target_ip = input("Target IP: ").strip()
    community = input("Community String (default: public): ").strip() or "public"
    port = 161
    
    print(f"Querying {target_ip} for sysDescr...")

    # Basic SNMP v2c Packet Construction (ASN.1 BER)
    # Sequence [ Version(Int), Community(String), PDU(GetRequest) ]
    def build_snmp_packet(community, oid="1.3.6.1.2.1.1.1.0"):
        # Helper to encode length
        def encode_len(l):
            if l < 128: return bytes([l])
            else:
                s = []
                while l > 0:
                    s.insert(0, l & 0xFF)
                    l >>= 8
                return bytes([0x80 | len(s)] + s)

        # OID Encoding
        oid_parts = [int(x) for x in oid.split('.')]
        oid_bytes = bytearray([oid_parts[0] * 40 + oid_parts[1]]) # First two
        for val in oid_parts[2:]:
            if val < 128:
                oid_bytes.append(val)
            else:
                # Base 128 encoding
                sub = []
                sub.append(val & 0x7F)
                val >>= 7
                while val > 0:
                    sub.insert(0, (val & 0x7F) | 0x80)
                    val >>= 7
                oid_bytes.extend(sub)

        # VarBind: Sequence [ OID, Null ]
        var_bind_val = b'\x06' + encode_len(len(oid_bytes)) + oid_bytes + b'\x05\x00'
        var_bind = b'\x30' + encode_len(len(var_bind_val)) + var_bind_val
        
        # VarBindList: Sequence [ VarBind ]
        var_bind_list = b'\x30' + encode_len(len(var_bind)) + var_bind

        # PDU: GetRequest(0xA0) [ ReqID, ErrStat, ErrIdx, VarBindList ]
        req_id = random.randint(1000, 9999)
        pdu_content = b'\x02\x04' + struct.pack('>I', req_id) + b'\x02\x01\x00\x02\x01\x00' + var_bind_list
        pdu = b'\xa0' + encode_len(len(pdu_content)) + pdu_content

        # Message: Sequence [ Ver, Comm, PDU ]
        # Version 2c = Integer 1
        comm_bytes = community.encode()
        msg_content = b'\x02\x01\x01' + b'\x04' + bytes([len(comm_bytes)]) + comm_bytes + pdu
        msg = b'\x30' + encode_len(len(msg_content)) + msg_content
        return msg

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        packet = build_snmp_packet(community)
        sock.sendto(packet, (target_ip, port))
        
        data, addr = sock.recvfrom(2048)
        
        # Very crude parsing of response to find the string at the end
        # We skip parsing the ASN.1 structure properly to save code space
        # SysDescr is usually the last printable string in the packet
        try:
            # Strip non-printable characters to find the description
            clean_data = "".join([chr(b) if 32 <= b <= 126 else '\n' for b in data])
            # The community string is in there too, so we look for the system info
            parts = clean_data.split('\n')
            # Look for long strings that aren't the community string
            found = False
            for p in parts:
                if len(p) > 5 and p != community and " " in p:
                    print(f"\n{C_GREEN}Success! Device Info:{C_RESET}")
                    print(f"{C_CYAN}{p}{C_RESET}")
                    found = True
                    break
            if not found:
                print(f"{C_YELLOW}Response received, but could not decode text string. (Raw: {data[:20]}...){C_RESET}")
        except:
             print(f"{C_YELLOW}Packet received but decode failed.{C_RESET}")
        
    except socket.timeout:
        print(f"{C_RED}Timeout: No response from {target_ip}. (Check IP, Community, or Firewall){C_RESET}")
    except Exception as e:
        print(f"{C_RED}Error: {e}{C_RESET}")
    finally:
        sock.close()

def tool_vlan_tracker():
    """NP-01: VLAN Planner and Tracker"""
    print(f"{C_BOLD}--- VLAN Planner & Tracker ---{C_RESET}")
    
    vlans = {}
    if os.path.exists(VLAN_DB_FILE):
        try:
            with open(VLAN_DB_FILE, 'r') as f:
                vlans = json.load(f)
        except:
            pass

    print(f"Tracking {len(vlans)} VLANs.")
    print("1. List VLANs")
    print("2. Add/Edit VLAN")
    print("3. Delete VLAN")
    
    choice = input("Choice: ").strip()
    
    if choice == "1":
        if not vlans:
            print("No VLANs in database.")
            return
        print(f"\n{C_BOLD}{'ID':<6} {'Name':<20} {'Subnet/Desc'}{C_RESET}")
        print("-" * 50)
        # Sort by integer ID
        for vid in sorted(vlans.keys(), key=lambda x: int(x)):
            data = vlans[vid]
            print(f"{vid:<6} {C_GREEN}{data['name']:<20}{C_RESET} {data['desc']}")
            
    elif choice == "2":
        vid = input("VLAN ID: ").strip()
        if not vid.isdigit():
            print(f"{C_RED}VLAN ID must be a number.{C_RESET}")
            return
        name = input("VLAN Name: ").strip()
        desc = input("Description/Subnet: ").strip()
        
        vlans[vid] = {"name": name, "desc": desc}
        with open(VLAN_DB_FILE, 'w') as f:
            json.dump(vlans, f, indent=4)
        print(f"{C_GREEN}VLAN {vid} saved.{C_RESET}")
        
    elif choice == "3":
        vid = input("VLAN ID to delete: ").strip()
        if vid in vlans:
            del vlans[vid]
            with open(VLAN_DB_FILE, 'w') as f:
                json.dump(vlans, f, indent=4)
            print(f"{C_GREEN}VLAN {vid} deleted.{C_RESET}")
        else:
            print(f"{C_RED}ID not found.{C_RESET}")

def tool_next_ip():
    print(f"{C_BOLD}--- Next Available IP Finder ---{C_RESET}")
    subnet_str = input("Enter Subnet (e.g. 192.168.10.0/24): ").strip()
    used_input = input("Enter used IPs (comma separated): ").strip()
    
    try:
        network = ipaddress.IPv4Network(subnet_str, strict=False)
        used_ips = {ipaddress.IPv4Address(ip.strip()) for ip in used_input.split(',') if ip.strip()}
        
        used_ips.add(network.network_address)
        used_ips.add(network.broadcast_address)
        
        found = None
        for ip in network.hosts():
            if ip not in used_ips:
                found = ip
                break
        
        if found:
            print(f"\n{C_GREEN}Next Available IP:{C_RESET} {found}")
            print(f"(Gateway assumption: If .1 is gateway, ensure it is in 'used' list)")
        else:
            print(f"\n{C_RED}No free IPs available in this subnet.{C_RESET}")
            
    except ValueError as e:
        print(f"{C_RED}Invalid IP or Subnet format: {e}{C_RESET}")


# --- Category F: Advanced Networking ---

def ping_host(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def tool_ping_sweep():
    print(f"{C_BOLD}--- LAN Ping Sweep ---{C_RESET}")
    base_ip = input("Enter Base IP (e.g., 192.168.1): ").strip()
    
    if len(base_ip.split('.')) < 3:
        print(f"{C_RED}Invalid base IP. Use format like 192.168.1{C_RESET}")
        return

    print(f"Scanning {base_ip}.1 to {base_ip}.254 ... Please wait.")
    
    active_hosts = []
    
    def check(ip):
        if ping_host(ip):
            print(f"{C_GREEN}[+] Host Up: {ip}{C_RESET}")
            active_hosts.append(ip)

    with ThreadPoolExecutor(max_workers=20) as executor:
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            executor.submit(check, ip)
            
    print(f"\n{C_BOLD}Scan Complete. Found {len(active_hosts)} active hosts.{C_RESET}")

def tool_bandwidth_mon():
    print(f"{C_BOLD}--- Real-Time Bandwidth (Linux Only) ---{C_RESET}")
    if platform.system() != "Linux":
        print(f"{C_RED}This tool relies on /proc/net/dev and is Linux only.{C_RESET}")
        return

    interface = input("Interface (e.g., eth0, wlan0): ").strip()
    path = "/proc/net/dev"
    
    def get_bytes():
        with open(path, "r") as f:
            lines = f.readlines()
        for line in lines:
            if interface in line:
                data = line.split(":")[1].split()
                return int(data[0]), int(data[8]) # RX bytes, TX bytes
        return None, None

    print(f"Monitoring {interface}... (Ctrl+C to stop)")
    try:
        rx1, tx1 = get_bytes()
        if rx1 is None:
            print(f"{C_RED}Interface not found.{C_RESET}")
            return
            
        while True:
            time.sleep(1)
            rx2, tx2 = get_bytes()
            rx_speed = (rx2 - rx1) / 1024
            tx_speed = (tx2 - tx1) / 1024
            
            sys.stdout.write(f"\rDownload: {C_GREEN}{rx_speed:.2f} KB/s{C_RESET} | Upload: {C_CYAN}{tx_speed:.2f} KB/s{C_RESET}")
            sys.stdout.flush()
            
            rx1, tx1 = rx2, tx2
    except KeyboardInterrupt:
        print("\nStopped.")

# --- Main Menu System ---

def main_menu():
    # Tools dictionary: Key -> (Description, Function Reference)
    tools = {
        # Diagnostics
        "1": ("CIDR Subnet Calculator", tool_cidr_calc),
        "2": ("TCP Port Tester", tool_tcp_tester),
        "3": ("SSL Expiry Checker", tool_ssl_expiry),
        "4": ("Bulk DNS Resolver", tool_bulk_dns),
        "5": ("Public IP & Geo", tool_public_ip),
        "6": ("Traceroute Path Analyzer", tool_traceroute_analyze), # ND-01
        
        # System
        "7": ("System Resource Snapshot", tool_sys_resource),
        "8": ("Top Process Hogger", tool_top_process),
        "9": ("Service Port Listener", tool_port_listener),
        "10": ("Log Keyword Scanner", tool_log_scanner),
        
        # Automation & Config 
        "11": ("Config File Diff", tool_config_diff),
        "12": ("Jinja2 Config Renderer", tool_jinja_render),
        "13": ("Interface Config Parser", tool_intf_parser),
        "14": ("SSH Bulk Commander", tool_ssh_bulk),
        "15": ("Config Rollback Gen", tool_rollback_gen), # CM-03
        "16": ("Config Snippet Lib", tool_snippet_lib),   # CM-04
        "17": ("Network Diagram Gen", tool_diagram_gen),  # DI-03
        
        # IP & Hardware 
        "18": ("MAC Vendor Lookup", tool_mac_oui),
        "19": ("Next Available IP", tool_next_ip),
        "20": ("LAN Ping Sweep", tool_ping_sweep),
        "21": ("Bandwidth Monitor", tool_bandwidth_mon),
        "22": ("VLAN Planner/Tracker", tool_vlan_tracker), # NP-01
        "23": ("SNMP Device Discovery", tool_snmp_discovery), # DI-01
        
        "q": ("Exit", sys.exit)
    }

    while True:
        print_header()
        
        # Dynamic Menu Printing based on Keys
        print(f"{C_BOLD}--- DIAGNOSTICS ---{C_RESET}")
        for k in ["1", "2", "3", "4", "5", "6"]:
            print(f"[{k:>2}] {tools[k][0]}")
            
        print(f"\n{C_BOLD}--- SYSTEM ---{C_RESET}")
        for k in ["7", "8", "9", "10"]:
             print(f"[{k:>2}] {tools[k][0]}")

        print(f"\n{C_BOLD}--- AUTOMATION ---{C_RESET}")
        for k in ["11", "12", "13", "14", "15", "16", "17"]:
             print(f"[{k:>2}] {tools[k][0]}")

        print(f"\n{C_BOLD}--- IP & HARDWARE ---{C_RESET}")
        for k in ["18", "19", "20", "21", "22", "23"]:
             print(f"[{k:>2}] {tools[k][0]}")
             
        print("-" * 30)
        print(f"[ q] Exit")
        
        choice = input(f"\n{C_CYAN}Enter Choice > {C_RESET}").lower().strip()
        
        if choice in tools:
            print("\n")
            if choice == 'q':
                print("Exiting...")
                sys.exit()
            else:
                try:
                    tools[choice][1]()
                except KeyboardInterrupt:
                    print(f"\n{C_YELLOW}Operation cancelled by user.{C_RESET}")
                wait_for_user()
        else:
            print(f"{C_RED}Invalid selection.{C_RESET}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit()