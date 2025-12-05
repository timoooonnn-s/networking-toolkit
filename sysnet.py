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
VERSION = "2.0.0"
# ANSI Colors
C_RESET  = "\033[0m"
C_RED    = "\033[91m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN   = "\033[96m"
C_BOLD   = "\033[1m"

def print_header(C_CYAN="\033[96m", C_BOLD="\033[1m", C_RESET="\033[0m", VERSION="1.0"):
    """
    Prints a fixed ASCII art banner for the SYSNET ENGINEER TOOLKIT.
    """
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Define the new width based on the ASCII art
    # The new width is 64 characters inside the borders
    BOX_WIDTH = 66
    
    print(f"{C_CYAN}{C_BOLD}")
    # Adjusted ASCII Art (64 characters wide)
    print(f"  _   _      _                      _    _                  _____           _ _    _ _   ")
    print(f" | \ | | ___| |___      _____  _ __| | _(_)_ __   __ _     |_   _|__   ___ | | | _(_) |_ ")
    print(f" |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / | '_ \ / _` |      | |/ _ \ / _ \| | |/ / | __|")
    print(f" | |\  |  __/ |_ \ V  V / (_) | |  |   <| | | | | (_| |      | | (_) | (_) | |   <| | |_ ")
    print(f" |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\_|_| |_|\__, |      |_|\___/ \___/|_|_|\_\_|\__|")
    print(f"                                                 |___/                                   ")
    
    # Horizontal line
    print("╔" + "═" * (BOX_WIDTH - 2) + "╗")
    
    # Toolkit Name
    VERSION_TITLE = "VERSION"
    padding_name = BOX_WIDTH - 2 - len(VERSION_TITLE)
    left_pad_name = padding_name // 2
    right_pad_name = padding_name - left_pad_name
    print(f"║{' ' * left_pad_name}{VERSION_TITLE}{' ' * right_pad_name}║")

    # Version Number
    VERSION_STR = f"v{VERSION}"
    padding_version = BOX_WIDTH - 2 - len(VERSION_STR)
    left_pad_version = padding_version // 2
    right_pad_version = padding_version - left_pad_version
    print(f"║{' ' * left_pad_version}{VERSION_STR}{' ' * right_pad_version}║")
    
    # Bottom border
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

def tool_ssl_expiry():
    print(f"{C_BOLD}--- SSL Certificate Expiry Checker ---{C_RESET}")
    hostname = input("Enter Domain (e.g., google.com): ").strip()
    port = 443
    
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # Parse date format: 'May 25 12:00:00 2025 GMT'
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
    
    # Load Avg
    if hasattr(os, 'getloadavg'):
        load = os.getloadavg()
        print(f"Load Avg (1, 5, 15m): {C_CYAN}{load}{C_RESET}")
    
    # Disk Usage
    total, used, free = shutil.disk_usage("/")
    print(f"Disk Usage (/):       {C_CYAN}{used // (2**30)}GB Used / {total // (2**30)}GB Total{C_RESET}")
    
    # Memory (Linux only simple parser)
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
    # Relies on 'ps' command (Linux/Mac)
    if platform.system() not in ["Linux", "Darwin"]:
        print(f"{C_RED}Tool only supports Linux/macOS.{C_RESET}")
        return

    try:
        # Get top 5 sorted by memory
        cmd = "ps -eo pid,ppid,%mem,%cpu,comm --sort=-%mem | head -n 6"
        output = subprocess.check_output(cmd, shell=True).decode()
        print(f"{C_CYAN}{output}{C_RESET}")
    except Exception as e:
        print(f"{C_RED}Error running ps: {e}{C_RESET}")

def tool_port_listener():
    print(f"{C_BOLD}--- Local Listening Ports ---{C_RESET}")
    # Using 'lsof' or 'netstat' is safer than pure python without psutil
    if platform.system() not in ["Linux", "Darwin"]:
         print(f"{C_RED}Tool only supports Linux/macOS.{C_RESET}")
         return
    
    try:
        # Try lsof first, then netstat
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

# --- Category D: Configuration Management ---

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
        # Load Data
        with open(data_path, 'r') as f:
            data = json.load(f)

        # Setup Jinja Environment
        env_path, template_file = os.path.split(template_path)
        env = Environment(loader=FileSystemLoader(env_path or '.'))
        template = env.get_template(template_file)
        
        # Render
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
                # Simple State Machine for Cisco/Arista style syntax
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

            if current_intf: # Append last one
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
            
            # Format output for display
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
    
    # Normalize MAC for API (XX:XX:XX:XX:XX:XX) - though API handles most, better safe
    clean_mac = re.sub(r'[.:-]', '', mac).upper()
    
    if len(clean_mac) < 6:
        print(f"{C_RED}Invalid MAC length.{C_RESET}")
        return

    print("Querying macvendors.co API...")
    try:
        # Using a free API (no key required for low volume)
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

def tool_next_ip():
    print(f"{C_BOLD}--- Next Available IP Finder ---{C_RESET}")
    subnet_str = input("Enter Subnet (e.g. 192.168.10.0/24): ").strip()
    used_input = input("Enter used IPs (comma separated): ").strip()
    
    try:
        network = ipaddress.IPv4Network(subnet_str, strict=False)
        used_ips = {ipaddress.IPv4Address(ip.strip()) for ip in used_input.split(',') if ip.strip()}
        
        # Add Network ID, Broadcast, and usually Gateway (.1) to used list logic
        used_ips.add(network.network_address)
        used_ips.add(network.broadcast_address)
        
        # Simple iterator to find first gap
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
    # Cross-platform ping
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    # Suppress output
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def tool_ping_sweep():
    print(f"{C_BOLD}--- LAN Ping Sweep ---{C_RESET}")
    base_ip = input("Enter Base IP (e.g., 192.168.1): ").strip()
    
    # Validate basic format
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
            
            # Move cursor up one line and clear line to create animation effect
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
        
        # System
        "6": ("System Resource Snapshot", tool_sys_resource),
        "7": ("Top Process Hogger", tool_top_process),
        "8": ("Service Port Listener", tool_port_listener),
        "9": ("Log Keyword Scanner", tool_log_scanner),
        
        # Automation & Config 
        "10": ("Config File Diff", tool_config_diff),
        "11": ("Jinja2 Config Renderer", tool_jinja_render),
        "12": ("Interface Config Parser", tool_intf_parser),
        "13": ("SSH Bulk Commander", tool_ssh_bulk),
        
        # IP & Hardware 
        "14": ("MAC Vendor Lookup", tool_mac_oui),
        "15": ("Next Available IP", tool_next_ip),
        "16": ("LAN Ping Sweep", tool_ping_sweep),
        "17": ("Bandwidth Monitor", tool_bandwidth_mon),
        
        "q": ("Exit", sys.exit)
    }

    while True:
        print_header()
        print(f"{C_BOLD}--- DIAGNOSTICS ---{C_RESET}")
        for k in ["1", "2", "3", "4", "5"]:
            print(f"[{k:>2}] {tools[k][0]}")
            
        print(f"\n{C_BOLD}--- SYSTEM ---{C_RESET}")
        for k in ["6", "7", "8", "9"]:
             print(f"[{k:>2}] {tools[k][0]}")

        print(f"\n{C_BOLD}--- AUTOMATION ---{C_RESET}")
        for k in ["10", "11", "12", "13"]:
             print(f"[{k:>2}] {tools[k][0]}")

        print(f"\n{C_BOLD}--- IP & HARDWARE ---{C_RESET}")
        for k in ["14", "15", "16", "17"]:
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