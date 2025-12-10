#!/usr/bin/env python3
"""
SysNet Toolkit v2.1
Refactored for modularity, security, and automation.
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
import difflib
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Dict, Any, Union, Tuple

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

# --- Configuration & Constants ---
class Config:
    VERSION = "2.1.0"
    TIMEOUT_SOCKET = 3
    TIMEOUT_HTTP = 5
    MAX_WORKERS = 10
    
    # ANSI Colors
    C_RESET  = "\033[0m"
    C_RED    = "\033[91m"
    C_GREEN  = "\033[92m"
    C_YELLOW = "\033[93m"
    C_CYAN   = "\033[96m"
    C_BOLD   = "\033[1m"
    
    # OS Detection
    IS_WINDOWS = os.name == 'nt'
    IS_LINUX = platform.system() == "Linux"
    IS_MAC = platform.system() == "Darwin"

# --- Utility Classes ---

class Spinner:
    """A threaded loading indicator."""
    def __init__(self, message: str = "Processing", delay: float = 0.1):
        self.spinner = ['|', '/', '-', '\\']
        self.delay = delay
        self.message = message
        self.running = False
        self.thread = None

    def spinner_task(self):
        while self.running:
            for char in self.spinner:
                sys.stdout.write(f'\r{Config.C_YELLOW}{self.message} {char}{Config.C_RESET}')
                sys.stdout.flush()
                time.sleep(self.delay)
                if not self.running:
                    break
        sys.stdout.write('\r' + ' ' * (len(self.message) + 2) + '\r') # Clear line
        sys.stdout.flush()

    def __enter__(self):
        self.running = True
        self.thread = threading.Thread(target=self.spinner_task)
        self.thread.start()

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.running = False
        if self.thread:
            self.thread.join()

# --- Business Logic Layer (No Print Statements) ---

class SysNetLogic:
    """Core logic for network and system tools. Returns data structures."""

    @staticmethod
    def calc_cidr(cidr_input: str) -> Dict[str, Any]:
        try:
            network = ipaddress.IPv4Network(cidr_input, strict=False)
            return {
                "network": str(network.network_address),
                "netmask": str(network.netmask),
                "broadcast": str(network.broadcast_address),
                "hosts": network.num_addresses - 2,
                "first": str(list(network.hosts())[0]) if network.num_addresses > 2 else "N/A",
                "last": str(list(network.hosts())[-1]) if network.num_addresses > 2 else "N/A"
            }
        except ValueError as e:
            raise ValueError(f"Invalid CIDR format: {e}")
        except IndexError:
            raise ValueError("Network too small.")

    @staticmethod
    def check_tcp_port(target: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(Config.TIMEOUT_SOCKET)
                result = sock.connect_ex((target, port))
                return result == 0
        except Exception as e:
            raise RuntimeError(f"Socket error: {e}")

    @staticmethod
    def check_ssl_expiry(hostname: str, port: int = 443) -> Dict[str, Any]:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=Config.TIMEOUT_HTTP) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expire_date_str = cert['notAfter']
                    expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                    remaining = expire_date - datetime.utcnow()
                    return {
                        "expiry_date": str(expire_date),
                        "days_left": remaining.days,
                        "status": "EXPIRED" if remaining.days < 0 else "WARNING" if remaining.days < 30 else "OK"
                    }
        except Exception as e:
            raise RuntimeError(f"SSL check failed: {e}")

    @staticmethod
    def bulk_dns_resolve(hosts: List[str]) -> Dict[str, str]:
        results = {}
        for host in hosts:
            try:
                ip = socket.gethostbyname(host.strip())
                results[host.strip()] = ip
            except socket.gaierror:
                results[host.strip()] = "Failed"
        return results

    @staticmethod
    def get_public_ip() -> Dict[str, Any]:
        try:
            with urllib.request.urlopen("https://ipinfo.io/json", timeout=Config.TIMEOUT_HTTP) as url:
                return json.loads(url.read().decode())
        except Exception as e:
            raise RuntimeError(f"API unreachable: {e}")

    @staticmethod
    def get_sys_resources() -> Dict[str, Any]:
        usage = shutil.disk_usage("/")
        data = {
            "disk_total_gb": usage.total // (2**30),
            "disk_used_gb": usage.used // (2**30),
            "load_avg": os.getloadavg() if hasattr(os, "getloadavg") else "N/A",
            "memory": "N/A"
        }
        
        if Config.IS_LINUX and os.path.exists('/proc/meminfo'):
            try:
                with open('/proc/meminfo') as f:
                    lines = f.readlines()
                mem_total = int(lines[0].split()[1]) // 1024
                mem_avail = int(lines[2].split()[1]) // 1024
                data["memory"] = f"{mem_total - mem_avail}MB Used / {mem_total}MB Total"
            except:
                pass
        return data

    @staticmethod
    def get_top_processes() -> str:
        if not (Config.IS_LINUX or Config.IS_MAC):
            raise NotImplementedError("Tool only supports Linux/macOS.")
        
        # Safe subprocess call without shell=True
        cmd = ["ps", "-eo", "pid,ppid,%mem,%cpu,comm", "--sort=-%mem"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # Simulate 'head -n 6' in python
            lines = result.stdout.strip().split('\n')
            return "\n".join(lines[:6])
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Command failed: {e}")

    @staticmethod
    def get_listening_ports() -> str:
        if not (Config.IS_LINUX or Config.IS_MAC):
            raise NotImplementedError("Tool only supports Linux/macOS.")
        
        # Try lsof first
        try:
            cmd = ["lsof", "-i", "-P", "-n"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                lines = [line for line in result.stdout.split('\n') if "LISTEN" in line]
                return "\n".join(lines) if lines else "No listening ports found (or permission denied)."
        except FileNotFoundError:
            pass

        # Fallback to netstat
        try:
            cmd = ["netstat", "-tuln"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        except FileNotFoundError:
            return "Neither lsof nor netstat found."

    @staticmethod
    def scan_logs(filepath: str, keyword: str) -> List[str]:
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File {filepath} not found.")
        
        matches = []
        try:
            with open(filepath, 'r', errors='ignore') as f:
                for i, line in enumerate(f):
                    if keyword.lower() in line.lower():
                        matches.append(f"Line {i+1}: {line.strip()[:100]}...")
                        if len(matches) >= 20: break
            return matches
        except Exception as e:
            raise RuntimeError(f"Read error: {e}")

    @staticmethod
    def compare_files(f1_path: str, f2_path: str) -> List[str]:
        if not os.path.exists(f1_path) or not os.path.exists(f2_path):
            raise FileNotFoundError("One or both files missing.")
        
        with open(f1_path, 'r') as f1, open(f2_path, 'r') as f2:
            f1_lines = f1.readlines()
            f2_lines = f2.readlines()
        
        return list(difflib.unified_diff(f1_lines, f2_lines, fromfile='File1', tofile='File2', lineterm=''))

    @staticmethod
    def render_jinja(template_path: str, data_path: str) -> str:
        if not HAS_JINJA:
            raise ImportError("Jinja2 library missing.")
        
        if not os.path.exists(template_path) or not os.path.exists(data_path):
            raise FileNotFoundError("Files not found.")

        with open(data_path, 'r') as f:
            data = json.load(f)

        env_path, template_file = os.path.split(template_path)
        env = Environment(loader=FileSystemLoader(env_path or '.'))
        template = env.get_template(template_file)
        return template.render(data)

    @staticmethod
    def parse_interfaces(path: str) -> List[Dict[str, str]]:
        if not os.path.exists(path):
            raise FileNotFoundError("File not found.")
        
        interfaces = []
        current_intf = {}
        
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith("interface "):
                    if current_intf: interfaces.append(current_intf)
                    current_intf = {"name": line.split()[1], "desc": "N/A", "ip": "N/A"}
                elif line.startswith("description ") and current_intf:
                    current_intf["desc"] = " ".join(line.split()[1:])
                elif line.startswith("ip address ") and current_intf:
                    parts = line.split()
                    if len(parts) >= 3: current_intf["ip"] = parts[2]
            if current_intf: interfaces.append(current_intf)
        return interfaces

    @staticmethod
    def ssh_bulk_run(targets: List[str], username, password, device_type, command) -> Dict[str, str]:
        if not HAS_NETMIKO:
            raise ImportError("Netmiko library missing.")
        
        results = {}
        def worker(ip):
            device = {'device_type': device_type, 'host': ip, 'username': username, 'password': password, 'timeout': 10}
            try:
                net_connect = ConnectHandler(**device)
                output = net_connect.send_command(command)
                net_connect.disconnect()
                return ip, output
            except Exception as e:
                return ip, f"Error: {e}"

        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            future_results = executor.map(worker, targets)
            for ip, output in future_results:
                results[ip] = output
        return results

    @staticmethod
    def mac_lookup(mac: str) -> Dict[str, Any]:
        clean_mac = re.sub(r'[.:-]', '', mac).upper()
        if len(clean_mac) < 6: raise ValueError("Invalid MAC length")
        
        url = f"https://macvendors.co/api/{clean_mac}"
        req = urllib.request.Request(url, headers={'User-Agent': 'SysNet Tool'})
        with urllib.request.urlopen(req, timeout=Config.TIMEOUT_HTTP) as response:
            return json.loads(response.read().decode())

    @staticmethod
    def find_next_ip(subnet_str: str, used_ips_list: List[str]) -> str:
        network = ipaddress.IPv4Network(subnet_str, strict=False)
        used_ips = {ipaddress.IPv4Address(ip.strip()) for ip in used_ips_list if ip.strip()}
        used_ips.add(network.network_address)
        used_ips.add(network.broadcast_address)
        
        for ip in network.hosts():
            if ip not in used_ips:
                return str(ip)
        return "None"

    @staticmethod
    def ping_sweep(base_ip: str) -> List[str]:
        # Validate base IP (simple check)
        parts = base_ip.split('.')
        if len(parts) < 3: raise ValueError("Invalid Base IP format")
        base = ".".join(parts[:3])
        
        active_hosts = []
        param = '-n' if Config.IS_WINDOWS else '-c'

        def check(ip):
            # Safe subprocess call
            cmd = ['ping', param, '1', ip]
            if subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                return ip
            return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            ips = [f"{base}.{i}" for i in range(1, 255)]
            results = executor.map(check, ips)
            
            for res in results:
                if res: active_hosts.append(res)
        
        return active_hosts

# --- Presentation Layer (UI & Output Handling) ---

class SysNetUI:
    """Handles formatting and output. Supports redirection to file."""
    
    def __init__(self):
        self.output_buffer = []
        self.capture_mode = False
        self.capture_file = None

    def enable_capture(self, filename: str):
        self.capture_mode = True
        self.capture_file = filename
        self.output_buffer = []

    def disable_capture(self):
        if self.capture_mode and self.capture_file:
            try:
                with open(self.capture_file, 'w') as f:
                    f.write("\n".join(self.output_buffer))
                print(f"{Config.C_GREEN}Output successfully saved to {self.capture_file}{Config.C_RESET}")
            except Exception as e:
                print(f"{Config.C_RED}Failed to write file: {e}{Config.C_RESET}")
        
        self.capture_mode = False
        self.capture_file = None
        self.output_buffer = []

    def log(self, message: str = "", color: str = Config.C_RESET, end: str = "\n"):
        """Central print function that handles redirection."""
        formatted_msg = f"{color}{message}{Config.C_RESET}"
        # Strip ANSI for file output
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_msg = ansi_escape.sub('', message)

        if self.capture_mode:
            self.output_buffer.append(clean_msg)
        else:
            print(formatted_msg, end=end)

    def display_header(self):
        if Config.IS_WINDOWS: os.system('cls')
        else: os.system('clear')
        
        BOX_WIDTH = 66
        
        print(f"{Config.C_CYAN}{Config.C_BOLD}")
        # Restored Original ASCII Art
        print(f"  _  _       _                       _    _                  _____           _ _    _ _   ")
        print(f" | \ | | ___| |___       _____  _ __| | _(_)_ __  __ _      |_    _|__   ___ | | | _(_) |_ ")
        print(f" |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / | '_ \ / _` |      | |/ _ \ / _ \| | |/ / | __|")
        print(f" | |\  |  __/ |_ \ V  V / (_) | |  |   <| | | | | (_| |      | | (_) | (_) | |   <| | |_ ")
        print(f" |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\_|_| |_|\__, |      |_|\___/ \___/|_|_|\_\_|\__|")
        print(f"                                                 |___/                                   ")
        
        # Horizontal line
        print("╔" + "═" * (BOX_WIDTH - 2) + "╗")
        
        # Toolkit Name
        VERSION_TITLE = "VERSION"
        padding_name = BOX_WIDTH - 2 - len(VERSION_TITLE)
        left_pad_name = padding_name // 2
        right_pad_name = padding_name - left_pad_name
        print(f"║{' ' * left_pad_name}{VERSION_TITLE}{' ' * right_pad_name}║")

        # Version Number
        VERSION_STR = f"v{Config.VERSION}"
        padding_version = BOX_WIDTH - 2 - len(VERSION_STR)
        left_pad_version = padding_version // 2
        right_pad_version = padding_version - left_pad_version
        print(f"║{' ' * left_pad_version}{VERSION_STR}{' ' * right_pad_version}║")
        
        # Bottom border
        print("╚" + "═" * (BOX_WIDTH - 2) + "╝")
        print(f"{Config.C_RESET}")

    # --- Specific Display Methods ---

    def show_cidr(self, data):
        self.log(f"--- CIDR Report ---", Config.C_BOLD)
        self.log(f"Network:   {data['network']}")
        self.log(f"Netmask:   {data['netmask']}")
        self.log(f"Broadcast: {data['broadcast']}")
        self.log(f"Hosts:     {data['hosts']}")
        self.log(f"Range:     {data['first']} - {data['last']}")

    def show_ssl(self, data):
        color = Config.C_RED if data['status'] == "EXPIRED" else Config.C_GREEN
        self.log(f"--- SSL Status ---", Config.C_BOLD)
        self.log(f"Expires: {data['expiry_date']}")
        self.log(f"Status:  {data['status']} ({data['days_left']} days left)", color)

    def show_dns(self, data):
        self.log(f"{'Hostname':<30} {'IP Address':<20}", Config.C_BOLD)
        self.log("-" * 50)
        for host, ip in data.items():
            color = Config.C_RED if ip == "Failed" else Config.C_GREEN
            self.log(f"{host:<30} {ip:<20}", color)

    def show_generic_dict(self, title, data):
        self.log(f"--- {title} ---", Config.C_BOLD)
        for k, v in data.items():
            self.log(f"{k.capitalize()}: {v}")

    def show_text_block(self, title, text):
        self.log(f"--- {title} ---", Config.C_BOLD)
        self.log(text, Config.C_CYAN)

    def show_interfaces(self, data):
        self.log(f"{'Interface':<20} {'IP Address':<18} {'Description'}", Config.C_BOLD)
        self.log("-" * 70)
        for intf in data:
            self.log(f"{intf['name']:<20} {intf['ip']:<18} {intf['desc']}")

    def show_ssh_results(self, data):
        for ip, output in data.items():
            self.log(f"--- {ip} ---", Config.C_BOLD)
            self.log(output)
            self.log("-" * 20)

    def show_mac(self, data):
        res = data.get('result', {})
        if res.get('company'):
            self.log(f"Vendor:  {res.get('company')}", Config.C_GREEN)
            self.log(f"Address: {res.get('address')}")
        else:
            self.log("Vendor not found.", Config.C_YELLOW)

# --- Application Controller ---

class SysNetApp:
    def __init__(self):
        self.logic = SysNetLogic()
        self.ui = SysNetUI()

    # --- Tool Wrappers ---
    # These methods act as the bridge between UI inputs and Logic

    def run_cidr(self, args):
        cidr = args if isinstance(args, str) else input("Enter IP/CIDR: ").strip()
        try:
            data = self.logic.calc_cidr(cidr)
            self.ui.show_cidr(data)
        except ValueError as e:
            self.ui.log(f"Error: {e}", Config.C_RED)

    def run_tcp(self, args):
        if isinstance(args, list) and len(args) == 2:
            host, port = args[0], args[1]
        else:
            host = input("Target IP/Host: ").strip()
            port = input("Port: ").strip()
        
        try:
            res = self.logic.check_tcp_port(host, int(port))
            status = "OPEN" if res else "CLOSED"
            color = Config.C_GREEN if res else Config.C_RED
            self.ui.log(f"Port {port} on {host} is {status}", color)
        except Exception as e:
            self.ui.log(f"Error: {e}", Config.C_RED)

    def run_ssl(self, args):
        host = args if isinstance(args, str) else input("Domain: ").strip()
        try:
            data = self.logic.check_ssl_expiry(host)
            self.ui.show_ssl(data)
        except Exception as e:
            self.ui.log(f"Error: {e}", Config.C_RED)

    def run_dns(self, args):
        inp = args if isinstance(args, str) else input("Hostnames (comma sep): ").strip()
        hosts = inp.split(',')
        with Spinner("Resolving"):
            data = self.logic.bulk_dns_resolve(hosts)
        self.ui.show_dns(data)

    def run_public_ip(self, _=None):
        with Spinner("Querying API"):
            try:
                data = self.logic.get_public_ip()
                self.ui.show_generic_dict("Public IP Info", data)
            except Exception as e:
                self.ui.log(str(e), Config.C_RED)

    def run_sys_resources(self, _=None):
        data = self.logic.get_sys_resources()
        self.ui.show_generic_dict("System Resources", data)

    def run_top(self, _=None):
        try:
            data = self.logic.get_top_processes()
            self.ui.show_text_block("Top Processes", data)
        except Exception as e:
            self.ui.log(str(e), Config.C_RED)

    def run_listeners(self, _=None):
        try:
            with Spinner("Scanning ports"):
                data = self.logic.get_listening_ports()
            self.ui.show_text_block("Listening Ports", data)
        except Exception as e:
            self.ui.log(str(e), Config.C_RED)

    def run_log_scan(self, _=None):
        path = input("Log Path: ").strip()
        kw = input("Keyword: ").strip()
        try:
            matches = self.logic.scan_logs(path, kw)
            if matches:
                self.ui.show_text_block(f"Matches for '{kw}'", "\n".join(matches))
            else:
                self.ui.log("No matches found.", Config.C_GREEN)
        except Exception as e:
            self.ui.log(str(e), Config.C_RED)

    def run_diff(self, _=None):
        f1 = input("File 1: ").strip()
        f2 = input("File 2: ").strip()
        try:
            diff = self.logic.compare_files(f1, f2)
            if not diff:
                self.ui.log("Files are identical.", Config.C_GREEN)
            else:
                for line in diff:
                    color = Config.C_GREEN if line.startswith('+') else Config.C_RED if line.startswith('-') else Config.C_CYAN
                    self.ui.log(line, color)
        except Exception as e:
            self.ui.log(str(e), Config.C_RED)

    def run_jinja(self, _=None):
        tpl = input("Template Path: ").strip()
        data = input("Data JSON Path: ").strip()
        try:
            output = self.logic.render_jinja(tpl, data)
            self.ui.show_text_block("Rendered Config", output)
        except Exception as e:
            self.ui.log(str(e), Config.C_RED)

    def run_intf_parser(self, _=None):
        path = input("Config Path: ").strip()
        try:
            data = self.logic.parse_interfaces(path)
            self.ui.show_interfaces(data)
        except Exception as e:
            self.ui.log(str(e), Config.C_RED)

    def run_ssh(self, _=None):
        t_str = input("Targets (comma sep): ").strip()
        targets = t_str.split(',')
        user = input("Username: ").strip()
        pwd = input("Password: ").strip()
        dtype = input("Device Type (cisco_ios): ").strip() or "cisco_ios"
        cmd = input("Command: ").strip()
        
        with Spinner("Executing SSH commands"):
            results = self.logic.ssh_bulk_run(targets, user, pwd, dtype, cmd)
        self.ui.show_ssh_results(results)

    def run_mac(self, args):
        mac = args if isinstance(args, str) else input("MAC Address: ").strip()
        try:
            with Spinner("Looking up Vendor"):
                data = self.logic.mac_lookup(mac)
            self.ui.show_mac(data)
        except Exception as e:
            self.ui.log(str(e), Config.C_RED)

    def run_next_ip(self, _=None):
        sub = input("Subnet: ").strip()
        used = input("Used IPs (comma sep): ").strip().split(',')
        try:
            res = self.logic.find_next_ip(sub, used)
            self.ui.log(f"Next Free IP: {res}", Config.C_GREEN)
            self.ui.log(f"(Gateway assumption: If .1 is gateway, ensure it is in 'used' list)", Config.C_CYAN)
        except Exception as e:
            self.ui.log(str(e), Config.C_RED)

    def run_ping_sweep(self, args):
        base = args if isinstance(args, str) else input("Base IP (e.g. 192.168.1): ").strip()
        self.ui.log(f"Sweeping {base}.1 - {base}.254...")
        with Spinner("Scanning Network"):
            active = self.logic.ping_sweep(base)
        self.ui.show_text_block("Active Hosts", "\n".join(active))

    def run_bandwidth(self, _=None):
        if not Config.IS_LINUX:
            self.ui.log("Linux only.", Config.C_RED)
            return
        
        iface = input("Interface: ").strip()
        self.ui.log("Monitoring... (Ctrl+C to stop)")
        try:
            while True:
                # Simple logic inline here as it requires a loop
                with open("/proc/net/dev") as f:
                    lines = f.readlines()
                r1, t1 = 0, 0
                for line in lines:
                    if iface in line:
                        data = line.split(":")[1].split()
                        r1, t1 = int(data[0]), int(data[8])
                        break
                
                time.sleep(1)
                
                with open("/proc/net/dev") as f:
                    lines = f.readlines()
                r2, t2 = 0, 0
                for line in lines:
                    if iface in line:
                        data = line.split(":")[1].split()
                        r2, t2 = int(data[0]), int(data[8])
                        break
                
                down = (r2 - r1) / 1024
                up = (t2 - t1) / 1024
                sys.stdout.write(f"\rRX: {down:.2f} KB/s | TX: {up:.2f} KB/s")
                sys.stdout.flush()
        except KeyboardInterrupt:
            print("\nStopped.")
        except Exception as e:
            print(f"\nError: {e}")


    # --- Main Modes ---

    def interactive_mode(self):
        tools = {
            "1": ("CIDR Calculator", self.run_cidr),
            "2": ("TCP Port Tester", self.run_tcp),
            "3": ("SSL Expiry", self.run_ssl),
            "4": ("DNS Bulk Resolver", self.run_dns),
            "5": ("Public IP Info", self.run_public_ip),
            "6": ("System Resources", self.run_sys_resources),
            "7": ("Top Processes", self.run_top),
            "8": ("Listening Ports", self.run_listeners),
            "9": ("Log Scanner", self.run_log_scan),
            "10": ("Config Diff", self.run_diff),
            "11": ("Jinja Renderer", self.run_jinja),
            "12": ("Interface Parser", self.run_intf_parser),
            "13": ("SSH Bulk", self.run_ssh),
            "14": ("MAC Lookup", self.run_mac),
            "15": ("Next IP", self.run_next_ip),
            "16": ("Ping Sweep", self.run_ping_sweep),
            "17": ("Bandwidth Mon", self.run_bandwidth),
        }

        while True:
            self.ui.display_header()
            print(f"{Config.C_BOLD}Available Tools:{Config.C_RESET}")
            # Dynamic grid printing
            keys = list(tools.keys())
            for i in range(0, len(keys), 2):
                k1 = keys[i]
                msg1 = f"[{k1:>2}] {tools[k1][0]}"
                msg2 = ""
                if i + 1 < len(keys):
                    k2 = keys[i+1]
                    msg2 = f"[{k2:>2}] {tools[k2][0]}"
                print(f"{msg1:<40} {msg2}")
            
            print("-" * 60)
            print(f"Usage: Enter number. \nTo save to file: '1 >> report.txt'")
            print("[ q] Exit")

            raw_choice = input(f"\n{Config.C_CYAN}Select > {Config.C_RESET}").strip()
            
            if raw_choice.lower() == 'q':
                sys.exit()

            # Handle ">>" shortcut
            cmd_args = None
            save_file = None
            
            if ">>" in raw_choice:
                parts = raw_choice.split(">>")
                raw_choice = parts[0].strip()
                save_file = parts[1].strip()
            
            if raw_choice in tools:
                print("\n")
                if save_file:
                    self.ui.enable_capture(save_file)
                
                try:
                    tools[raw_choice][1](cmd_args)
                except KeyboardInterrupt:
                    print("\nCancelled.")
                finally:
                    if save_file:
                        self.ui.disable_capture()
                    else:
                        input(f"\n{Config.C_YELLOW}Press Enter...{Config.C_RESET}")
            else:
                print("Invalid selection.")
                time.sleep(0.5)

    def cli_mode(self):
        parser = argparse.ArgumentParser(description="SysNet Toolkit CLI")
        subparsers = parser.add_subparsers(dest="command")

        # Define subcommands
        p_cidr = subparsers.add_parser("cidr", help="Calculate Subnet")
        p_cidr.add_argument("network", help="CIDR (e.g. 192.168.1.0/24)")

        p_tcp = subparsers.add_parser("tcp", help="Test TCP Port")
        p_tcp.add_argument("host", help="Target Host")
        p_tcp.add_argument("port", type=int, help="Target Port")

        p_ssl = subparsers.add_parser("ssl", help="Check SSL Expiry")
        p_ssl.add_argument("domain", help="Domain name")

        p_mac = subparsers.add_parser("mac", help="MAC Vendor Lookup")
        p_mac.add_argument("address", help="MAC Address")

        p_sweep = subparsers.add_parser("sweep", help="Ping Sweep")
        p_sweep.add_argument("base_ip", help="Base IP (e.g. 192.168.1)")

        args = parser.parse_args()

        if args.command == "cidr":
            self.run_cidr(args.network)
        elif args.command == "tcp":
            self.run_tcp([args.host, args.port])
        elif args.command == "ssl":
            self.run_ssl(args.domain)
        elif args.command == "mac":
            self.run_mac(args.address)
        elif args.command == "sweep":
            self.run_ping_sweep(args.base_ip)
        else:
            parser.print_help()

if __name__ == "__main__":
    app = SysNetApp()
    if len(sys.argv) > 1:
        app.cli_mode()
    else:
        try:
            app.interactive_mode()
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit()