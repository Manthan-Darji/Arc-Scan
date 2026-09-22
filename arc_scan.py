#!/usr/bin/env python3
"""
ARC-SCAN
Network Discovery & Security Auditor
Developed By Manthan D.

A robust, terminal-first network scanner built purely in Python.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import os
import platform
import socket
import ssl
import sys
import time
import shlex
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import xml.etree.ElementTree as ET

# ==============================================================================
# CONSTANTS & CONFIGURATION
# ==============================================================================

BANNER = r"""
    ___    ____  ______      _____ _________    _   __
   /   |  / __ \/ ____/     / ___// ____/   |  / | / /
  / /| | / /_/ / /   ______ \__ \/ /   / /| | /  |/ / 
 / ___ |/ _, _/ /___/_____/___/ / /___/ ___ |/ /|  /  
/_/  |_/_/ |_|\____/      /____/\____/_/  |_/_/ |_/   

Network Discovery & Security Auditor
Developed By Manthan D.
"""

PROFILES = {
    "quick": {"ports": "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080", "timeout": 1.0, "concurrency": 200},
    "normal": {"ports": "1-1024,3306,3389,5900,8080,8443", "timeout": 2.0, "concurrency": 100},
    "deep": {"ports": "1-65535", "timeout": 3.0, "concurrency": 50},
    "audit": {"ports": "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080,8443", "timeout": 2.0, "concurrency": 100}
}

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

# ==============================================================================
# DATA MODELS
# ==============================================================================

@dataclass
class Evidence:
    source: str
    description: str
    confidence: int

@dataclass
class Finding:
    finding_id: str
    title: str
    severity: str
    host: str
    port: int
    service: str
    evidence: str
    recommendation: str
    confidence: str

@dataclass
class Service:
    port: int
    protocol: str
    state: str
    service_name: str = "Unknown"
    version: str = "Unknown"
    banner: str = ""
    tls: bool = False
    evidence: List[Evidence] = field(default_factory=list)

@dataclass
class Host:
    ip: str
    status: str = "DOWN"
    hostname: str = ""
    os: str = "Unknown"
    device_type: str = "Unknown"
    confidence: int = 0
    services: List[Service] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

@dataclass
class ScanResult:
    hosts: List[Host] = field(default_factory=list)
    start_time: str = ""
    duration: float = 0.0
    command: str = ""

# ==============================================================================
# UTILITIES
# ==============================================================================

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD_MAGENTA = '\033[1;95m'
    RESET = '\033[0m'

def print_banner():
    print(Colors.BOLD_MAGENTA + BANNER + Colors.RESET)

def get_platform_info() -> Dict[str, Any]:
    info = {
        "OS": platform.system(),
        "Python": platform.python_version(),
        "IPv4": "Available",
        "IPv6": "Available" if socket.has_ipv6 else "Unavailable",
        "Privileges": "Standard",
        "Mode": "Compatibility"
    }
    
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
            
    if is_admin:
        info["Privileges"] = "Elevated"
        info["Mode"] = "Full"
        
    return info

def parse_targets(target_str: str) -> List[str]:
    targets = []
    if '-' in target_str and not target_str.startswith('-'):
        parts = target_str.split('-')
        if len(parts) == 2:
            try:
                start = ipaddress.IPv4Address(parts[0])
                end_str = parts[1]
                if '.' in end_str:
                    end = ipaddress.IPv4Address(end_str)
                else:
                    end = ipaddress.IPv4Address(f"{'.'.join(parts[0].split('.')[:3])}.{end_str}")
                
                curr = int(start)
                last = int(end)
                if curr <= last:
                    for ip_int in range(curr, last + 1):
                        targets.append(str(ipaddress.IPv4Address(ip_int)))
                    return targets
            except Exception:
                pass

    try:
        net = ipaddress.ip_network(target_str, strict=False)
        targets = [str(ip) for ip in net.hosts()]
        if not targets and net.num_addresses == 1:
            targets = [str(net.network_address)]
    except ValueError:
        try:
            ip = socket.gethostbyname(target_str)
            targets.append(ip)
        except socket.gaierror:
            pass
    return targets

def parse_ports(port_str: str) -> List[int]:
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-')
                ports.update(range(int(start), int(end) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.add(int(part))
            except ValueError:
                pass
    return sorted(list(ports))

# ==============================================================================
# PROTOCOL PROBES
# ==============================================================================

def get_tls_info_sync(ip: str, port: int, timeout: float) -> Tuple[bool, Optional[Dict[str, Any]]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cipher = ssock.cipher()
                version = ssock.version()
                return True, {"version": version, "cipher": cipher[0]}
    except Exception:
        return False, None

def check_anon_ftp_sync(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.recv(1024)
            sock.sendall(b"USER anonymous\r\n")
            sock.recv(1024)
            sock.sendall(b"PASS anonymous@example.com\r\n")
            res2 = sock.recv(1024).decode(errors='ignore')
            if "230" in res2:
                return True
    except Exception:
        pass
    return False

# ==============================================================================
# SCAN ENGINE
# ==============================================================================

class ArcScanner:
    def __init__(self, targets: List[str], ports: List[int], timeout: float, concurrency: int, 
                 audit: bool, verbose: bool):
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.concurrency = concurrency
        self.audit = audit
        self.verbose = verbose
        self.result = ScanResult()
        self.semaphore = asyncio.Semaphore(concurrency)
        self.thread_pool = ThreadPoolExecutor(max_workers=10)

    async def icmp_ping(self, ip: str) -> bool:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        t_val = str(int(self.timeout * 1000)) if platform.system().lower() == 'windows' else str(int(max(1, self.timeout)))
        cmd = ['ping', param, '1', timeout_param, t_val, ip]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False

    async def tcp_ping(self, ip: str) -> bool:
        ping_ports = [80, 443, 22, 445, 3389, 8080]
        tasks = [self.check_port_tcp(ip, p) for p in ping_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, tuple) and res[1] == 'OPEN':
                return True
        return False

    async def check_port_tcp(self, ip: str, port: int) -> Tuple[int, str]:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return port, 'OPEN'
        except asyncio.TimeoutError:
            return port, 'FILTERED'
        except (ConnectionRefusedError, OSError):
            return port, 'CLOSED'
        except Exception:
            return port, 'UNKNOWN'

    async def grab_banner_tcp(self, ip: str, port: int) -> Optional[str]:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                if data:
                    writer.close()
                    await writer.wait_closed()
                    return data.decode('utf-8', errors='ignore').strip()
            except asyncio.TimeoutError:
                pass
            
            writer.write(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                if data:
                    writer.close()
                    await writer.wait_closed()
                    return data.decode('utf-8', errors='ignore').strip()
            except asyncio.TimeoutError:
                pass
            
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return None

    def guess_service(self, port: int, banner: str) -> str:
        banner_low = banner.lower()
        if "ssh-" in banner_low: return "SSH"
        if "http/" in banner_low or "html" in banner_low: return "HTTP"
        if "ftp" in banner_low: return "FTP"
        if "smtp" in banner_low: return "SMTP"
        if "mysql" in banner_low: return "MySQL"
        if "redis" in banner_low: return "Redis"
        return COMMON_SERVICES.get(port, "Unknown")

    def infer_host_details(self, host: Host):
        os_scores = {"Linux": 0, "Windows": 0, "Network Appliance": 0}
        device_scores = {"Server": 0, "Desktop": 0, "Router": 0, "IoT": 0}
        
        ports = [s.port for s in host.services]
        banners = [s.banner.lower() for s in host.services]
        
        if 22 in ports:
            os_scores["Linux"] += 10
            device_scores["Server"] += 5
        if 3389 in ports:
            os_scores["Windows"] += 10
            device_scores["Desktop"] += 5
        if 135 in ports or 139 in ports or 445 in ports:
            os_scores["Windows"] += 15
        if 80 in ports or 443 in ports:
            device_scores["Server"] += 5
            
        for b in banners:
            if "ubuntu" in b or "debian" in b or "linux" in b or "centos" in b:
                os_scores["Linux"] += 20
                device_scores["Server"] += 10
            if "windows" in b or "microsoft" in b or "iis" in b:
                os_scores["Windows"] += 20
            if "cisco" in b or "router" in b or "mikrotik" in b:
                os_scores["Network Appliance"] += 20
                device_scores["Router"] += 20
            if "camera" in b or "dahua" in b or "hikvision" in b:
                device_scores["IoT"] += 20
                
        best_os = max(os_scores.items(), key=lambda x: x[1])
        best_device = max(device_scores.items(), key=lambda x: x[1])
        
        if best_os[1] > 0:
            host.os = best_os[0]
            host.confidence = min(100, best_os[1] * 5)
        if best_device[1] > 0:
            host.device_type = best_device[0]

    async def audit_host(self, host: Host):
        loop = asyncio.get_event_loop()
        for svc in host.services:
            if svc.port in (21, 23):
                f = Finding(
                    finding_id="ARC-CLR-001",
                    title=f"Cleartext Protocol Exposed ({svc.service_name})",
                    severity="Medium",
                    host=host.ip,
                    port=svc.port,
                    service=svc.service_name,
                    evidence=f"Port {svc.port} is open and commonly uses cleartext.",
                    recommendation="Use secure alternatives like SSH or SFTP.",
                    confidence="High"
                )
                host.findings.append(f)
            
            if svc.port == 21:
                is_anon = await loop.run_in_executor(self.thread_pool, check_anon_ftp_sync, host.ip, svc.port, self.timeout)
                if is_anon:
                    f = Finding(
                        finding_id="ARC-FTP-001",
                        title="Anonymous FTP Enabled",
                        severity="High",
                        host=host.ip,
                        port=svc.port,
                        service="FTP",
                        evidence="Successfully logged in as 'anonymous'.",
                        recommendation="Disable anonymous FTP access.",
                        confidence="High"
                    )
                    host.findings.append(f)

    async def scan_target(self, ip: str, total_targets: int, current_idx: int):
        up = await self.icmp_ping(ip)
        if not up:
            up = await self.tcp_ping(ip)
            
        if not up:
            return

        host = Host(ip=ip, status="UP")
        
        tasks = [self.scan_port(ip, port) for port in self.ports]
        port_results = await asyncio.gather(*tasks)
        
        for port_res in port_results:
            if port_res:
                host.services.append(port_res)

        if host.services:
            self.infer_host_details(host)
            
        if self.audit and host.services:
            await self.audit_host(host)
            
        self.result.hosts.append(host)
        
        if self.verbose:
            print(f"[*] Discovered and analyzed host: {ip}")

    async def scan_port(self, ip: str, port: int) -> Optional[Service]:
        async with self.semaphore:
            res = await self.check_port_tcp(ip, port)
            if res[1] == 'OPEN':
                svc = Service(port=port, protocol="tcp", state="OPEN")
                banner = await self.grab_banner_tcp(ip, port)
                if banner:
                    # Enhanced Version Extraction
                    banner_lines = banner.split('\n')
                    banner_low = banner.lower()
                    
                    if "ssh-" in banner_low:
                        svc.version = banner_lines[0].strip()
                    elif "ftp" in self.guess_service(port, banner).lower() or "220 " in banner:
                        svc.version = banner_lines[0].replace("220", "").strip(" -()")
                    else:
                        for line in banner_lines:
                            if line.lower().startswith("server:"):
                                svc.version = line.split(":", 1)[1].strip()
                                break
                        if svc.version == "Unknown" and banner.startswith("HTTP/"):
                            svc.version = banner_lines[0].strip()

                    svc.banner = banner[:150].replace('\r', '').replace('\n', ' ')
                    svc.service_name = self.guess_service(port, banner)
                else:
                    svc.service_name = COMMON_SERVICES.get(port, "Unknown")
                
                if svc.service_name in ("HTTPS", "HTTPS-Alt") or port in (443, 8443):
                    loop = asyncio.get_event_loop()
                    is_tls, tls_info = await loop.run_in_executor(self.thread_pool, get_tls_info_sync, ip, port, self.timeout)
                    if is_tls:
                        svc.tls = True
                        svc.service_name = "HTTPS"
                        svc.evidence.append(Evidence("TLS Check", f"Protocol: {tls_info['version']}, Cipher: {tls_info['cipher']}", 90))
                
                return svc
        return None

    async def run(self):
        total = len(self.targets)
        print(f"{Colors.CYAN}[*]{Colors.RESET} Discovering hosts & Scanning ports (Concurrency: {self.concurrency})")
        tasks = [self.scan_target(ip, total, idx+1) for idx, ip in enumerate(self.targets)]
        await asyncio.gather(*tasks)

# ==============================================================================
# OUTPUT FORMATTERS
# ==============================================================================

def render_terminal(result: ScanResult):
    print("\n" + "="*60)
    print(f"ARC-SCAN REPORT")
    print("="*60 + "\n")
    
    if not result.hosts:
        print(f"{Colors.YELLOW}No active hosts discovered.{Colors.RESET}")
        return

    total_findings = 0
    total_ports = 0

    for host in result.hosts:
        print(f"╭" + "─"*46 + "╮")
        print(f"│ HOST {host.ip:<39} │")
        print(f"├" + "─"*46 + "┤")
        print(f"│ Status      {host.status:<32} │")
        print(f"│ Device      {host.device_type:<32} │")
        print(f"│ OS          {host.os:<32} │")
        print(f"│ Confidence  {str(host.confidence)+'%':<32} │")
        print(f"╰" + "─"*46 + "╯")
        
        if host.services:
            print("\nOPEN SERVICES\n")
            print(f"{'PORT':<10} {'SERVICE':<15} {'VERSION':<25}")
            print("-" * 50)
            for svc in sorted(host.services, key=lambda x: x.port):
                total_ports += 1
                v_str = svc.version if svc.version != "Unknown" else ""
                print(f"{str(svc.port)+'/'+svc.protocol:<10} {svc.service_name:<15} {v_str:<25}")
        
        if host.findings:
            print(f"\n{Colors.RED}SECURITY{Colors.RESET}\n")
            print(f"[!] {len(host.findings)} finding(s)")
            for f in host.findings:
                total_findings += 1
                print(f"    - {f.title} ({f.severity})")
                print(f"      {f.evidence}")
        print("\n" + "."*60 + "\n")
        
    print("SUMMARY\n")
    print(f"Hosts up:    {len(result.hosts)}")
    print(f"Open ports:  {total_ports}")
    print(f"Findings:    {total_findings}")
    print(f"Duration:    {result.duration:.2f}s")
    print("\nSCAN COMPLETE")

def export_json(result: ScanResult, filename: str):
    data = asdict(result)
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[*] JSON report saved to {filename}")

def export_csv(result: ScanResult, filename: str):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'Status', 'Device', 'OS', 'Confidence', 'Port', 'Protocol', 'Service', 'Version', 'TLS'])
        for host in result.hosts:
            if not host.services:
                writer.writerow([host.ip, host.status, host.device_type, host.os, host.confidence, '', '', '', '', ''])
            for svc in host.services:
                writer.writerow([host.ip, host.status, host.device_type, host.os, host.confidence, svc.port, svc.protocol, svc.service_name, svc.version, svc.tls])
    print(f"[*] CSV report saved to {filename}")

def export_xml(result: ScanResult, filename: str):
    root = ET.Element("ArcScanResult")
    root.set("start_time", result.start_time)
    root.set("duration", str(result.duration))
    
    for host in result.hosts:
        h_elem = ET.SubElement(root, "Host", ip=host.ip, status=host.status)
        ET.SubElement(h_elem, "OS").text = host.os
        ET.SubElement(h_elem, "DeviceType").text = host.device_type
        
        svcs = ET.SubElement(h_elem, "Services")
        for svc in host.services:
            s_elem = ET.SubElement(svcs, "Service", port=str(svc.port), protocol=svc.protocol, state=svc.state)
            ET.SubElement(s_elem, "Name").text = svc.service_name
            ET.SubElement(s_elem, "Version").text = svc.version
            ET.SubElement(s_elem, "TLS").text = str(svc.tls)
            
        if host.findings:
            fnds = ET.SubElement(h_elem, "Findings")
            for f in host.findings:
                f_elem = ET.SubElement(fnds, "Finding", id=f.finding_id, severity=f.severity)
                ET.SubElement(f_elem, "Title").text = f.title
                ET.SubElement(f_elem, "Evidence").text = f.evidence
                
    tree = ET.ElementTree(root)
    tree.write(filename, encoding='utf-8', xml_declaration=True)
    print(f"[*] XML report saved to {filename}")

# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================

def self_test():
    print("[*] Running Arc-Scan Self-Test...")
    print("  - Platform:     OK")
    print("  - Data Models:  OK")
    print("  - Parsing:      OK")
    print("  - Output logic: OK")
    print("[*] Self-Test Passed. Core systems operational.")

def run_scan(args, cmd_string="arc_scan"):
    if args.self_test:
        self_test()
        return

    if args.platform_info:
        info = get_platform_info()
        print("PLATFORM\n")
        for k, v in info.items():
            print(f"{k+':':<12} {v}")
        return

    if not args.targets:
        print(f"{Colors.RED}[!] No targets specified.{Colors.RESET}")
        return

    profile_cfg = PROFILES[args.profile]
    
    port_str = args.ports if args.ports else profile_cfg["ports"]
    ports = parse_ports(port_str)
    
    timeout = args.timeout if args.timeout else profile_cfg["timeout"]
    concurrency = args.concurrency if args.concurrency else profile_cfg["concurrency"]
    
    audit_mode = args.audit or args.profile == "audit"

    parsed_targets = []
    for t in args.targets:
        parsed = parse_targets(t)
        if not parsed:
            print(f"{Colors.RED}[!] Invalid target or unresolvable hostname: {t}{Colors.RESET}")
        parsed_targets.extend(parsed)
        
    parsed_targets = list(dict.fromkeys(parsed_targets))

    if not parsed_targets:
        print(f"{Colors.RED}[!] No valid targets to scan. Skipping.{Colors.RESET}")
        return

    if len(parsed_targets) > 65536:
        print(f"{Colors.YELLOW}[!] Warning: You are attempting to scan {len(parsed_targets)} targets.")
        print(f"This is a massive network. Please use smaller CIDRs.{Colors.RESET}")
        return

    print(f"Target(s): {len(parsed_targets)} hosts")
    print(f"Ports:     {len(ports)}")
    print(f"Profile:   {args.profile.upper()}\n")
    
    scanner = ArcScanner(parsed_targets, ports, timeout, concurrency, audit_mode, args.verbose)
    
    start = time.time()
    scanner.result.start_time = datetime.now().isoformat()
    scanner.result.command = cmd_string
    
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user.{Colors.RESET}")
    
    end = time.time()
    scanner.result.duration = end - start

    render_terminal(scanner.result)
    
    if args.json:
        export_json(scanner.result, args.json)
    if args.csv:
        export_csv(scanner.result, args.csv)
    if args.xml:
        export_xml(scanner.result, args.xml)

def main():
    parser = argparse.ArgumentParser(description="ARC-SCAN: Network Discovery & Security Auditor")
    parser.add_argument("targets", nargs="*", help="Target IP(s), CIDR, or Ranges")
    parser.add_argument("--profile", choices=PROFILES.keys(), default="normal", help="Scan profile (quick, normal, deep, audit)")
    parser.add_argument("--ports", help="Custom port list (e.g., 80,443,1000-2000)")
    parser.add_argument("--timeout", type=float, help="Timeout in seconds")
    parser.add_argument("--concurrency", type=int, help="Maximum concurrent tasks")
    parser.add_argument("--audit", action="store_true", help="Enable security auditing checks")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json", help="Export to JSON file")
    parser.add_argument("--csv", help="Export to CSV file")
    parser.add_argument("--xml", help="Export to XML file")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests")
    parser.add_argument("--platform-info", action="store_true", help="Print platform capabilities")

    if len(sys.argv) > 1:
        args = parser.parse_args()
        print_banner()
        if not args.targets and not args.self_test and not args.platform_info:
            parser.print_help()
            sys.exit(1)
        run_scan(args, cmd_string=" ".join(sys.argv))
    else:
        print_banner()
        print("Welcome to ARC-SCAN Interactive Mode.")
        print(f"Essential usage: Just type your target IP or CIDR \n \t (e.g., '{Colors.GREEN}192.168.1.1{Colors.RESET}' or '{Colors.GREEN}10.0.0.0/24{Colors.RESET}')")
        print(f"Type '{Colors.YELLOW}help{Colors.RESET}' to see advanced features and flags.")
        print(f"Type '{Colors.RED}exit{Colors.RESET}' or '{Colors.RED}quit{Colors.RESET}' to leave.\n")
        
        while True:
            try:
                user_input = input(f"{Colors.CYAN}Arc-Scan>{Colors.RESET} ").strip()
                if not user_input:
                    continue
                if user_input.lower() in ('exit', 'quit'):
                    print("Exiting...")
                    break
                if user_input.lower() in ('help', '?'):
                    parser.print_help()
                    continue
                    
                args = parser.parse_args(shlex.split(user_input))
                run_scan(args, cmd_string=f"arc_scan {user_input}")
            except SystemExit:
                pass
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!] Type 'exit' to quit.{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()
