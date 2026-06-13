#!/usr/bin/env python3
"""
Network Vulnerability Scanner and Risk Assessment Tool
Version: 2.0
"""

import socket
import threading
import ssl
import json
import csv
import argparse
import time
import sys
import re
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple


class Colors:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    END     = '\033[0m'


@dataclass
class Vulnerability:
    host: str
    port: int
    service: str
    vulnerability: str
    severity: str
    description: str
    recommendation: str
    cvss_score: float
    cve_id: Optional[str] = None


@dataclass
class ScanResult:
    host: str
    port: int
    state: str
    service: str
    version: str
    banner: str


class NetworkScanner:
    def __init__(self, threads=100, timeout=3):
        self.threads     = threads
        self.timeout     = timeout
        self.scan_results  = []
        self.vulnerabilities = []
        self.start_time  = None

        self.common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps',
            995: 'pop3s', 1433: 'mssql', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 27017: 'mongodb'
        }

        self.vuln_db = {
            'weak_ssh': {
                'description': 'SSH server allows weak authentication methods',
                'severity': 'Medium',
                'cvss': 5.3,
                'recommendation': 'Disable password authentication, use key-based authentication'
            },
            'http_server_header': {
                'description': 'HTTP server reveals version information in response headers',
                'severity': 'Low',
                'cvss': 2.6,
                'recommendation': 'Configure the server to suppress version details in headers'
            },
            'ssl_weak_cipher': {
                'description': 'SSL/TLS server supports weak cipher suites',
                'severity': 'High',
                'cvss': 7.5,
                'recommendation': 'Disable weak cipher suites and use strong encryption'
            },
            'default_credentials': {
                'description': 'Service may be using default credentials',
                'severity': 'Critical',
                'cvss': 9.8,
                'recommendation': 'Change default usernames and passwords immediately'
            },
            'unencrypted_protocol': {
                'description': 'Service uses an unencrypted communication protocol',
                'severity': 'High',
                'cvss': 7.5,
                'recommendation': 'Migrate to an encrypted protocol variant (HTTPS, SFTP, etc.)'
            },
            'outdated_service': {
                'description': 'Service version is outdated and may contain known vulnerabilities',
                'severity': 'Medium',
                'cvss': 6.1,
                'recommendation': 'Update the service to the latest stable version'
            }
        }

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def is_port_open(self, host: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                return sock.connect_ex((host, port)) == 0
        except (socket.gaierror, socket.timeout):
            return False

    def grab_banner(self, host: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((host, port)) == 0:
                    if port in [80, 443, 8080, 8000]:
                        sock.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                    elif port not in [21, 22, 25]:
                        sock.send(b"\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    return banner[:200]
        except Exception:
            return ""
        return ""

    def detect_service_version(self, host: str, port: int, banner: str) -> Tuple[str, str]:
        service = self.common_ports.get(port, 'unknown')
        version = 'unknown'

        if banner:
            if 'Server:' in banner:
                m = re.search(r'Server:\s*([^\r\n]+)', banner)
                if m:
                    version = m.group(1).strip()
            elif banner.startswith('SSH-'):
                version = banner.split()[0] if banner.split() else banner
            elif port == 21 and ('FTP' in banner.upper() or '220' in banner):
                version = banner.split('\r\n')[0] if '\r\n' in banner else banner
            else:
                for pattern in [r'(\d+\.\d+\.\d+)', r'([A-Za-z]+/\d+\.\d+)', r'([A-Za-z]+ \d+\.\d+)']:
                    m = re.search(pattern, banner)
                    if m:
                        version = m.group(1)
                        break

        return service, version

    def scan_port(self, host: str, port: int) -> Optional[ScanResult]:
        if self.is_port_open(host, port):
            banner = self.grab_banner(host, port)
            service, version = self.detect_service_version(host, port, banner)
            result = ScanResult(host=host, port=port, state='open',
                                service=service, version=version, banner=banner)
            self.check_vulnerabilities(result)
            return result
        return None

    def check_vulnerabilities(self, result: ScanResult):
        host, port, service, version, banner = (
            result.host, result.port, result.service, result.version, result.banner
        )

        if port in [21, 23, 80, 110, 143]:
            info = self.vuln_db['unencrypted_protocol']
            self.vulnerabilities.append(Vulnerability(
                host=host, port=port, service=service,
                vulnerability='unencrypted_protocol',
                severity=info['severity'], description=info['description'],
                recommendation=info['recommendation'], cvss_score=info['cvss']
            ))

        if banner and any(k in banner.lower() for k in ['server:', 'version', 'apache', 'nginx', 'iis']):
            info = self.vuln_db['http_server_header']
            self.vulnerabilities.append(Vulnerability(
                host=host, port=port, service=service,
                vulnerability='information_disclosure',
                severity=info['severity'], description=info['description'],
                recommendation=info['recommendation'], cvss_score=info['cvss']
            ))

        if port in [3389, 5900, 1433, 3306]:
            info = self.vuln_db['default_credentials']
            self.vulnerabilities.append(Vulnerability(
                host=host, port=port, service=service,
                vulnerability='potential_default_credentials',
                severity=info['severity'], description=info['description'],
                recommendation=info['recommendation'], cvss_score=info['cvss']
            ))

        if port in [443, 993, 995] or 'ssl' in service.lower():
            self.check_ssl_vulnerabilities(host, port)

    def check_ssl_vulnerabilities(self, host: str, port: int):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher and cipher[2] < 128:
                        info = self.vuln_db['ssl_weak_cipher']
                        self.vulnerabilities.append(Vulnerability(
                            host=host, port=port, service='https',
                            vulnerability='weak_ssl_cipher',
                            severity=info['severity'],
                            description=f"Weak cipher detected: {cipher[0]}",
                            recommendation=info['recommendation'],
                            cvss_score=info['cvss']
                        ))
        except Exception:
            pass

    def scan_host_ports(self, host: str, ports: List[int]) -> List[ScanResult]:
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    self.scan_results.append(result)
        return results

    def scan_network_range(self, network: str, ports: List[int]) -> Dict[str, List[ScanResult]]:
        try:
            net = ipaddress.ip_network(network, strict=False)
            all_results = {}
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Scanning network: {network}")
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Hosts to scan: {net.num_addresses}")
            for ip in net.hosts():
                host = str(ip)
                print(f"{Colors.CYAN}[SCAN]{Colors.END} Scanning {host}...")
                results = self.scan_host_ports(host, ports)
                if results:
                    all_results[host] = results
                    print(f"{Colors.GREEN}[FOUND]{Colors.END} {len(results)} open ports on {host}")
            return all_results
        except ValueError as e:
            print(f"{Colors.RED}[ERROR]{Colors.END} Invalid network range: {e}")
            return {}

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def generate_risk_score(self) -> Dict[str, Any]:
        if not self.vulnerabilities:
            return {
                'overall_risk': 'Low', 'risk_score': 0.0,
                'total_vulns': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
            }

        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        total_cvss = 0.0
        for v in self.vulnerabilities:
            counts[v.severity] += 1
            total_cvss += v.cvss_score

        avg = total_cvss / len(self.vulnerabilities)

        if counts['Critical'] > 0 or avg >= 7.0:
            level = 'Critical'
        elif counts['High'] > 0 or avg >= 5.0:
            level = 'High'
        elif counts['Medium'] > 0 or avg >= 3.0:
            level = 'Medium'
        else:
            level = 'Low'

        return {
            'overall_risk': level, 'risk_score': round(avg, 2),
            'total_vulns': len(self.vulnerabilities),
            'critical': counts['Critical'], 'high': counts['High'],
            'medium': counts['Medium'], 'low': counts['Low']
        }

    # ------------------------------------------------------------------
    # Terminal output
    # ------------------------------------------------------------------

    def display_results(self, results: Dict[str, List[ScanResult]]):
        print(f"\n{Colors.BOLD}{Colors.GREEN}SCAN RESULTS{Colors.END}")
        print("=" * 70)

        total_ports = sum(len(r) for r in results.values())
        duration    = time.time() - self.start_time

        print(f"  Hosts with open ports : {len(results)}")
        print(f"  Open ports found      : {total_ports}")
        print(f"  Vulnerabilities found : {len(self.vulnerabilities)}")
        print(f"  Scan duration         : {duration:.2f}s\n")

        for host, host_results in results.items():
            print(f"{Colors.BOLD}{Colors.BLUE}{host}{Colors.END}")
            print("-" * 50)
            for r in sorted(host_results, key=lambda x: x.port):
                svc = r.service + (f" ({r.version})" if r.version != 'unknown' else "")
                print(f"  {Colors.GREEN}{r.port:>5}{Colors.END}/tcp  {svc}")
            print()

        if self.vulnerabilities:
            risk = self.generate_risk_score()
            print(f"{Colors.BOLD}{Colors.RED}VULNERABILITY ASSESSMENT{Colors.END}")
            print("=" * 70)
            print(f"  Overall risk  : {risk['overall_risk']}")
            print(f"  Avg CVSS      : {risk['risk_score']}")
            print(f"  Critical / High / Medium / Low : "
                  f"{risk['critical']} / {risk['high']} / {risk['medium']} / {risk['low']}\n")

            for i, v in enumerate(self.vulnerabilities, 1):
                print(f"[{i}] {v.host}:{v.port} ({v.service})  [{v.severity}  CVSS {v.cvss_score}]")
                print(f"    {v.description}")
                print(f"    Fix: {v.recommendation}\n")

    # ------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------

    def export_json(self, filename: str, results: Dict[str, List[ScanResult]]):
        data = {
            'scan_metadata': {
                'timestamp':   datetime.now().isoformat(),
                'total_hosts': len(results),
                'total_ports': sum(len(r) for r in results.values()),
                'scan_duration': round(time.time() - self.start_time, 2)
            },
            'risk_assessment': self.generate_risk_score(),
            'hosts': {host: [asdict(r) for r in rlist] for host, rlist in results.items()},
            'vulnerabilities': [asdict(v) for v in self.vulnerabilities]
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"{Colors.GREEN}[EXPORT]{Colors.END} JSON saved to {filename}")

    def export_csv(self, filename: str, results: Dict[str, List[ScanResult]]):
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['host', 'port', 'service', 'version', 'state', 'banner'])
            writer.writeheader()
            for host_results in results.values():
                for r in host_results:
                    writer.writerow(asdict(r))
        print(f"{Colors.GREEN}[EXPORT]{Colors.END} CSV saved to {filename}")

    def export_html_report(self, results: Dict[str, List[ScanResult]], filename: str = 'report.html'):
        """Build a professional Bootstrap report and write it to filename."""
        risk        = self.generate_risk_score()
        timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        duration    = round(time.time() - self.start_time, 2)
        total_ports = sum(len(r) for r in results.values())
        risk_level  = risk['overall_risk'].lower()

        # ---- host table rows ----------------------------------------
        host_blocks = ""
        for host, host_results in results.items():
            rows = ""
            for r in sorted(host_results, key=lambda x: x.port):
                ver     = r.version if r.version != 'unknown' else 'N/A'
                preview = (r.banner[:90] + '...') if len(r.banner) > 90 else r.banner
                rows += f"""
                <tr>
                  <td class="port-num">{r.port}</td>
                  <td>{r.service}</td>
                  <td>{ver}</td>
                  <td><span class="badge-open">open</span></td>
                  <td class="banner-text">{preview}</td>
                </tr>"""
            host_blocks += f"""
            <div class="host-block mb-3">
              <div class="host-title">{host}</div>
              <table class="table table-sm mb-0">
                <thead>
                  <tr>
                    <th>Port</th><th>Service</th><th>Version</th>
                    <th>State</th><th>Banner</th>
                  </tr>
                </thead>
                <tbody>{rows}
                </tbody>
              </table>
            </div>"""

        # ---- vulnerability cards ------------------------------------
        if self.vulnerabilities:
            vuln_cards = ""
            for v in self.vulnerabilities:
                sev = v.severity.lower()
                vuln_cards += f"""
            <div class="vuln-card {sev} mb-3">
              <div class="d-flex justify-content-between align-items-start mb-2">
                <span class="vuln-host">{v.host}:{v.port} - {v.service}</span>
                <span class="severity-pill {sev}">{v.severity} / CVSS {v.cvss_score}</span>
              </div>
              <div class="row g-3">
                <div class="col-12 col-md-6">
                  <div class="field-label">Issue</div>
                  <div>{v.description}</div>
                </div>
                <div class="col-12 col-md-6">
                  <div class="field-label">Recommendation</div>
                  <div>{v.recommendation}</div>
                </div>
              </div>
            </div>"""
        else:
            vuln_cards = '<p class="text-muted py-3">No vulnerabilities detected.</p>'

        # ---- priority actions ---------------------------------------
        priority = ""
        if risk['critical'] > 0:
            priority += '<p class="mb-2"><strong>Critical:</strong> Address critical findings immediately.</p>'
        if risk['high'] > 0:
            priority += '<p class="mb-2"><strong>High:</strong> Remediate within 24 to 48 hours.</p>'
        if risk['medium'] > 0:
            priority += '<p class="mb-2"><strong>Medium:</strong> Schedule remediation within the week.</p>'
        if risk['total_vulns'] == 0:
            priority += '<p class="mb-0">No vulnerabilities found. Continue routine monitoring.</p>'

        # ---- full HTML ----------------------------------------------
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Network Security Assessment Report</title>
  <link rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css">
  <style>
    :root {{
      --bg:       #f0f2f5;
      --surface:  #ffffff;
      --border:   #e2e6ea;
      --accent:   #1d3557;
      --accent2:  #457b9d;
      --text:     #1f2937;
      --muted:    #6b7280;
      --critical: #b91c1c;
      --high:     #c2410c;
      --medium:   #b45309;
      --low:      #1d4ed8;
    }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, sans-serif;
      font-size: 0.9rem;
    }}
    .page-header {{
      background: var(--accent);
      color: #fff;
      padding: 2rem 0 1.75rem;
      border-bottom: 3px solid var(--accent2);
    }}
    .page-header h1 {{
      font-size: 1.4rem;
      font-weight: 600;
      margin-bottom: 0.2rem;
      letter-spacing: -0.01em;
    }}
    .page-header .meta {{ color: #94a3b8; font-size: 0.78rem; }}
    .stat-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.4rem 1.5rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }}
    .stat-card .stat-value {{
      font-size: 2rem;
      font-weight: 700;
      color: var(--accent);
      line-height: 1;
    }}
    .stat-card .stat-label {{
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin-top: 0.4rem;
    }}
    .risk-banner {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-left: 4px solid transparent;
      border-radius: 8px;
      padding: 1.1rem 1.5rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }}
    .risk-banner.critical {{ border-left-color: var(--critical); }}
    .risk-banner.high     {{ border-left-color: var(--high); }}
    .risk-banner.medium   {{ border-left-color: var(--medium); }}
    .risk-banner.low      {{ border-left-color: #16a34a; }}
    .risk-cell .cell-label {{
      font-size: 0.65rem;
      text-transform: uppercase;
      letter-spacing: 0.09em;
      color: var(--muted);
      margin-bottom: 0.15rem;
    }}
    .risk-cell .cell-value {{
      font-size: 1.1rem;
      font-weight: 700;
      color: var(--accent);
    }}
    .risk-divider {{
      width: 1px;
      background: var(--border);
      align-self: stretch;
      margin: 0 0.5rem;
    }}
    .section-label {{
      font-size: 0.68rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.4rem;
      margin-bottom: 1rem;
    }}
    .nav-tabs {{ border-bottom-color: var(--border); }}
    .nav-tabs .nav-link {{
      color: var(--muted);
      border: none;
      border-bottom: 2px solid transparent;
      border-radius: 0;
      font-size: 0.83rem;
      font-weight: 500;
      padding: 0.6rem 1.1rem;
    }}
    .nav-tabs .nav-link:hover {{ color: var(--text); }}
    .nav-tabs .nav-link.active {{
      color: var(--accent);
      border-bottom-color: var(--accent);
      background: transparent;
    }}
    .host-block {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }}
    .host-title {{
      background: #f8fafc;
      border-bottom: 1px solid var(--border);
      padding: 0.6rem 1rem;
      font-family: 'Courier New', monospace;
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--accent2);
    }}
    .table {{ color: var(--text); margin-bottom: 0; }}
    .table thead th {{
      background: var(--accent);
      color: #cbd5e1;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      border: none;
      padding: 0.55rem 1rem;
    }}
    .table tbody td {{
      padding: 0.6rem 1rem;
      vertical-align: middle;
      font-size: 0.85rem;
      border-color: var(--border);
    }}
    .table tbody tr:last-child td {{ border-bottom: none; }}
    .table tbody tr:hover {{ background: #f8fafc; }}
    .port-num {{
      font-family: 'Courier New', monospace;
      font-weight: 600;
      color: var(--accent);
    }}
    .badge-open {{
      background: #dcfce7;
      color: #15803d;
      font-size: 0.68rem;
      font-weight: 600;
      padding: 0.2em 0.7em;
      border-radius: 20px;
      letter-spacing: 0.03em;
    }}
    .banner-text {{
      font-family: 'Courier New', monospace;
      font-size: 0.72rem;
      color: var(--muted);
    }}
    .vuln-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-left: 3px solid transparent;
      border-radius: 8px;
      padding: 1rem 1.25rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }}
    .vuln-card.critical {{ border-left-color: var(--critical); }}
    .vuln-card.high     {{ border-left-color: var(--high); }}
    .vuln-card.medium   {{ border-left-color: var(--medium); }}
    .vuln-card.low      {{ border-left-color: var(--low); }}
    .vuln-host {{
      font-family: 'Courier New', monospace;
      font-size: 0.78rem;
      color: var(--muted);
    }}
    .severity-pill {{
      font-size: 0.65rem;
      font-weight: 600;
      padding: 0.25em 0.7em;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      white-space: nowrap;
    }}
    .severity-pill.critical {{ background: #fee2e2; color: var(--critical); }}
    .severity-pill.high     {{ background: #ffedd5; color: var(--high); }}
    .severity-pill.medium   {{ background: #fef3c7; color: var(--medium); }}
    .severity-pill.low      {{ background: #dbeafe; color: var(--low); }}
    .field-label {{
      font-size: 0.65rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin-bottom: 0.2rem;
    }}
    .rec-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem 1.5rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }}
    .page-footer {{
      border-top: 1px solid var(--border);
      padding: 1.25rem 0;
      font-size: 0.75rem;
      color: var(--muted);
    }}
  </style>
</head>
<body>

<div class="page-header">
  <div class="container">
    <h1>Network Security Assessment Report</h1>
    <div class="meta mt-1">Generated: {timestamp} &nbsp; | &nbsp; Tool v2.0</div>
  </div>
</div>

<div class="container py-4">

  <div class="row g-3 mb-4">
    <div class="col-6 col-md-3">
      <div class="stat-card">
        <div class="stat-value">{len(results)}</div>
        <div class="stat-label">Hosts Scanned</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="stat-card">
        <div class="stat-value">{total_ports}</div>
        <div class="stat-label">Open Ports</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="stat-card">
        <div class="stat-value">{risk['total_vulns']}</div>
        <div class="stat-label">Vulnerabilities</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="stat-card">
        <div class="stat-value">{duration}s</div>
        <div class="stat-label">Scan Duration</div>
      </div>
    </div>
  </div>

  <div class="risk-banner {risk_level} mb-4">
    <div class="d-flex align-items-center flex-wrap gap-3">
      <div class="risk-cell">
        <div class="cell-label">Overall Risk</div>
        <div class="cell-value">{risk['overall_risk']}</div>
      </div>
      <div class="risk-divider d-none d-md-block"></div>
      <div class="risk-cell">
        <div class="cell-label">Avg CVSS</div>
        <div class="cell-value">{risk['risk_score']}</div>
      </div>
      <div class="risk-divider d-none d-md-block"></div>
      <div class="risk-cell">
        <div class="cell-label">Critical</div>
        <div class="cell-value">{risk['critical']}</div>
      </div>
      <div class="risk-cell ms-3">
        <div class="cell-label">High</div>
        <div class="cell-value">{risk['high']}</div>
      </div>
      <div class="risk-cell ms-3">
        <div class="cell-label">Medium</div>
        <div class="cell-value">{risk['medium']}</div>
      </div>
      <div class="risk-cell ms-3">
        <div class="cell-label">Low</div>
        <div class="cell-value">{risk['low']}</div>
      </div>
    </div>
  </div>

  <ul class="nav nav-tabs mb-4" id="reportTabs">
    <li class="nav-item">
      <a class="nav-link active" data-bs-toggle="tab" href="#hosts">Discovered Hosts</a>
    </li>
    <li class="nav-item">
      <a class="nav-link" data-bs-toggle="tab" href="#vulns">Vulnerabilities</a>
    </li>
    <li class="nav-item">
      <a class="nav-link" data-bs-toggle="tab" href="#recs">Recommendations</a>
    </li>
  </ul>

  <div class="tab-content">

    <div class="tab-pane fade show active" id="hosts">
      <div class="section-label">Hosts and Open Services</div>
      {host_blocks}
    </div>

    <div class="tab-pane fade" id="vulns">
      <div class="section-label">Findings</div>
      {vuln_cards}
    </div>

    <div class="tab-pane fade" id="recs">
      <div class="section-label">Priority Actions</div>
      <div class="rec-card">{priority}</div>
    </div>

  </div>
</div>

<div class="page-footer">
  <div class="container d-flex justify-content-between flex-wrap gap-2">
    <span>Network Vulnerability Scanner and Risk Assessment Tool v2.0</span>
    <span>This report contains sensitive security information. Handle with care.</span>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

        print(f"{Colors.GREEN}[EXPORT]{Colors.END} HTML report written to {filename}")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def parse_port_range(port_string: str) -> List[int]:
    ports = []
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-', 1))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Network Vulnerability Scanner and Risk Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 -p 1-1000
  %(prog)s -t 192.168.1.0/24 --top-ports
  %(prog)s -t scanme.nmap.org --top-ports -o results.json
  %(prog)s -t scanme.nmap.org -p 1-65535 --csv ports.csv
        """
    )

    parser.add_argument('-t', '--target',   required=True,
                        help='Target IP or network range (e.g. 192.168.1.1 or 192.168.1.0/24)')
    parser.add_argument('-p', '--ports',    default='1-1000',
                        help='Port range (e.g. 1-1000, 22,80,443)')
    parser.add_argument('--top-ports',      action='store_true',
                        help='Scan the 20 most common ports')
    parser.add_argument('--threads',        type=int, default=100,
                        help='Thread count (default: 100)')
    parser.add_argument('--timeout',        type=int, default=3,
                        help='Connection timeout in seconds (default: 3)')
    parser.add_argument('-o', '--output',
                        help='Export results to a JSON file')
    parser.add_argument('--csv',
                        help='Export results to a CSV file')
    parser.add_argument('-v', '--verbose',  action='store_true',
                        help='Verbose output')

    args    = parser.parse_args()
    scanner = NetworkScanner(threads=args.threads, timeout=args.timeout)

    if args.top_ports:
        ports = list(scanner.common_ports.keys())
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Scanning top {len(ports)} common ports")
    else:
        try:
            ports = parse_port_range(args.ports)
            if len(ports) > 10000:
                print(f"{Colors.YELLOW}[WARNING]{Colors.END} {len(ports)} ports selected. This may take a while.")
                if input("Continue? (y/N): ").lower() not in ['y', 'yes']:
                    print(f"{Colors.RED}[ABORT]{Colors.END} Cancelled.")
                    sys.exit(1)
        except ValueError as e:
            print(f"{Colors.RED}[ERROR]{Colors.END} Invalid port range: {e}")
            sys.exit(1)

    print(f"{Colors.YELLOW}[INFO]{Colors.END} Target  : {args.target}")
    print(f"{Colors.YELLOW}[INFO]{Colors.END} Ports   : {len(ports)}")
    print(f"{Colors.YELLOW}[INFO]{Colors.END} Threads : {args.threads}")
    print(f"{Colors.YELLOW}[INFO]{Colors.END} Timeout : {args.timeout}s")

    scanner.start_time = time.time()

    try:
        if '/' in args.target:
            results = scanner.scan_network_range(args.target, ports)
        else:
            host_results = scanner.scan_host_ports(args.target, ports)
            results = {args.target: host_results} if host_results else {}

        if results:
            scanner.display_results(results)
            scanner.export_html_report(results)          # always writes report.html

            if args.output:
                scanner.export_json(args.output, results)
            if args.csv:
                scanner.export_csv(args.csv, results)
        else:
            print(f"{Colors.YELLOW}[INFO]{Colors.END} No open ports found.")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO]{Colors.END} Scan interrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    print(f"\n{Colors.GREEN}[DONE]{Colors.END} Scan complete.")


if __name__ == "__main__":
    main()