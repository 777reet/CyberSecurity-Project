#!/usr/bin/env python3
"""
Network Vulnerability Scanner & Risk Assessment Tool
Professional cybersecurity tool for network reconnaissance and vulnerability assessment
Author: Security Analyst
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
import subprocess
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

@dataclass
class Vulnerability:
    """Data structure for vulnerability findings"""
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
    """Data structure for scan results"""
    host: str
    port: int
    state: str
    service: str
    version: str
    banner: str

class NetworkScanner:
    def __init__(self, threads=100, timeout=3):
        self.threads = threads
        self.timeout = timeout
        self.scan_results = []
        self.vulnerabilities = []
        self.start_time = None
        
        # Common ports and services
        self.common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps',
            995: 'pop3s', 1433: 'mssql', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 27017: 'mongodb'
        }
        
        # Vulnerability database
        self.vuln_db = {
            'weak_ssh': {
                'description': 'SSH server allows weak authentication methods',
                'severity': 'Medium',
                'cvss': 5.3,
                'recommendation': 'Disable password authentication, use key-based authentication'
            },
            'http_server_header': {
                'description': 'HTTP server reveals version information',
                'severity': 'Low',
                'cvss': 2.6,
                'recommendation': 'Configure server to hide version information'
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
                'description': 'Service uses unencrypted communication protocol',
                'severity': 'High',
                'cvss': 7.5,
                'recommendation': 'Migrate to encrypted protocol variant (HTTPS, SFTP, etc.)'
            },
            'outdated_service': {
                'description': 'Service version is outdated and may contain vulnerabilities',
                'severity': 'Medium',
                'cvss': 6.1,
                'recommendation': 'Update service to the latest stable version'
            }
        }

    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║              Network Vulnerability Scanner                ║
║                  & Risk Assessment Tool                   ║
║                                                           ║
║  Professional Security Assessment Framework v2.0         ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(banner)

    def is_port_open(self, host: str, port: int) -> bool:
        """Check if a specific port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except (socket.gaierror, socket.timeout):
            return False

    def grab_banner(self, host: str, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                # Use connect_ex to handle mid-scan disconnects safely
            if sock.connect_ex((host, port)) == 0:
             # proceed with send/recv
                
                # Send HTTP request for web servers
                if port in [80, 443, 8080, 8000]:
                    request = b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
                  # If port 443, the socket should ideally be wrapped, but adding 443 here 
                 # at least attempts the request if the handshake was handled elsewhere.
                    sock.send(request)
                elif port == 21:  # FTP
                    pass  # FTP sends banner immediately
                elif port == 22:  # SSH
                    pass  # SSH sends version immediately
                elif port == 25:  # SMTP
                    pass  # SMTP sends banner immediately
                else:
                    sock.send(b"\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:200]  # Limit banner length
        except:
            return ""

    def detect_service_version(self, host: str, port: int, banner: str) -> Tuple[str, str]:
        """Detect service name and version from banner"""
        service = self.common_ports.get(port, 'unknown')
        version = 'unknown'
        
        if banner:
            # HTTP Server detection
            if 'Server:' in banner:
                server_match = re.search(r'Server:\s*([^\r\n]+)', banner)
                if server_match:
                    version = server_match.group(1).strip()
            
            # SSH version detection
            elif banner.startswith('SSH-'):
                version = banner.split()[0] if banner.split() else banner
            
            # FTP version detection
            elif port == 21 and ('FTP' in banner.upper() or '220' in banner):
                version = banner.split('\r\n')[0] if '\r\n' in banner else banner
            
            # Generic version extraction
            else:
                version_patterns = [
                    r'(\d+\.\d+\.\d+)',  # Version numbers like 1.2.3
                    r'([A-Za-z]+/\d+\.\d+)',  # Service/version like Apache/2.4
                    r'([A-Za-z]+ \d+\.\d+)'  # Service version like OpenSSH 7.4
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, banner)
                    if match:
                        version = match.group(1)
                        break
        
        return service, version

    def scan_port(self, host: str, port: int) -> Optional[ScanResult]:
        """Scan a single port"""
        if self.is_port_open(host, port):
            banner = self.grab_banner(host, port)
            service, version = self.detect_service_version(host, port, banner)
            
            result = ScanResult(
                host=host,
                port=port,
                state='open',
                service=service,
                version=version,
                banner=banner
            )
            
            # Check for vulnerabilities
            self.check_vulnerabilities(result)
            return result
        return None

    def check_vulnerabilities(self, result: ScanResult):
        """Check for common vulnerabilities"""
        host, port, service, version, banner = result.host, result.port, result.service, result.version, result.banner
        
        # Check for unencrypted protocols
        if port in [21, 23, 80, 110, 143]:  # FTP, Telnet, HTTP, POP3, IMAP
            vuln_info = self.vuln_db['unencrypted_protocol']
            vuln = Vulnerability(
                host=host,
                port=port,
                service=service,
                vulnerability='unencrypted_protocol',
                severity=vuln_info['severity'],
                description=vuln_info['description'],
                recommendation=vuln_info['recommendation'],
                cvss_score=vuln_info['cvss']
            )
            self.vulnerabilities.append(vuln)
        
        # Check for information disclosure
        if banner and any(keyword in banner.lower() for keyword in ['server:', 'version', 'apache', 'nginx', 'iis']):
            vuln_info = self.vuln_db['http_server_header']
            vuln = Vulnerability(
                host=host,
                port=port,
                service=service,
                vulnerability='information_disclosure',
                severity=vuln_info['severity'],
                description=vuln_info['description'],
                recommendation=vuln_info['recommendation'],
                cvss_score=vuln_info['cvss']
            )
            self.vulnerabilities.append(vuln)
        
        # Check for potentially default services
        if port in [3389, 5900, 1433, 3306]:  # RDP, VNC, MSSQL, MySQL
            vuln_info = self.vuln_db['default_credentials']
            vuln = Vulnerability(
                host=host,
                port=port,
                service=service,
                vulnerability='potential_default_credentials',
                severity=vuln_info['severity'],
                description=vuln_info['description'],
                recommendation=vuln_info['recommendation'],
                cvss_score=vuln_info['cvss']
            )
            self.vulnerabilities.append(vuln)
        
        # SSL/TLS vulnerability check
        if port in [443, 993, 995] or 'ssl' in service.lower():
            self.check_ssl_vulnerabilities(host, port)

    def check_ssl_vulnerabilities(self, host: str, port: int):
        """Check SSL/TLS configuration for vulnerabilities"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check for weak ciphers
                    if cipher and cipher[2] < 128:  # Key length less than 128 bits
                        vuln_info = self.vuln_db['ssl_weak_cipher']
                        vuln = Vulnerability(
                            host=host,
                            port=port,
                            service='https',
                            vulnerability='weak_ssl_cipher',
                            severity=vuln_info['severity'],
                            description=f"Weak cipher detected: {cipher[0]}",
                            recommendation=vuln_info['recommendation'],
                            cvss_score=vuln_info['cvss']
                        )
                        self.vulnerabilities.append(vuln)
        except:
            pass  # SSL check failed, service might not support SSL

    def scan_host_ports(self, host: str, ports: List[int]) -> List[ScanResult]:
        """Scan multiple ports on a host"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.scan_port, host, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    results.append(result)
                    self.scan_results.append(result)
        
        return results

    def scan_network_range(self, network: str, ports: List[int]) -> Dict[str, List[ScanResult]]:
        """Scan a network range"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            all_results = {}
            
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Scanning network: {network}")
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Target ports: {len(ports)} ports")
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

    def generate_risk_score(self) -> Dict[str, Any]:
        """Calculate overall risk assessment"""
        if not self.vulnerabilities:
            return {
                'overall_risk': 'Low',
                'risk_score': 0.0,
                'total_vulns': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        total_cvss = 0.0
        
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] += 1
            total_cvss += vuln.cvss_score
        
        avg_cvss = total_cvss / len(self.vulnerabilities)
        
        # Determine overall risk level
        if severity_counts['Critical'] > 0 or avg_cvss >= 7.0:
            overall_risk = 'Critical'
        elif severity_counts['High'] > 0 or avg_cvss >= 5.0:
            overall_risk = 'High'
        elif severity_counts['Medium'] > 0 or avg_cvss >= 3.0:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'
        
        return {
            'overall_risk': overall_risk,
            'risk_score': round(avg_cvss, 2),
            'total_vulns': len(self.vulnerabilities),
            'critical': severity_counts['Critical'],
            'high': severity_counts['High'],
            'medium': severity_counts['Medium'],
            'low': severity_counts['Low']
        }

    def display_results(self, results: Dict[str, List[ScanResult]]):
        """Display scan results in terminal"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}SCAN RESULTS{Colors.END}")
        print("=" * 80)
        
        total_hosts = len(results)
        total_ports = sum(len(host_results) for host_results in results.values())
        
        print(f"{Colors.CYAN}Scan Summary:{Colors.END}")
        print(f"  • Hosts scanned: {total_hosts}")
        print(f"  • Open ports found: {total_ports}")
        print(f"  • Vulnerabilities detected: {len(self.vulnerabilities)}")
        print(f"  • Scan duration: {time.time() - self.start_time:.2f} seconds\n")
        
        # Display open ports by host
        for host, host_results in results.items():
            print(f"{Colors.BOLD}{Colors.BLUE}Host: {host}{Colors.END}")
            print("-" * 60)
            
            for result in sorted(host_results, key=lambda x: x.port):
                service_info = f"{result.service}"
                if result.version != 'unknown':
                    service_info += f" ({result.version})"
                
                print(f"  {Colors.GREEN}{result.port:>5}{Colors.END}/tcp  "
                      f"{Colors.WHITE}{service_info:<25}{Colors.END} "
                      f"{Colors.YELLOW}{result.state}{Colors.END}")
            print()
        
        # Display vulnerabilities
        if self.vulnerabilities:
            print(f"{Colors.BOLD}{Colors.RED}VULNERABILITY ASSESSMENT{Colors.END}")
            print("=" * 80)
            
            risk_assessment = self.generate_risk_score()
            
            # Risk summary
            risk_color = {
                'Critical': Colors.RED,
                'High': Colors.RED,
                'Medium': Colors.YELLOW,
                'Low': Colors.GREEN
            }[risk_assessment['overall_risk']]
            
            print(f"{Colors.BOLD}Risk Assessment Summary:{Colors.END}")
            print(f"  • Overall Risk Level: {risk_color}{risk_assessment['overall_risk']}{Colors.END}")
            print(f"  • Average CVSS Score: {risk_assessment['risk_score']}")
            print(f"  • Critical: {risk_assessment['critical']}")
            print(f"  • High: {risk_assessment['high']}")
            print(f"  • Medium: {risk_assessment['medium']}")
            print(f"  • Low: {risk_assessment['low']}\n")
            
            # Detailed vulnerabilities
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_color = {
                    'Critical': Colors.RED,
                    'High': Colors.RED,
                    'Medium': Colors.YELLOW,
                    'Low': Colors.CYAN
                }[vuln.severity]
                
                print(f"{Colors.BOLD}[{i}] {vuln.host}:{vuln.port} - {vuln.service}{Colors.END}")
                print(f"    Severity: {severity_color}{vuln.severity}{Colors.END} (CVSS: {vuln.cvss_score})")
                print(f"    Issue: {vuln.description}")
                print(f"    Recommendation: {vuln.recommendation}")
                print()

    def export_json(self, filename: str, results: Dict[str, List[ScanResult]]):
        """Export results to JSON format"""
        export_data = {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_hosts': len(results),
                'total_ports': sum(len(host_results) for host_results in results.values()),
                'scan_duration': round(time.time() - self.start_time, 2)
            },
            'risk_assessment': self.generate_risk_score(),
            'hosts': {},
            'vulnerabilities': [asdict(vuln) for vuln in self.vulnerabilities]
        }
        
        for host, host_results in results.items():
            export_data['hosts'][host] = [asdict(result) for result in host_results]
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"{Colors.GREEN}[EXPORT]{Colors.END} Results exported to {filename}")

    def export_csv(self, filename: str, results: Dict[str, List[ScanResult]]):
        """Export results to CSV format"""
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['host', 'port', 'service', 'version', 'state', 'banner']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for host, host_results in results.items():
                for result in host_results:
                    writer.writerow(asdict(result))
        
        print(f"{Colors.GREEN}[EXPORT]{Colors.END} Results exported to {filename}")

    def export_html_report(self, filename: str, results: Dict[str, List[ScanResult]]):
        """Generate professional HTML report"""
        risk_assessment = self.generate_risk_score()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Vulnerability Assessment Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #2c3e50; margin: 0; font-size: 2.5em; }}
        .header p {{ color: #7f8c8d; margin: 10px 0 0 0; font-size: 1.1em; }}
        .risk-summary {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .risk-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }}
        .risk-card {{ background: rgba(255,255,255,0.1); padding: 15px; border-radius: 5px; text-align: center; }}
        .risk-card h3 {{ margin: 0 0 5px 0; font-size: 2em; }}
        .risk-card p {{ margin: 0; opacity: 0.9; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .host-section {{ background: #ecf0f1; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .host-section h3 {{ color: #2c3e50; margin-top: 0; }}
        .port-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        .port-table th, .port-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #bdc3c7; }}
        .port-table th {{ background: #34495e; color: white; }}
        .port-table tr:hover {{ background: #f8f9fa; }}
        .vuln-item {{ background: #fff; border-left: 5px solid #e74c3c; padding: 15px; margin-bottom: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .vuln-critical {{ border-left-color: #c0392b; }}
        .vuln-high {{ border-left-color: #e74c3c; }}
        .vuln-medium {{ border-left-color: #f39c12; }}
        .vuln-low {{ border-left-color: #3498db; }}
        .severity {{ padding: 4px 8px; border-radius: 4px; color: white; font-weight: bold; }}
        .severity.critical {{ background: #c0392b; }}
        .severity.high {{ background: #e74c3c; }}
        .severity.medium {{ background: #f39c12; }}
        .severity.low {{ background: #3498db; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #bdc3c7; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Network Vulnerability Assessment Report</h1>
            <p>Generated on {timestamp}</p>
        </div>
        
        <div class="risk-summary">
            <h2 style="margin-top: 0;">Executive Summary</h2>
            <p>Overall Risk Level: <strong>{risk_assessment['overall_risk']}</strong> | Average CVSS Score: <strong>{risk_assessment['risk_score']}</strong></p>
            <div class="risk-grid">
                <div class="risk-card">
                    <h3>{len(results)}</h3>
                    <p>Hosts Scanned</p>
                </div>
                <div class="risk-card">
                    <h3>{sum(len(host_results) for host_results in results.values())}</h3>
                    <p>Open Ports</p>
                </div>
                <div class="risk-card">
                    <h3>{risk_assessment['total_vulns']}</h3>
                    <p>Vulnerabilities</p>
                </div>
                <div class="risk-card">
                    <h3>{risk_assessment['critical'] + risk_assessment['high']}</h3>
                    <p>High Risk Issues</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Discovered Hosts & Services</h2>
        """
        
        for host, host_results in results.items():
            html_content += f"""
            <div class="host-section">
                <h3>Host: {host}</h3>
                <table class="port-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>State</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for result in sorted(host_results, key=lambda x: x.port):
                html_content += f"""
                        <tr>
                            <td>{result.port}</td>
                            <td>{result.service}</td>
                            <td>{result.version if result.version != 'unknown' else 'N/A'}</td>
                            <td>{result.state}</td>
                        </tr>
                """
            
            html_content += """
                    </tbody>
                </table>
            </div>
            """
        
        if self.vulnerabilities:
            html_content += """
        </div>
        
        <div class="section">
            <h2>Vulnerability Details</h2>
            """
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_class = vuln.severity.lower()
                html_content += f"""
            <div class="vuln-item vuln-{severity_class}">
                <h4>[{i}] {vuln.host}:{vuln.port} - {vuln.service}</h4>
                <p><span class="severity {severity_class}">{vuln.severity}</span> CVSS Score: {vuln.cvss_score}</p>
                <p><strong>Description:</strong> {vuln.description}</p>
                <p><strong>Recommendation:</strong> {vuln.recommendation}</p>
            </div>
                """
        
        html_content += """
        </div>
        
        <div class="footer">
            <p>This report was generated by Network Vulnerability Scanner & Risk Assessment Tool</p>
            <p>For questions regarding this assessment, please contact your security team.</p>
        </div>
    </div>
</body>
</html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        print(f"{Colors.GREEN}[EXPORT]{Colors.END} HTML report generated: {filename}")

def parse_port_range(port_string: str) -> List[int]:
    """Parse port range string into list of ports"""
    ports = []
    
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-', 1))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return sorted(list(set(ports)))

def main():
    parser = argparse.ArgumentParser(
        description='Network Vulnerability Scanner & Risk Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 -p 1-1000                    # Scan single host, ports 1-1000
  %(prog)s -t 192.168.1.0/24 -p 22,80,443,3389         # Scan network range, specific ports
  %(prog)s -t 10.0.0.1 --top-ports -o results.json    # Scan top ports, export JSON
  %(prog)s -t scanme.nmap.org -p 1-65535 --html        # Full port scan with HTML report
        """
    )
    
    parser.add_argument('-t', '--target', required=True, 
                       help='Target IP address or network range (e.g., 192.168.1.1 or 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', default='1-1000',
                       help='Port range to scan (e.g., 1-1000, 22,80,443, 1-65535)')
    parser.add_argument('--top-ports', action='store_true',
                       help='Scan only the most common ports')
    parser.add_argument('--threads', type=int, default=100,
                       help='Number of threads to use (default: 100)')
    parser.add_argument('--timeout', type=int, default=3,
                       help='Connection timeout in seconds (default: 3)')
    parser.add_argument('-o', '--output', 
                       help='Output file for JSON export')
    parser.add_argument('--csv',
                       help='Export results to CSV file')
    parser.add_argument('--html', nargs='?', const='scan_report.html',
                        help='Generate HTML report (optional: provide filename)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--no-banner', action='store_true',
                       help='Disable banner display')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = NetworkScanner(threads=args.threads, timeout=args.timeout)
    
    if not args.no_banner:
        scanner.print_banner()
    
    # Determine ports to scan
    if args.top_ports:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379]
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Using top 20 common ports")
    else:
        try:
            ports = parse_port_range(args.ports)
            if len(ports) > 10000:
                print(f"{Colors.YELLOW}[WARNING]{Colors.END} Scanning {len(ports)} ports may take significant time")
                response = input(f"{Colors.CYAN}Continue? (y/N): {Colors.END}")
                if response.lower() not in ['y', 'yes']:
                    print(f"{Colors.RED}[ABORT]{Colors.END} Scan cancelled by user")
                    sys.exit(1)
        except ValueError as e:
            print(f"{Colors.RED}[ERROR]{Colors.END} Invalid port range: {e}")
            sys.exit(1)
    
    print(f"{Colors.YELLOW}[INFO]{Colors.END} Starting scan of {args.target}")
    print(f"{Colors.YELLOW}[INFO]{Colors.END} Ports: {len(ports)} ports")
    print(f"{Colors.YELLOW}[INFO]{Colors.END} Threads: {args.threads}")
    print(f"{Colors.YELLOW}[INFO]{Colors.END} Timeout: {args.timeout}s")
    
    scanner.start_time = time.time()
    
    # Perform scan
    try:
        if '/' in args.target:  # Network range
            results = scanner.scan_network_range(args.target, ports)
        else:  # Single host
            host_results = scanner.scan_host_ports(args.target, ports)
            results = {args.target: host_results} if host_results else {}
        
        # Display results
        if results:
            scanner.display_results(results)
            
            # Export results
            if args.output:
                scanner.export_json(args.output, results)
            
            if args.csv:
                scanner.export_csv(args.csv, results)
            
            if args.html:
                scanner.export_html_report(args.html, results)
            
            # Auto-generate HTML report if vulnerabilities found
            elif scanner.vulnerabilities:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                auto_report = f"vulnerability_report_{timestamp}.html"
                scanner.export_html_report(auto_report, results)
        
        else:
            print(f"{Colors.YELLOW}[INFO]{Colors.END} No open ports found on target(s)")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO]{Colors.END} Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    print(f"\n{Colors.GREEN}[COMPLETE]{Colors.END} Scan finished successfully")

if __name__ == "__main__":
    main()




"""Testing Commands


    Network Vulnerability Scanner - Usage Guide
Official Test Targets
Scan the Nmap official test server with top common ports and generate an HTML report:
python code.py -t scanme.nmap.org --top-ports --html dashboard.html


SSL/TLS security assessment on port 443:
python code.py -t testssl.sh -p 443 --html ssl_dashboard.html


Local Testing
Quick localhost scan on common ports:
python code.py -t 127.0.0.1 --top-ports --html dashboard.html


Scan Windows-specific ports (RPC, NetBIOS, SMB, RDP) with verbose output:
python code.py -t 127.0.0.1 -p 135,139,445,3389 -v


Scan common web development ports:
python code.py -t 127.0.0.1 -p 3000,8000,8080,9000 --html webdev_scan.html
Network Assessment
Scan your home router gateway (replace 192.168.1.1 with your actual IP):
python code.py -t 192.168.1.1 -p 22,80,443,8080 --html router_scan.html
Scan an entire subnet on common ports:
python code.py -t 192.168.1.0/24 --top-ports --html network_scan.html
Professional Demonstration
Full port scan (1-1000) with multiple output formats:
python code.py -t scanme.nmap.org -p 1-1000 --html demo_report.html -o data.json --csv ports.csv
High-performance scanning with increased threads and reduced timeout:
python code.py -t scanme.nmap.org -p 1-5000 --threads 200 --timeout 2 -v
Quick professional demo report:
python code.py -t scanme.nmap.org --top-ports --html professional_demo.html


"""