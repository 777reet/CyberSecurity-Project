"""
AegisScan: High-Performance Multi-Threaded Network Reconnaissance Engine
Executes concurrent TCP SYN/Connect port scans, banner fingerprinting,
socket round-trip latency measurements, and coordinates multi-vector security modules.
"""

import ipaddress
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Callable

from core.cve_intel import correlate_service_cves, calculate_cvss31, CVSSMetrics
from core.crypto_audit import audit_ssl_tls
from core.dns_audit import audit_dns_and_email_spoofing
from core.remediation import (
    generate_header_remediation,
    generate_sensitive_path_remediation,
    generate_ssl_remediation,
    generate_dns_remediation,
    generate_port_firewall_remediation
)


COMMON_PORTS_CATALOG = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote Shell)",
    25: "SMTP (Simple Mail Transfer)",
    53: "DNS (Domain Name System)",
    80: "HTTP (World Wide Web)",
    110: "POP3 (Post Office Protocol v3)",
    111: "RPCBind / Sun RPC",
    135: "MSRPC (Microsoft RPC)",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access Protocol)",
    389: "LDAP (Lightweight Directory Access)",
    443: "HTTPS (HTTP over TLS/SSL)",
    445: "SMB / Microsoft-DS",
    465: "SMTPS (SMTP over SSL)",
    587: "SMTP Submission",
    993: "IMAPS (IMAP over SSL)",
    995: "POP3S (POP3 over SSL)",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    2049: "NFS (Network File System)",
    3000: "Node.js / React Dev Server",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5000: "Flask / Python Web Service",
    5432: "PostgreSQL Database",
    5900: "VNC (Virtual Network Computing)",
    6379: "Redis In-Memory Data Store",
    8000: "HTTP Alt / Django / Python",
    8080: "HTTP Proxy / Tomcat / Spring",
    8443: "HTTPS Alt / Cloud Web Service",
    8888: "Jupyter / HTTP Alt",
    9000: "SonarQube / PHP-FPM / Microservice",
    9200: "Elasticsearch REST API",
    27017: "MongoDB Database"
}

PRESET_PROFILES = {
    "quick": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443],
    "web": [80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000, 9200],
    "databases": [1433, 1521, 3306, 5432, 6379, 9200, 27017],
    "infrastructure": [21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 3389, 5900],
    "standard": list(COMMON_PORTS_CATALOG.keys())
}


@dataclass
class DiscoveredPort:
    port: int
    state: str
    service: str
    version: str
    banner: str
    latency_ms: float


class AegisReconEngine:
    def __init__(self, threads: int = 60, timeout: float = 2.5):
        self.threads = threads
        self.timeout = timeout

    def check_port(self, host: str, port: int) -> Optional[DiscoveredPort]:
        """Probes a single TCP port, measures latency, and extracts service banner."""
        start_time = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((host, port)) == 0:
                    latency = round((time.perf_counter() - start_time) * 1000, 2)
                    banner = self.grab_banner(sock, host, port)
                    service, version = self.identify_service(port, banner)
                    return DiscoveredPort(
                        port=port,
                        state="open",
                        service=service,
                        version=version,
                        banner=banner,
                        latency_ms=latency
                    )
        except Exception:
            return None
        return None

    def grab_banner(self, connected_sock: socket.socket, host: str, port: int) -> str:
        """Extracts application banner or greeting string from an open socket."""
        try:
            connected_sock.settimeout(1.5)
            # Web ports: send basic HTTP HEAD request
            if port in [80, 443, 3000, 5000, 8000, 8080, 8443, 8888]:
                payload = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: AegisScan/3.0\r\nConnection: close\r\n\r\n"
                connected_sock.sendall(payload.encode("utf-8"))
            elif port == 6379:
                connected_sock.sendall(b"PING\r\n")
            elif port not in [21, 22, 25, 110]:
                connected_sock.sendall(b"\r\n")

            data = connected_sock.recv(1024)
            banner = data.decode("utf-8", errors="ignore").strip()
            return banner[:200]
        except Exception:
            return ""

    def identify_service(self, port: int, banner: str) -> Tuple[str, str]:
        """Infers service title and version from port and banner content."""
        service = COMMON_PORTS_CATALOG.get(port, f"Custom Port {port}")
        version = "Unknown"

        if banner:
            # Check for SSH
            if banner.startswith("SSH-"):
                service = "SSH"
                version = banner.split("\r\n")[0].replace("SSH-", "").strip()
            # Check for HTTP Server
            elif "Server:" in banner:
                service = "HTTPS" if port in [443, 8443] else "HTTP"
                m = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
                if m:
                    version = m.group(1).strip()
            # Check for FTP
            elif "FTP" in banner.upper() or banner.startswith("220"):
                service = "FTP"
                m = re.search(r"([A-Za-z]+FTP[A-Za-z0-9\-_./ ]+)", banner, re.IGNORECASE)
                if m:
                    version = m.group(1).strip()
                else:
                    version = banner.split("\r\n")[0]
            # Check for Redis
            elif "+PONG" in banner or "PONG" in banner:
                service = "Redis"
                version = "Active Redis Instance"
            # Generic version regex
            else:
                for pattern in [r"([a-zA-Z_\-]+[ /]\d+\.\d+(\.\d+)?)", r"(\d+\.\d+\.\d+)"]:
                    m = re.search(pattern, banner)
                    if m:
                        version = m.group(0)
                        break

        return service, version

    def scan_ports(
        self,
        host: str,
        ports: List[int],
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> List[DiscoveredPort]:
        """Scans list of ports concurrently using thread pool."""
        open_ports: List[DiscoveredPort] = []
        total = len(ports)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.check_port, host, p): p for p in ports}
            for future in as_completed(future_to_port):
                completed += 1
                result = future.result()
                if result:
                    open_ports.append(result)
                    if progress_callback:
                        progress_callback({
                            "type": "port_found",
                            "port": result.port,
                            "service": result.service,
                            "version": result.version,
                            "latency_ms": result.latency_ms,
                            "progress": round((completed / total) * 100, 1)
                        })
                else:
                    if progress_callback and (completed % 10 == 0 or completed == total):
                        progress_callback({
                            "type": "scan_progress",
                            "completed": completed,
                            "total": total,
                            "progress": round((completed / total) * 100, 1)
                        })

        return sorted(open_ports, key=lambda x: x.port)


def run_full_assessment(
    target: str,
    ports: Optional[List[int]] = None,
    profile: str = "quick",
    threads: int = 50,
    timeout: float = 2.5,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
) -> Dict[str, Any]:
    """
    Coordinates end-to-end multi-vector security assessment across:
    1. Port Recon & Latency Fingerprinting
    2. CVE Threat Correlation & CVSS 3.1 Scoring
    3. SSL/TLS Cryptographic Audit
    4. OWASP Web Security & Sensitive Path Probing
    5. DNS & Email Spoofing Defense
    6. Concrete Remediation Playbooks
    """
    start_time = time.time()

    # Clean target
    clean_host = target.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    # Resolve IP address
    resolved_ip = clean_host
    try:
        resolved_ip = socket.gethostbyname(clean_host)
    except Exception:
        pass

    if progress_callback:
        progress_callback({
            "type": "status",
            "message": f"Target resolved: {clean_host} ({resolved_ip}). Initiating reconnaissance..."
        })

    # Select Ports
    if ports:
        scan_ports = ports
    elif profile in PRESET_PROFILES:
        scan_ports = PRESET_PROFILES[profile]
    else:
        scan_ports = PRESET_PROFILES["quick"]

    # 1. Port Scanning
    engine = AegisReconEngine(threads=threads, timeout=timeout)
    if progress_callback:
        progress_callback({
            "type": "status",
            "message": f"Scanning {len(scan_ports)} ports with {threads} worker threads..."
        })

    discovered_ports = engine.scan_ports(resolved_ip, scan_ports, progress_callback)

    all_vulnerabilities: List[Dict[str, Any]] = []
    remediations: List[Dict[str, Any]] = []

    # 2. Port & Service Findings
    for p in discovered_ports:
        # Check unencrypted protocols
        if p.port in [21, 23, 80, 110, 143]:
            cvss = calculate_cvss31(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"
            ))
            all_vulnerabilities.append({
                "title": f"Cleartext Protocol In Use: {p.service} (Port {p.port})",
                "severity": cvss["severity"],
                "cvss_score": cvss["base_score"],
                "vector_string": cvss["vector_string"],
                "description": f"Service on port {p.port} transmits credentials and data in unencrypted plaintext, vulnerable to passive eavesdropping.",
                "recommendation": f"Migrate from cleartext {p.service} to an encrypted protocol alternative (e.g. SSH, SFTP, HTTPS, IMAPS)."
            })
            remediations.append(generate_port_firewall_remediation(p.port, p.service))

        # Check exposed database / management ports
        if p.port in [1433, 1521, 3306, 5432, 6379, 27017, 3389, 5900]:
            cvss = calculate_cvss31(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H"
            ))
            all_vulnerabilities.append({
                "title": f"Exposed Database / Remote Management Port ({p.port} - {p.service})",
                "severity": cvss["severity"],
                "cvss_score": cvss["base_score"],
                "vector_string": cvss["vector_string"],
                "description": f"Internal service '{p.service}' on port {p.port} is directly reachable from the public network, exposing it to brute force attacks and known exploits.",
                "recommendation": f"Bind {p.service} exclusively to 127.0.0.1 (localhost) or restrict access via VPN and firewall rules."
            })
            remediations.append(generate_port_firewall_remediation(p.port, p.service))

        # Correlate CVEs from banner/version
        if p.version != "Unknown":
            matched_cves = correlate_service_cves(p.service, p.version)
            for cve in matched_cves:
                all_vulnerabilities.append(cve)

    # 3. SSL/TLS Audit (Only probe ports verified open)
    ssl_audit_data = None
    tls_ports = [p.port for p in discovered_ports if p.port in [443, 8443, 993, 995] or "HTTPS" in p.service.upper() or "SSL" in p.service.upper()]

    for t_port in tls_ports:
        if progress_callback:
            progress_callback({"type": "status", "message": f"Conducting SSL/TLS cryptographic audit on port {t_port}..."})
        crypto_res = audit_ssl_tls(clean_host, port=t_port, timeout=timeout)
        if crypto_res.get("enabled"):
            ssl_audit_data = crypto_res
            for v in crypto_res.get("vulnerabilities", []):
                all_vulnerabilities.append(v)
            if crypto_res.get("vulnerabilities"):
                remediations.append(generate_ssl_remediation())
            break

    # 4. Web Application Security Audit (Only probe ports verified open)
    from core.web_audit import audit_web_security
    web_audit_data = None
    web_ports = [p.port for p in discovered_ports if p.port in [80, 443, 8080, 8443, 3000, 5000, 8000] or "HTTP" in p.service.upper()]

    for w_port in web_ports:
        if progress_callback:
            progress_callback({"type": "status", "message": f"Auditing OWASP web security on port {w_port}..."})
        web_res = audit_web_security(clean_host, port=w_port, timeout=timeout)
        if web_res.get("is_web"):
            web_audit_data = web_res
            for v in web_res.get("vulnerabilities", []):
                all_vulnerabilities.append(v)

            if web_res.get("missing_headers"):
                remediations.append(generate_header_remediation(web_res["missing_headers"]))
            if web_res.get("sensitive_paths"):
                remediations.append(generate_sensitive_path_remediation())
            break

    # 5. DNS & Email Spoofing Defense
    if progress_callback:
        progress_callback({"type": "status", "message": f"Querying DNS infrastructure and SPF/DMARC anti-spoofing policies..."})
    dns_audit_data = audit_dns_and_email_spoofing(clean_host)
    for v in dns_audit_data.get("vulnerabilities", []):
        all_vulnerabilities.append(v)

    if not dns_audit_data.get("is_ip") and (not dns_audit_data["spf"]["is_secure"] or not dns_audit_data["dmarc"]["is_secure"]):
        remediations.append(generate_dns_remediation(clean_host))

    # 6. Quantitative Risk Scoring
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
    total_cvss = 0.0

    for vuln in all_vulnerabilities:
        sev = vuln.get("severity", "Low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total_cvss += vuln.get("cvss_score", 0.0)

    vuln_count = len(all_vulnerabilities)
    avg_cvss = round(total_cvss / vuln_count, 1) if vuln_count > 0 else 0.0

    # Determine overall qualitative risk
    if severity_counts["Critical"] > 0 or avg_cvss >= 7.5:
        overall_risk = "Critical"
    elif severity_counts["High"] > 0 or avg_cvss >= 5.0:
        overall_risk = "High"
    elif severity_counts["Medium"] > 0 or avg_cvss >= 3.0:
        overall_risk = "Medium"
    elif vuln_count > 0:
        overall_risk = "Low"
    else:
        overall_risk = "Secure"

    scan_duration = round(time.time() - start_time, 2)

    # Compile final results payload
    assessment_payload = {
        "metadata": {
            "target": clean_host,
            "resolved_ip": resolved_ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration_seconds": scan_duration,
            "total_ports_scanned": len(scan_ports),
            "open_ports_count": len(discovered_ports),
            "engine_version": "AegisScan v3.0 Pro"
        },
        "risk_summary": {
            "overall_risk": overall_risk,
            "cvss_average": avg_cvss,
            "total_findings": vuln_count,
            "critical": severity_counts["Critical"],
            "high": severity_counts["High"],
            "medium": severity_counts["Medium"],
            "low": severity_counts["Low"]
        },
        "open_ports": [asdict(p) for p in discovered_ports],
        "vulnerabilities": all_vulnerabilities,
        "ssl_audit": ssl_audit_data,
        "web_audit": web_audit_data,
        "dns_audit": dns_audit_data,
        "remediations": remediations
    }

    if progress_callback:
        progress_callback({
            "type": "complete",
            "message": f"Assessment complete in {scan_duration}s. {vuln_count} findings categorized.",
            "data": assessment_payload
        })

    return assessment_payload
