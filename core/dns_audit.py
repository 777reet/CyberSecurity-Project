"""
AegisScan: DNS Intelligence, Infrastructure Reconnaissance & Email Spoofing Defense
Audits DNS resource records (A, AAAA, MX, TXT) and performs in-depth SPF/DMARC
anti-spoofing policy analysis using standard DNS-over-HTTPS (DoH).
"""

import json
import socket
import ssl
import urllib.request
from typing import Dict, Any, List, Optional
from core.cve_intel import CVSSMetrics, calculate_cvss31

try:
    import certifi
    CA_FILE = certifi.where()
except ImportError:
    CA_FILE = None


def create_safe_ssl_context() -> ssl.SSLContext:
    """Create SSL context with system/certifi CA bundle or fallback to unverified if offline."""
    if CA_FILE:
        try:
            return ssl.create_default_context(cafile=CA_FILE)
        except Exception:
            pass
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def query_doh(domain: str, record_type: str = "A", timeout: float = 3.5) -> List[str]:
    """Query Cloudflare / Google DNS over HTTPS for reliable cross-platform DNS resolution."""
    providers = [
        f"https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}",
        f"https://dns.google/resolve?name={domain}&type={record_type}"
    ]
    ctx = create_safe_ssl_context()

    for url in providers:
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/dns-json", "User-Agent": "AegisScan-CyberSecurity/3.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                answers = data.get("Answer", [])
                results = []
                for ans in answers:
                    val = ans.get("data", "").strip().strip('"')
                    if val:
                        results.append(val)
                if results:
                    return results
        except Exception:
            continue

    return []


def audit_dns_and_email_spoofing(target: str) -> Dict[str, Any]:
    """
    Performs full DNS infrastructure reconnaissance and evaluates email spoofing defenses
    (SPF and DMARC policy compliance).
    """
    # Clean target (remove http/https and port if provided)
    host = target.lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    # Check if target is a raw IP address
    is_ip = False
    try:
        socket.inet_aton(host)
        is_ip = True
    except socket.error:
        pass

    dns_data: Dict[str, Any] = {
        "target_host": host,
        "is_ip": is_ip,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "txt_records": [],
        "reverse_dns": None,
        "spf": {
            "present": False,
            "record": None,
            "mechanism": "Missing",
            "is_secure": False,
            "details": "No SPF record found."
        },
        "dmarc": {
            "present": False,
            "record": None,
            "policy": "Missing",
            "is_secure": False,
            "details": "No DMARC record found at _dmarc."
        },
        "vulnerabilities": []
    }

    if is_ip:
        # Reverse DNS lookup for IP target
        try:
            name, _, _ = socket.gethostbyaddr(host)
            dns_data["reverse_dns"] = name
            dns_data["a_records"] = [host]
        except Exception:
            dns_data["reverse_dns"] = "No PTR record found"
            dns_data["a_records"] = [host]
        return dns_data

    # Query A, AAAA, MX, TXT records
    dns_data["a_records"] = query_doh(host, "A")
    dns_data["aaaa_records"] = query_doh(host, "AAAA")
    dns_data["mx_records"] = query_doh(host, "MX")
    dns_data["txt_records"] = query_doh(host, "TXT")

    # Local fallback for A records if DoH is blocked
    if not dns_data["a_records"]:
        try:
            _, _, ips = socket.gethostbyname_ex(host)
            dns_data["a_records"] = ips
        except Exception:
            pass

    # 1. Analyze SPF Records
    spf_records = [r for r in dns_data["txt_records"] if r.startswith("v=spf1")]
    if spf_records:
        spf = spf_records[0]
        dns_data["spf"]["present"] = True
        dns_data["spf"]["record"] = spf

        if "-all" in spf:
            dns_data["spf"]["mechanism"] = "Hard Fail (-all)"
            dns_data["spf"]["is_secure"] = True
            dns_data["spf"]["details"] = "Strict SPF policy enforced. Unauthorized senders are rejected."
        elif "~all" in spf:
            dns_data["spf"]["mechanism"] = "Soft Fail (~all)"
            dns_data["spf"]["is_secure"] = True
            dns_data["spf"]["details"] = "SPF soft fail enabled. Senders are flagged but may still be accepted."
        elif "+all" in spf or "?all" in spf:
            dns_data["spf"]["mechanism"] = "Insecure (+all / ?all)"
            dns_data["spf"]["is_secure"] = False
            dns_data["spf"]["details"] = "Overly permissive SPF policy permits unauthorized parties to spoof emails."

            cvss = calculate_cvss31(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="R", scope="U", confidentiality="N", integrity="H", availability="N"
            ))
            dns_data["vulnerabilities"].append({
                "title": "Permissive SPF Email Spoofing Policy",
                "severity": cvss["severity"],
                "cvss_score": cvss["base_score"],
                "vector_string": cvss["vector_string"],
                "description": f"The domain {host} has a permissive SPF policy ({spf}) that fails to reject unauthorized mail senders.",
                "recommendation": "Update SPF TXT record to end with -all to instruct mail servers to reject unlisted IP addresses."
            })
    else:
        # Missing SPF vulnerability
        if dns_data["mx_records"]:
            cvss = calculate_cvss31(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="R", scope="U", confidentiality="N", integrity="L", availability="N"
            ))
            dns_data["vulnerabilities"].append({
                "title": "Missing SPF Record (Email Spoofing Vulnerability)",
                "severity": cvss["severity"],
                "cvss_score": cvss["base_score"],
                "vector_string": cvss["vector_string"],
                "description": f"Domain {host} publishes MX mail servers but lacks an SPF (Sender Policy Framework) record.",
                "recommendation": f"Publish an SPF TXT record on {host}: 'v=spf1 mx -all'."
            })

    # 2. Analyze DMARC Record (_dmarc.<host>)
    dmarc_records = query_doh(f"_dmarc.{host}", "TXT")
    dmarc_entries = [r for r in dmarc_records if "v=DMARC1" in r]

    if dmarc_entries:
        dmarc = dmarc_entries[0]
        dns_data["dmarc"]["present"] = True
        dns_data["dmarc"]["record"] = dmarc

        if "p=reject" in dmarc:
            dns_data["dmarc"]["policy"] = "Reject (p=reject)"
            dns_data["dmarc"]["is_secure"] = True
            dns_data["dmarc"]["details"] = "Highest protection: spoofed emails are rejected by receiving servers."
        elif "p=quarantine" in dmarc:
            dns_data["dmarc"]["policy"] = "Quarantine (p=quarantine)"
            dns_data["dmarc"]["is_secure"] = True
            dns_data["dmarc"]["details"] = "Moderate protection: spoofed emails are directed to recipient spam folders."
        else:
            dns_data["dmarc"]["policy"] = "Monitoring Only (p=none)"
            dns_data["dmarc"]["is_secure"] = False
            dns_data["dmarc"]["details"] = "DMARC policy is set to 'p=none', offering no enforcement against email spoofing."

            cvss = calculate_cvss31(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="R", scope="U", confidentiality="N", integrity="L", availability="N"
            ))
            dns_data["vulnerabilities"].append({
                "title": "DMARC Policy Set to None (Spoofing Allowed)",
                "severity": cvss["severity"],
                "cvss_score": cvss["base_score"],
                "vector_string": cvss["vector_string"],
                "description": f"Domain {host} has DMARC configured with p=none, allowing fraudulent emails appearing to come from this domain to reach recipient inboxes.",
                "recommendation": "Upgrade DMARC policy from p=none to p=quarantine or p=reject to enforce strict anti-spoofing."
            })
    else:
        # Missing DMARC
        if dns_data["mx_records"]:
            cvss = calculate_cvss31(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="R", scope="U", confidentiality="N", integrity="H", availability="N"
            ))
            dns_data["vulnerabilities"].append({
                "title": "Missing DMARC Anti-Phishing Policy",
                "severity": cvss["severity"],
                "cvss_score": cvss["base_score"],
                "vector_string": cvss["vector_string"],
                "description": f"Domain {host} does not publish a DMARC policy record at _dmarc.{host}. Attackers can send phishing emails pretending to originate from this organization.",
                "recommendation": f"Add a TXT record for _dmarc.{host} with 'v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@{host}'."
            })

    return dns_data
