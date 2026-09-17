"""
AegisScan: SSL/TLS Cryptographic Engine & Certificate Security Auditor
Extracts X.509 certificate chains, verifies validity/expiration periods,
inspects TLS protocol versions, and evaluates cipher suite encryption strengths.
"""

import socket
import ssl
from datetime import datetime
from typing import Dict, Any, List, Optional
from core.cve_intel import CVSSMetrics, calculate_cvss31

try:
    import certifi
    CA_FILE = certifi.where()
except ImportError:
    CA_FILE = None


def audit_ssl_tls(host: str, port: int = 443, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Performs comprehensive cryptographic audit of SSL/TLS endpoint.
    Returns certificate metadata, protocol versions, cipher details, and vulnerability findings.
    """
    result: Dict[str, Any] = {
        "enabled": False,
        "host": host,
        "port": port,
        "certificate": {},
        "protocol_version": None,
        "cipher_suite": None,
        "cipher_bits": None,
        "has_pfs": False,
        "is_self_signed": False,
        "days_until_expiration": None,
        "vulnerabilities": []
    }

    # Step 1: Connect and extract peer certificate using default or unverified context
    # (Using verify_mode = CERT_NONE to allow full inspection even for self-signed / internal servers)
    ctx = ssl.create_default_context(cafile=CA_FILE) if CA_FILE else ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["enabled"] = True
                result["protocol_version"] = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result["cipher_suite"] = cipher_info[0]
                    result["cipher_bits"] = cipher_info[2]
                    # PFS check
                    result["has_pfs"] = any(k in cipher_info[0] for k in ["ECDHE", "DHE", "TLS_AES", "CHACHA20"])

                # Peer certificate details
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # In case CERT_NONE doesn't return decoded dict, try with CERT_OPTIONAL
                    try:
                        ctx_opt = ssl.create_default_context(cafile=CA_FILE) if CA_FILE else ssl.create_default_context()
                        ctx_opt.check_hostname = False
                        with socket.create_connection((host, port), timeout=timeout) as sock2:
                            with ctx_opt.wrap_socket(sock2, server_hostname=host) as ssock2:
                                cert = ssock2.getpeercert()
                    except Exception:
                        pass

                if cert:
                    # Parse subject
                    subject_dict = {}
                    for item in cert.get("subject", ()):
                        for k, v in item:
                            subject_dict[k] = v

                    # Parse issuer
                    issuer_dict = {}
                    for item in cert.get("issuer", ()):
                        for k, v in item:
                            issuer_dict[k] = v

                    # Dates
                    not_before_str = cert.get("notBefore", "")
                    not_after_str = cert.get("notAfter", "")

                    days_left = None
                    expiry_date_str = None
                    if not_after_str:
                        try:
                            # Format: 'May 15 12:00:00 2026 GMT'
                            expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            expiry_date_str = expiry_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                            days_left = (expiry_dt - datetime.utcnow()).days
                            result["days_until_expiration"] = days_left
                        except Exception:
                            expiry_date_str = not_after_str

                    # Check SANs
                    sans = []
                    for k, v in cert.get("subjectAltName", ()):
                        if k == "DNS":
                            sans.append(v)

                    # Self-signed check
                    is_self_signed = (subject_dict.get("commonName") == issuer_dict.get("commonName") and
                                      subject_dict.get("organizationName") == issuer_dict.get("organizationName"))
                    result["is_self_signed"] = is_self_signed

                    result["certificate"] = {
                        "common_name": subject_dict.get("commonName", host),
                        "organization": subject_dict.get("organizationName", "N/A"),
                        "issuer_common_name": issuer_dict.get("commonName", "N/A"),
                        "issuer_organization": issuer_dict.get("organizationName", "N/A"),
                        "valid_from": not_before_str,
                        "valid_to": expiry_date_str,
                        "days_remaining": days_left,
                        "sans": sans[:10],
                        "serial_number": str(cert.get("serialNumber", "N/A"))
                    }

                    # Vulnerability Check 1: Expired Certificate
                    if days_left is not None and days_left < 0:
                        cvss = calculate_cvss31(CVSSMetrics(
                            attack_vector="N", attack_complexity="L", privileges_required="N",
                            user_interaction="R", scope="U", confidentiality="H", integrity="H", availability="N"
                        ))
                        result["vulnerabilities"].append({
                            "title": "Expired SSL/TLS Certificate",
                            "severity": cvss["severity"],
                            "cvss_score": cvss["base_score"],
                            "vector_string": cvss["vector_string"],
                            "description": f"The SSL certificate on {host}:{port} expired {abs(days_left)} days ago.",
                            "recommendation": "Renew the SSL/TLS certificate immediately with an automated ACME client like Let's Encrypt / Certbot."
                        })
                    elif days_left is not None and days_left <= 14:
                        cvss = calculate_cvss31(CVSSMetrics(
                            attack_vector="N", attack_complexity="L", privileges_required="N",
                            user_interaction="N", scope="U", confidentiality="N", integrity="L", availability="H"
                        ))
                        result["vulnerabilities"].append({
                            "title": "SSL/TLS Certificate Expiring Soon",
                            "severity": cvss["severity"],
                            "cvss_score": cvss["base_score"],
                            "vector_string": cvss["vector_string"],
                            "description": f"The SSL certificate on {host}:{port} will expire in {days_left} days.",
                            "recommendation": "Schedule certificate renewal before expiration to prevent service downtime and browser security warnings."
                        })

                    # Vulnerability Check 2: Self-Signed Certificate
                    if is_self_signed:
                        cvss = calculate_cvss31(CVSSMetrics(
                            attack_vector="N", attack_complexity="H", privileges_required="N",
                            user_interaction="R", scope="U", confidentiality="H", integrity="H", availability="N"
                        ))
                        result["vulnerabilities"].append({
                            "title": "Self-Signed Certificate In Use",
                            "severity": cvss["severity"],
                            "cvss_score": cvss["base_score"],
                            "vector_string": cvss["vector_string"],
                            "description": f"The certificate on {host}:{port} is self-signed and not signed by a trusted Certificate Authority (CA).",
                            "recommendation": "Replace with a publicly trusted certificate signed by a recognized Certificate Authority."
                        })

                # Vulnerability Check 3: Weak Cipher Suite (<128 bit)
                if result["cipher_bits"] and result["cipher_bits"] < 128:
                    cvss = calculate_cvss31(CVSSMetrics(
                        attack_vector="N", attack_complexity="L", privileges_required="N",
                        user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N"
                    ))
                    result["vulnerabilities"].append({
                        "title": "Weak SSL/TLS Encryption Cipher (< 128 bits)",
                        "severity": cvss["severity"],
                        "cvss_score": cvss["base_score"],
                        "vector_string": cvss["vector_string"],
                        "description": f"The endpoint negotiated a weak cipher suite ({result['cipher_suite']}) with only {result['cipher_bits']} bits of encryption.",
                        "recommendation": "Disable weak ciphers and enforce AES-128-GCM, AES-256-GCM, or CHACHA20-POLY1305."
                    })

                # Vulnerability Check 4: Deprecated Protocol Check (TLSv1.0 or TLSv1.1)
                if result["protocol_version"] in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    cvss = calculate_cvss31(CVSSMetrics(
                        attack_vector="N", attack_complexity="H", privileges_required="N",
                        user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"
                    ))
                    result["vulnerabilities"].append({
                        "title": f"Deprecated {result['protocol_version']} Protocol Supported",
                        "severity": cvss["severity"],
                        "cvss_score": cvss["base_score"],
                        "vector_string": cvss["vector_string"],
                        "description": f"The server negotiated {result['protocol_version']}, which is deprecated by RFC 8996 due to known cryptographic weaknesses (e.g. POODLE, BEAST).",
                        "recommendation": "Disable SSLv3, TLS 1.0, and TLS 1.1 in web server configuration; permit only TLS 1.2 and TLS 1.3."
                    })

    except Exception:
        # Port might not be an active SSL/TLS listener
        pass

    return result
