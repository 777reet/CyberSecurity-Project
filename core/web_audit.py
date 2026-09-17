"""
AegisScan: OWASP Web Application & API Security Auditor
Audits HTTP Security Headers, Information Disclosure, Sensitive Path Exposure,
CORS configurations, and Cookie security flags against live web targets.
"""

import http.client
import re
import socket
import ssl
import urllib.parse
import urllib.request
from typing import Dict, Any, List, Optional
from core.cve_intel import CVSSMetrics, calculate_cvss31

try:
    import certifi
    CA_FILE = certifi.where()
except ImportError:
    CA_FILE = None


RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "description": "HSTS ensures modern browsers connect exclusively via HTTPS, defending against SSL stripping and man-in-the-middle attacks.",
        "recommendation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "metrics": CVSSMetrics(attack_vector="N", attack_complexity="H", privileges_required="N", user_interaction="R", scope="U", confidentiality="L", integrity="L", availability="N")
    },
    "Content-Security-Policy": {
        "title": "Missing Content Security Policy (CSP)",
        "description": "Content-Security-Policy restricts malicious scripts, iframes, and cross-site scripting (XSS) injection vectors.",
        "recommendation": "Implement a restrictive CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
        "metrics": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="R", scope="U", confidentiality="L", integrity="L", availability="N")
    },
    "X-Frame-Options": {
        "title": "Missing Clickjacking Protection (X-Frame-Options)",
        "description": "The site does not restrict framing via X-Frame-Options, making it vulnerable to UI redressing (Clickjacking) attacks.",
        "recommendation": "Set header: X-Frame-Options: SAMEORIGIN or DENY.",
        "metrics": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="R", scope="U", confidentiality="N", integrity="L", availability="N")
    },
    "X-Content-Type-Options": {
        "title": "Missing MIME-Sniffing Defense (X-Content-Type-Options)",
        "description": "Without 'X-Content-Type-Options: nosniff', browsers may interpret file uploads as executable scripts (MIME confusion attack).",
        "recommendation": "Set header: X-Content-Type-Options: nosniff.",
        "metrics": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="R", scope="U", confidentiality="N", integrity="L", availability="N")
    },
    "Referrer-Policy": {
        "title": "Missing or Loose Referrer-Policy",
        "description": "Absence of Referrer-Policy may leak sensitive internal URLs, query tokens, and user parameters to external referrers.",
        "recommendation": "Set header: Referrer-Policy: strict-origin-when-cross-origin.",
        "metrics": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="U", confidentiality="L", integrity="N", availability="N")
    },
    "Permissions-Policy": {
        "title": "Missing Permissions-Policy",
        "description": "Permissions-Policy (formerly Feature-Policy) limits unauthorized browser access to geolocation, camera, microphone, and payment APIs.",
        "recommendation": "Define explicit allowed origins: Permissions-Policy: geolocation=(), camera=(), microphone=().",
        "metrics": CVSSMetrics(attack_vector="N", attack_complexity="H", privileges_required="N", user_interaction="N", scope="U", confidentiality="L", integrity="N", availability="N")
    }
}

SENSITIVE_PATHS_TO_PROBE = [
    {"path": "/.env", "name": "Environment Variables File", "cvss": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N")},
    {"path": "/.git/HEAD", "name": "Git Source Repository Metadata", "cvss": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N")},
    {"path": "/robots.txt", "name": "Robots Information File", "cvss": None},
    {"path": "/sitemap.xml", "name": "Site Structure Map", "cvss": None},
    {"path": "/.well-known/security.txt", "name": "RFC 9116 Security Contact File", "cvss": None},
    {"path": "/backup.zip", "name": "Public Backup Archive", "cvss": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N")},
    {"path": "/server-status", "name": "Apache Server Status Page", "cvss": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="U", confidentiality="L", integrity="N", availability="N")},
    {"path": "/admin", "name": "Administrative Login Portal", "cvss": None}
]


def audit_web_security(host: str, port: int, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Connects to an HTTP or HTTPS service and conducts security header,
    information disclosure, path exposure, and cookie inspections.
    """
    protocol = "https" if port in [443, 8443] else "http"
    base_url = f"{protocol}://{host}:{port}" if port not in [80, 443] else f"{protocol}://{host}"

    result: Dict[str, Any] = {
        "url": base_url,
        "host": host,
        "port": port,
        "protocol": protocol,
        "is_web": False,
        "status_code": None,
        "headers": {},
        "missing_headers": [],
        "present_headers": [],
        "server_banner": None,
        "powered_by": None,
        "sensitive_paths": [],
        "cors_policy": None,
        "cookies": [],
        "vulnerabilities": []
    }

    # Setup SSL context for HTTPS requests
    ctx = ssl.create_default_context(cafile=CA_FILE) if CA_FILE else ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # 1. Fetch Root Endpoint Headers
    try:
        req = urllib.request.Request(
            base_url + "/",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisScan/3.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            result["is_web"] = True
            result["status_code"] = response.getcode()
            headers = {k.title(): v for k, v in response.headers.items()}
            result["headers"] = headers
    except urllib.error.HTTPError as e:
        result["is_web"] = True
        result["status_code"] = e.code
        headers = {k.title(): v for k, v in e.headers.items()}
        result["headers"] = headers
    except Exception:
        # Not an active HTTP web server
        return result

    # 2. Check Security Headers
    for header_name, info in RECOMMENDED_HEADERS.items():
        # Match case-insensitively
        found_val = next((v for k, v in headers.items() if k.lower() == header_name.lower()), None)
        if found_val:
            result["present_headers"].append({"name": header_name, "value": found_val})
        else:
            result["missing_headers"].append(header_name)
            # Add vulnerability for missing security header
            cvss = calculate_cvss31(info["metrics"])
            result["vulnerabilities"].append({
                "title": info["title"],
                "severity": cvss["severity"],
                "cvss_score": cvss["base_score"],
                "vector_string": cvss["vector_string"],
                "description": info["description"],
                "recommendation": info["recommendation"]
            })

    # 3. Information Disclosure Headers
    server_header = next((v for k, v in headers.items() if k.lower() == "server"), None)
    if server_header:
        result["server_banner"] = server_header
        # Check if detailed version is leaked
        if re.search(r"\d+\.\d+", server_header):
            cvss = calculate_cvss31(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="L", integrity="N", availability="N"
            ))
            result["vulnerabilities"].append({
                "title": "Server Version Header Disclosure",
                "severity": cvss["severity"],
                "cvss_score": cvss["base_score"],
                "vector_string": cvss["vector_string"],
                "description": f"The HTTP Server header discloses exact software version details: '{server_header}'. This assists attackers in locating targeted CVE exploits.",
                "recommendation": "Configure web server to suppress version banners (e.g., 'ServerTokens Prod' in Apache, 'server_tokens off;' in Nginx)."
            })

    powered_by = next((v for k, v in headers.items() if k.lower() == "x-powered-by"), None)
    if powered_by:
        result["powered_by"] = powered_by
        cvss = calculate_cvss31(CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="U", confidentiality="L", integrity="N", availability="N"
        ))
        result["vulnerabilities"].append({
            "title": "Technology Stack Disclosure (X-Powered-By)",
            "severity": cvss["severity"],
            "cvss_score": cvss["base_score"],
            "vector_string": cvss["vector_string"],
            "description": f"The 'X-Powered-By: {powered_by}' header leaks runtime framework details.",
            "recommendation": "Remove the X-Powered-By response header in backend server configuration."
        })

    # 4. CORS Policy Check
    cors_header = next((v for k, v in headers.items() if k.lower() == "access-control-allow-origin"), None)
    if cors_header:
        result["cors_policy"] = cors_header
        if cors_header.strip() == "*":
            cvss = calculate_cvss31(CVSSMetrics(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="R", scope="U", confidentiality="L", integrity="N", availability="N"
            ))
            result["vulnerabilities"].append({
                "title": "Wildcard Access-Control-Allow-Origin (CORS)",
                "severity": cvss["severity"],
                "cvss_score": cvss["base_score"],
                "vector_string": cvss["vector_string"],
                "description": "The web server allows wildcard '*' CORS origins, allowing arbitrary external domains to request resources.",
                "recommendation": "Specify explicit trusted domains in Access-Control-Allow-Origin rather than wildcard '*'."
            })

    # 5. Cookie Security Flags
    cookie_headers = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for cookie in cookie_headers:
        cookie_name = cookie.split("=")[0].strip() if "=" in cookie else "Cookie"
        is_secure = "secure" in cookie.lower()
        is_httponly = "httponly" in cookie.lower()
        samesite = "samesite" in cookie.lower()

        result["cookies"].append({
            "cookie": cookie_name,
            "secure": is_secure,
            "httponly": is_httponly,
            "samesite": samesite
        })

        if not is_secure and protocol == "https":
            cvss = calculate_cvss31(CVSSMetrics(attack_vector="N", attack_complexity="H", privileges_required="N", user_interaction="R", scope="U", confidentiality="L", integrity="L", availability="N"))
            result["vulnerabilities"].append({
                "title": f"Cookie Without 'Secure' Flag ({cookie_name})",
                "severity": cvss["severity"],
                "cvss_score": cvss["base_score"],
                "vector_string": cvss["vector_string"],
                "description": f"Cookie '{cookie_name}' is set without the 'Secure' attribute, allowing transmission over unencrypted HTTP.",
                "recommendation": "Append '; Secure' to all Set-Cookie directives."
            })

        if not is_httponly:
            cvss = calculate_cvss31(CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="R", scope="U", confidentiality="L", integrity="N", availability="N"))
            result["vulnerabilities"].append({
                "title": f"Cookie Without 'HttpOnly' Flag ({cookie_name})",
                "severity": cvss["severity"],
                "cvss_score": cvss["base_score"],
                "vector_string": cvss["vector_string"],
                "description": f"Cookie '{cookie_name}' lacks the 'HttpOnly' attribute, making it accessible to client-side scripts if XSS occurs.",
                "recommendation": "Append '; HttpOnly' to Set-Cookie directives for session and auth tokens."
            })

    # 6. Sensitive Path Probing (Concurrent)
    def probe_single_path(probe_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        path = probe_item["path"]
        target_path_url = base_url + path
        try:
            req = urllib.request.Request(
                target_path_url,
                headers={"User-Agent": "AegisScan-CyberSecurity/3.0"}
            )
            with urllib.request.urlopen(req, timeout=1.5, context=ctx) as p_resp:
                code = p_resp.getcode()
                content = p_resp.read(512).decode("utf-8", errors="ignore")

                # Verify it's not a generic 404 page returning 200
                if code == 200 and not any(k in content.lower() for k in ["page not found", "error 404", "cannot find"]):
                    return {
                        "path": path,
                        "name": probe_item["name"],
                        "status": code,
                        "preview": content[:120].strip(),
                        "probe": probe_item
                    }
        except Exception:
            return None
        return None

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=6) as p_exec:
        futures = [p_exec.submit(probe_single_path, p) for p in SENSITIVE_PATHS_TO_PROBE]
        for f in as_completed(futures):
            found = f.result()
            if found:
                result["sensitive_paths"].append({
                    "path": found["path"],
                    "name": found["name"],
                    "status": found["status"],
                    "preview": found["preview"]
                })
                probe_info = found["probe"]
                if probe_info["cvss"]:
                    cvss = calculate_cvss31(probe_info["cvss"])
                    result["vulnerabilities"].append({
                        "title": f"Exposed Sensitive Resource: {probe_info['name']} ({found['path']})",
                        "severity": cvss["severity"],
                        "cvss_score": cvss["base_score"],
                        "vector_string": cvss["vector_string"],
                        "description": f"The sensitive file/endpoint '{found['path']}' was publicly accessible with HTTP 200 OK. This leaks internal operational configurations.",
                        "recommendation": f"Restrict public access to '{found['path']}' via web server configuration rules or remove the file from web root."
                    })

    return result
