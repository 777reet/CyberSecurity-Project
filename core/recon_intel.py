"""
AegisScan: Reconnaissance & Threat Intelligence Module
Covers:
  - Subdomain enumeration via certificate transparency (crt.sh)
  - HTTP Security Header Grading (A-F)
  - IP Geolocation & WHOIS / RDAP lookup
  - Technology Fingerprinting (CMS, WAF, Framework detection)
  - Certificate Transparency Log Viewer (crt.sh)
  - Threat Intelligence / Abuse reputation lookup
"""

import json
import re
import socket
import ssl
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: float = 8.0, extra_headers: Optional[Dict] = None) -> Tuple[Optional[str], int, Dict]:
    """Perform a simple HTTP GET and return (body_text, status_code, response_headers)."""
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "AegisScan/3.0 Security Research")
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="ignore")
            hdrs = dict(resp.headers)
            return body, resp.status, hdrs
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return body, e.code, {}
    except Exception:
        return None, 0, {}


def _safe_json(text: Optional[str]) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _is_ip(target: str) -> bool:
    try:
        socket.inet_aton(target)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 1. Subdomain Enumeration via crt.sh (Certificate Transparency)
# ---------------------------------------------------------------------------

def enumerate_subdomains(domain: str, timeout: float = 12.0) -> Dict[str, Any]:
    """
    Query crt.sh certificate transparency logs to enumerate subdomains.
    Returns a deduplicated, sorted list of discovered subdomains.
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "subdomains": [],
        "total_found": 0,
        "source": "crt.sh Certificate Transparency",
        "error": None
    }

    if _is_ip(domain):
        result["error"] = "IP addresses do not have certificate transparency records."
        return result

    url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
    body, status, _ = _http_get(url, timeout=timeout)

    if status == 0:
        result["error"] = "Could not reach crt.sh. Check network connectivity."
        return result

    data = _safe_json(body)
    if not data or not isinstance(data, list):
        result["error"] = "crt.sh returned no data or unexpected format."
        return result

    seen = set()
    entries = []
    for entry in data:
        name_value = entry.get("name_value", "")
        issuer = entry.get("issuer_name", "")
        not_before = entry.get("not_before", "")
        not_after = entry.get("not_after", "")
        serial = entry.get("serial_number", "")

        for name in name_value.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if not name or name in seen:
                continue
            if not (name.endswith(f".{domain}") or name == domain):
                continue
            seen.add(name)
            entries.append({
                "subdomain": name,
                "issuer": issuer[:80] if issuer else "Unknown",
                "not_before": not_before,
                "not_after": not_after,
                "serial": serial
            })

    entries.sort(key=lambda x: x["subdomain"])
    result["subdomains"] = entries
    result["total_found"] = len(entries)
    return result


# ---------------------------------------------------------------------------
# 2. Certificate Transparency Log Viewer
# ---------------------------------------------------------------------------

def get_cert_transparency_log(domain: str, timeout: float = 12.0) -> Dict[str, Any]:
    """
    Retrieve detailed list of SSL certificates issued for a domain via crt.sh.
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "certificates": [],
        "total": 0,
        "error": None
    }

    if _is_ip(domain):
        result["error"] = "Certificate transparency logs are domain-based."
        return result

    url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
    body, status, _ = _http_get(url, timeout=timeout)

    if status == 0:
        result["error"] = "Could not reach crt.sh."
        return result

    data = _safe_json(body)
    if not data or not isinstance(data, list):
        result["error"] = "No certificate data returned."
        return result

    now = datetime.now(timezone.utc)
    seen_ids = set()
    certs = []

    for entry in data:
        cert_id = entry.get("id")
        if cert_id in seen_ids:
            continue
        seen_ids.add(cert_id)

        not_after_str = entry.get("not_after", "")
        is_expired = False
        days_remaining = None
        try:
            expiry = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
            delta = expiry - now
            days_remaining = delta.days
            is_expired = days_remaining < 0
        except Exception:
            pass

        certs.append({
            "id": cert_id,
            "common_name": entry.get("common_name", ""),
            "name_value": entry.get("name_value", ""),
            "issuer": entry.get("issuer_name", "")[:100],
            "not_before": entry.get("not_before", ""),
            "not_after": not_after_str,
            "days_remaining": days_remaining,
            "is_expired": is_expired,
            "serial": entry.get("serial_number", "")
        })

    certs.sort(key=lambda x: x.get("not_before", ""), reverse=True)
    result["certificates"] = certs[:50]
    result["total"] = len(certs)
    return result


# ---------------------------------------------------------------------------
# 3. HTTP Security Header Grader
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "strict-transport-security": {
        "label": "HSTS",
        "weight": 20,
        "description": "Forces HTTPS connections. Prevents protocol downgrade attacks.",
        "recommended": "max-age=31536000; includeSubDomains; preload"
    },
    "content-security-policy": {
        "label": "CSP",
        "weight": 25,
        "description": "Prevents XSS and data injection attacks by defining trusted content sources.",
        "recommended": "default-src 'self'; script-src 'self'"
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "weight": 15,
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "recommended": "DENY"
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "weight": 10,
        "description": "Prevents MIME-type sniffing attacks.",
        "recommended": "nosniff"
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "weight": 10,
        "description": "Controls how much referrer info is included with requests.",
        "recommended": "strict-origin-when-cross-origin"
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "weight": 10,
        "description": "Controls access to browser features (camera, microphone, geolocation, etc.).",
        "recommended": "geolocation=(), microphone=(), camera=()"
    },
    "x-xss-protection": {
        "label": "X-XSS-Protection",
        "weight": 5,
        "description": "Legacy XSS filter for older browsers.",
        "recommended": "1; mode=block"
    },
    "cross-origin-resource-policy": {
        "label": "CORP",
        "weight": 5,
        "description": "Prevents cross-origin resource leaks via Spectre-like side-channels.",
        "recommended": "same-origin"
    }
}

INFO_LEAK_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-runtime", "x-version"
]


def grade_http_headers(host: str, port: int = 443, timeout: float = 8.0) -> Dict[str, Any]:
    """
    Fetch HTTP response headers and grade security posture A+ to F.
    """
    scheme = "https" if port in [443, 8443] else "http"
    url = f"{scheme}://{host}" if port in [80, 443] else f"{scheme}://{host}:{port}"

    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "url": url,
        "grade": "F",
        "score": 0,
        "max_score": 100,
        "headers_found": [],
        "headers_missing": [],
        "info_leaks": [],
        "raw_headers": {},
        "error": None
    }

    body, status, raw_headers = _http_get(url, timeout=timeout)

    if status == 0:
        result["error"] = f"Could not connect to {url}"
        return result

    lower_headers = {k.lower(): v for k, v in raw_headers.items()}
    result["raw_headers"] = lower_headers

    total_score = 0
    for header_key, meta in SECURITY_HEADERS.items():
        present = header_key in lower_headers
        value = lower_headers.get(header_key, "")
        entry = {
            "header": header_key,
            "label": meta["label"],
            "weight": meta["weight"],
            "description": meta["description"],
            "recommended": meta["recommended"],
            "present": present,
            "value": value
        }
        if present:
            total_score += meta["weight"]
            result["headers_found"].append(entry)
        else:
            result["headers_missing"].append(entry)

    for header_key in INFO_LEAK_HEADERS:
        if header_key in lower_headers:
            result["info_leaks"].append({
                "header": header_key,
                "value": lower_headers[header_key],
                "risk": "Reveals server technology stack to attackers."
            })

    result["score"] = total_score
    pct = total_score / 100.0
    if pct >= 0.90:
        result["grade"] = "A+"
    elif pct >= 0.80:
        result["grade"] = "A"
    elif pct >= 0.65:
        result["grade"] = "B"
    elif pct >= 0.50:
        result["grade"] = "C"
    elif pct >= 0.35:
        result["grade"] = "D"
    else:
        result["grade"] = "F"

    return result


# ---------------------------------------------------------------------------
# 4. IP Geolocation & WHOIS / RDAP
# ---------------------------------------------------------------------------

def lookup_whois_geo(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    """
    Lookup IP geolocation, ASN, ISP, and RDAP WHOIS data.
    Uses ip-api.com (free, no key) and IANA RDAP.
    """
    result: Dict[str, Any] = {
        "target": target,
        "ip": None,
        "is_private": False,
        "geo": {},
        "rdap": {},
        "abuse": {},
        "error": None
    }

    try:
        ip = socket.gethostbyname(target)
        result["ip"] = ip
    except Exception:
        result["error"] = f"Could not resolve {target}"
        return result

    def ip_to_int(ip_str: str) -> int:
        parts = ip_str.split(".")
        return sum(int(p) << (24 - 8 * i) for i, p in enumerate(parts))

    private_ranges = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255"),
        ("127.0.0.0", "127.255.255.255"),
    ]
    ip_int = ip_to_int(ip)
    for start, end in private_ranges:
        if ip_to_int(start) <= ip_int <= ip_to_int(end):
            result["is_private"] = True
            result["geo"] = {"note": "Private/Reserved IP address."}
            return result

    # ip-api.com geolocation
    geo_fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    geo_url = f"http://ip-api.com/json/{ip}?fields={geo_fields}"
    geo_body, _, _ = _http_get(geo_url, timeout=timeout)
    geo_data = _safe_json(geo_body)
    if geo_data and geo_data.get("status") == "success":
        result["geo"] = {
            "country": geo_data.get("country", ""),
            "country_code": geo_data.get("countryCode", ""),
            "region": geo_data.get("regionName", ""),
            "city": geo_data.get("city", ""),
            "latitude": geo_data.get("lat"),
            "longitude": geo_data.get("lon"),
            "timezone": geo_data.get("timezone", ""),
            "isp": geo_data.get("isp", ""),
            "org": geo_data.get("org", ""),
            "asn": geo_data.get("as", ""),
            "asn_name": geo_data.get("asname", ""),
            "reverse_dns": geo_data.get("reverse", ""),
            "is_mobile": geo_data.get("mobile", False),
            "is_proxy": geo_data.get("proxy", False),
            "is_hosting": geo_data.get("hosting", False),
        }
        flags = []
        if geo_data.get("proxy"):
            flags.append("Known proxy / VPN / Tor exit node")
        if geo_data.get("hosting"):
            flags.append("Datacenter / hosting provider IP")
        result["abuse"] = {
            "is_proxy": geo_data.get("proxy", False),
            "is_hosting": geo_data.get("hosting", False),
            "risk_flags": flags
        }

    # RDAP lookup
    rdap_url = f"https://rdap.arin.net/registry/ip/{ip}"
    rdap_body, rdap_status, _ = _http_get(rdap_url, timeout=timeout)
    rdap_data = _safe_json(rdap_body)
    if rdap_data:
        entities = rdap_data.get("entities", [])
        abuse_email = None
        registrant = None
        for entity in entities:
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list):
                        if item[0] == "email" and "abuse" in roles:
                            abuse_email = item[3] if len(item) > 3 else None
                        if item[0] == "fn" and ("registrant" in roles or "administrative" in roles):
                            registrant = item[3] if len(item) > 3 else None

        result["rdap"] = {
            "name": rdap_data.get("name", ""),
            "handle": rdap_data.get("handle", ""),
            "type": rdap_data.get("type", ""),
            "start_address": rdap_data.get("startAddress", ""),
            "end_address": rdap_data.get("endAddress", ""),
            "country": rdap_data.get("country", ""),
            "abuse_email": abuse_email,
            "registrant": registrant,
            "rdap_link": rdap_url
        }

    return result


# ---------------------------------------------------------------------------
# 5. Technology Fingerprinting
# ---------------------------------------------------------------------------

TECH_SIGNATURES = [
    # Web Servers
    {"sig": "nginx",      "category": "Web Server",     "name": "Nginx",            "match": "header", "header": "server"},
    {"sig": "apache",     "category": "Web Server",     "name": "Apache",           "match": "header", "header": "server"},
    {"sig": "litespeed",  "category": "Web Server",     "name": "LiteSpeed",        "match": "header", "header": "server"},
    {"sig": "iis",        "category": "Web Server",     "name": "Microsoft IIS",    "match": "header", "header": "server"},
    {"sig": "caddy",      "category": "Web Server",     "name": "Caddy",            "match": "header", "header": "server"},
    {"sig": "openresty",  "category": "Web Server",     "name": "OpenResty",        "match": "header", "header": "server"},
    # CDN / WAF
    {"sig": "cloudflare", "category": "CDN/WAF",        "name": "Cloudflare",       "match": "header_key", "header": "cf-ray"},
    {"sig": "cloudfront", "category": "CDN",            "name": "AWS CloudFront",   "match": "header_key", "header": "x-amz-cf-id"},
    {"sig": "azure",      "category": "CDN",            "name": "Azure CDN",        "match": "header_key", "header": "x-azure-ref"},
    {"sig": "sucuri",     "category": "WAF",            "name": "Sucuri WAF",       "match": "header_key", "header": "x-sucuri-id"},
    {"sig": "datadome",   "category": "Bot Protection", "name": "DataDome",         "match": "header_key", "header": "x-datadome-cid"},
    # Frameworks
    {"sig": "php",        "category": "Language",       "name": "PHP",              "match": "header", "header": "x-powered-by"},
    {"sig": "asp.net",    "category": "Framework",      "name": "ASP.NET",          "match": "header", "header": "x-powered-by"},
    {"sig": "express",    "category": "Framework",      "name": "Express.js",       "match": "header", "header": "x-powered-by"},
    {"sig": "next.js",    "category": "Framework",      "name": "Next.js",          "match": "header", "header": "x-powered-by"},
    # CMS (body)
    {"sig": "wp-content", "category": "CMS",            "name": "WordPress",        "match": "body"},
    {"sig": "drupal",     "category": "CMS",            "name": "Drupal",           "match": "body"},
    {"sig": "joomla",     "category": "CMS",            "name": "Joomla",           "match": "body"},
    {"sig": "shopify",    "category": "E-Commerce",     "name": "Shopify",          "match": "body"},
    {"sig": "wix.com",    "category": "Website Builder", "name": "Wix",             "match": "body"},
    {"sig": "ghost",      "category": "CMS",            "name": "Ghost",            "match": "body"},
]


def fingerprint_technologies(host: str, port: int = 443, timeout: float = 8.0) -> Dict[str, Any]:
    """
    Detect CMS, WAF, framework, CDN, and web server by analyzing HTTP headers and body.
    """
    result: Dict[str, Any] = {
        "host": host,
        "technologies": [],
        "waf_detected": None,
        "cdn_detected": None,
        "server": None,
        "error": None
    }

    scheme = "https" if port in [443, 8443] else "http"
    url = f"{scheme}://{host}" if port in [80, 443] else f"{scheme}://{host}:{port}"

    body, status, raw_headers = _http_get(url, timeout=timeout)
    if status == 0:
        result["error"] = f"Could not fetch {url}"
        return result

    lower_headers = {k.lower(): v.lower() for k, v in raw_headers.items()}
    body_lower = (body or "").lower()

    detected: Dict[str, Dict] = {}
    for sig_def in TECH_SIGNATURES:
        name = sig_def["name"]
        if name in detected:
            continue
        matched = False
        match_type = sig_def.get("match", "body")
        sig = sig_def["sig"]

        if match_type == "header":
            hdr_val = lower_headers.get(sig_def.get("header", ""), "")
            matched = sig in hdr_val
        elif match_type == "header_key":
            matched = sig_def.get("header", "") in lower_headers
        elif match_type == "body":
            matched = sig in body_lower

        if matched:
            detected[name] = {"name": name, "category": sig_def["category"]}

    if "server" in lower_headers:
        result["server"] = lower_headers["server"]

    for tech in detected.values():
        if tech["category"] == "WAF":
            result["waf_detected"] = tech["name"]
        elif tech["category"] in ["CDN", "CDN/WAF"]:
            result["cdn_detected"] = tech["name"]

    result["technologies"] = list(detected.values())
    return result


# ---------------------------------------------------------------------------
# Combined Intelligence Run
# ---------------------------------------------------------------------------

def run_recon_intelligence(target: str, web_port: int = 443, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Run all intelligence modules and return combined results.
    """
    clean = target.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    return {
        "target": clean,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains": enumerate_subdomains(clean, timeout=timeout),
        "cert_transparency": get_cert_transparency_log(clean, timeout=timeout),
        "header_grade": grade_http_headers(clean, port=web_port, timeout=timeout),
        "whois_geo": lookup_whois_geo(clean, timeout=timeout),
        "tech_fingerprint": fingerprint_technologies(clean, port=web_port, timeout=timeout),
    }
