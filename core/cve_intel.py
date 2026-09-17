"""
AegisScan: NIST CVSS v3.1 Base Scoring Engine & CVE Threat Intelligence
Provides standardized quantitative risk scoring, vector string generation,
and version-correlated vulnerability intelligence.
"""

import math
import re
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List


@dataclass
class CVSSMetrics:
    attack_vector: str = "N"          # N (Network), A (Adjacent), L (Local), P (Physical)
    attack_complexity: str = "L"      # L (Low), H (High)
    privileges_required: str = "N"    # N (None), L (Low), H (High)
    user_interaction: str = "N"       # N (None), R (Required)
    scope: str = "U"                  # U (Unchanged), C (Changed)
    confidentiality: str = "H"        # N (None), L (Low), H (High)
    integrity: str = "H"              # N (None), L (Low), H (High)
    availability: str = "H"           # N (None), L (Low), H (High)

    def to_vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/"
            f"A:{self.availability}"
        )


def round_up(val: float) -> float:
    """CVSS v3.1 specification rounding: round up to next 0.1."""
    int_val = round(val * 100000)
    if (int_val % 10000) == 0:
        return int_val / 100000.0
    return (math.floor(int_val / 10000) + 1) / 10.0


def calculate_cvss31(metrics: CVSSMetrics) -> Dict[str, Any]:
    """
    Computes exact NIST CVSS v3.1 Base Score and qualitative severity
    per FIRST.org specification.
    """
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_weights = {"L": 0.77, "H": 0.44}
    ui_weights = {"N": 0.85, "R": 0.62}
    c_weights  = {"N": 0.00, "L": 0.22, "H": 0.56}
    i_weights  = {"N": 0.00, "L": 0.22, "H": 0.56}
    a_weights  = {"N": 0.00, "L": 0.22, "H": 0.56}

    # PR weight depends on Scope
    if metrics.scope == "U":
        pr_weights = {"N": 0.85, "L": 0.62, "H": 0.27}
    else:
        pr_weights = {"N": 0.85, "L": 0.68, "H": 0.50}

    av = av_weights.get(metrics.attack_vector, 0.85)
    ac = ac_weights.get(metrics.attack_complexity, 0.77)
    pr = pr_weights.get(metrics.privileges_required, 0.85)
    ui = ui_weights.get(metrics.user_interaction, 0.85)
    c  = c_weights.get(metrics.confidentiality, 0.56)
    i  = i_weights.get(metrics.integrity, 0.56)
    a  = a_weights.get(metrics.availability, 0.56)

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    if metrics.scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow((iss - 0.02), 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    else:
        if metrics.scope == "U":
            base_score = round_up(min(impact + exploitability, 10.0))
        else:
            base_score = round_up(min(1.08 * (impact + exploitability), 10.0))

    if base_score == 0.0:
        severity = "None"
    elif base_score <= 3.9:
        severity = "Low"
    elif base_score <= 6.9:
        severity = "Medium"
    elif base_score <= 8.9:
        severity = "High"
    else:
        severity = "Critical"

    return {
        "base_score": base_score,
        "severity": severity,
        "impact": round(impact, 2),
        "exploitability": round(exploitability, 2),
        "vector_string": metrics.to_vector_string()
    }


# Knowledge base of known vulnerabilities, CVE cross-references, and CVSS parameters
KNOWN_CVE_DATABASE: List[Dict[str, Any]] = [
    {
        "service_regex": r"Apache[ /]2\.4\.(49|50)",
        "cve_id": "CVE-2021-41773",
        "title": "Apache HTTP Server Path Traversal and RCE",
        "description": "Path traversal flaw in Apache HTTP Server 2.4.49 and 2.4.50 allows remote attackers to map URLs to files outside expected document roots and potentially execute arbitrary code.",
        "metrics": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H"),
        "recommendation": "Upgrade immediately to Apache HTTP Server 2.4.51 or higher."
    },
    {
        "service_regex": r"OpenSSH[ _]7\.[0-4]",
        "cve_id": "CVE-2016-10009",
        "title": "OpenSSH Untrusted Search Path & Agent Hijacking",
        "description": "OpenSSH allows remote code execution via untrusted PKCS#11 provider loading when forwarding authentication agents.",
        "metrics": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="L", user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H"),
        "recommendation": "Upgrade OpenSSH to version 8.0p1 or newer, and disable agent forwarding if not needed."
    },
    {
        "service_regex": r"OpenSSH[ _]8\.[0-9]|OpenSSH[ _]9\.[0-2]",
        "cve_id": "CVE-2023-38408",
        "title": "OpenSSH PKCS#11 Provider Remote Code Execution",
        "description": "Condition in ssh-agent PKCS#11 support allows arbitrary library loading and potential remote code execution via forwarded agent sockets.",
        "metrics": CVSSMetrics(attack_vector="N", attack_complexity="H", privileges_required="N", user_interaction="R", scope="U", confidentiality="H", integrity="H", availability="H"),
        "recommendation": "Upgrade OpenSSH to version 9.3p2 or later."
    },
    {
        "service_regex": r"vsftpd[ /]2\.3\.4",
        "cve_id": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 Backdoor Command Execution",
        "description": "Backdoor inserted in vsftpd-2.3.4 source code opens a listening root shell on port 6200 when a smiley face `:)` is sent as the username.",
        "metrics": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"),
        "recommendation": "Remove vsftpd 2.3.4 immediately and install a verified vsftpd 3.x release from trusted repositories."
    },
    {
        "service_regex": r"nginx[ /]1\.1[0-8]\.",
        "cve_id": "CVE-2019-9511",
        "title": "HTTP/2 Denial of Service (Data Dribble)",
        "description": "Vulnerability in HTTP/2 implementation allows an attacker to cause excessive CPU and memory consumption by requesting large data streams.",
        "metrics": CVSSMetrics(attack_vector="N", attack_complexity="L", privileges_required="N", user_interaction="N", scope="U", confidentiality="N", integrity="N", availability="H"),
        "recommendation": "Update Nginx to the current mainline/stable branch (1.24+)."
    }
]


def correlate_service_cves(service: str, version: str) -> List[Dict[str, Any]]:
    """Correlate detected service name and version banner with known CVE intelligence."""
    matches = []
    target_string = f"{service} {version}".strip()

    for item in KNOWN_CVE_DATABASE:
        if re.search(item["service_regex"], target_string, re.IGNORECASE):
            cvss_info = calculate_cvss31(item["metrics"])
            matches.append({
                "cve_id": item["cve_id"],
                "title": item["title"],
                "description": item["description"],
                "recommendation": item["recommendation"],
                "cvss_score": cvss_info["base_score"],
                "severity": cvss_info["severity"],
                "vector_string": cvss_info["vector_string"],
                "impact": cvss_info["impact"],
                "exploitability": cvss_info["exploitability"]
            })

    return matches
