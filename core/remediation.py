"""
AegisScan: Actionable Remediation & Hardening Playbook Generator
Generates concrete, copy-pasteable configuration snippets for Nginx, Apache,
Linux iptables/UFW, sshd_config, and DNS policies.
"""

from typing import Dict, Any, List


def generate_header_remediation(missing_headers: List[str]) -> Dict[str, str]:
    """Generates server configuration directives to enforce missing security headers."""
    nginx_lines = []
    apache_lines = []

    directives = {
        "Strict-Transport-Security": (
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"'
        ),
        "Content-Security-Policy": (
            'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; upgrade-insecure-requests" always;',
            'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; upgrade-insecure-requests"'
        ),
        "X-Frame-Options": (
            'add_header X-Frame-Options "SAMEORIGIN" always;',
            'Header always set X-Frame-Options "SAMEORIGIN"'
        ),
        "X-Content-Type-Options": (
            'add_header X-Content-Type-Options "nosniff" always;',
            'Header always set X-Content-Type-Options "nosniff"'
        ),
        "Referrer-Policy": (
            'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            'Header always set Referrer-Policy "strict-origin-when-cross-origin"'
        ),
        "Permissions-Policy": (
            'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
            'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"'
        )
    }

    for h in missing_headers:
        if h in directives:
            nginx_lines.append("    " + directives[h][0])
            apache_lines.append("    " + directives[h][1])

    nginx_block = (
        "# Nginx Server Configuration Block\n"
        "server {\n"
        "    listen 443 ssl http2;\n"
        "    server_name example.com;\n\n"
        "    # OWASP Recommended Security Headers\n"
        + "\n".join(nginx_lines) + "\n"
        "    ...\n"
        "}"
    )

    apache_block = (
        "# Apache VirtualHost or .htaccess Configuration\n"
        "<IfModule mod_headers.c>\n"
        + "\n".join(apache_lines) + "\n"
        "</IfModule>"
    )

    return {
        "title": "Enforce HTTP Security Headers",
        "nginx": nginx_block,
        "apache": apache_block
    }


def generate_sensitive_path_remediation() -> Dict[str, str]:
    """Generates server rules to deny access to hidden files and sensitive directories."""
    nginx = (
        "# Nginx: Block access to hidden files (.env, .git, .svn) and backup archives\n"
        "location ~ /\\.(?!well-known).* {\n"
        "    deny all;\n"
        "    access_log off;\n"
        "    log_not_found off;\n"
        "    return 404;\n"
        "}\n\n"
        "location ~* \\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|env)$ {\n"
        "    deny all;\n"
        "    return 404;\n"
        "}"
    )

    apache = (
        "# Apache: Deny access to sensitive files and directories\n"
        "<FilesMatch \"^\\.(?!well-known)\">\n"
        "    Require all denied\n"
        "</FilesMatch>\n\n"
        "<FilesMatch \"\\.(bak|config|sql|ini|log|sh|env|git)$\">\n"
        "    Require all denied\n"
        "</FilesMatch>"
    )

    return {
        "title": "Block Sensitive Asset Disclosures (.env, .git)",
        "nginx": nginx,
        "apache": apache
    }


def generate_ssl_remediation() -> Dict[str, str]:
    """Generates modern TLS configuration enforcing TLS 1.2+ and AEAD ciphers."""
    nginx = (
        "# Nginx: Modern Cryptographic Profile (Mozilla Recommended)\n"
        "ssl_protocols TLSv1.2 TLSv1.3;\n"
        "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;\n"
        "ssl_prefer_server_ciphers off;\n"
        "ssl_session_timeout 1d;\n"
        "ssl_session_cache shared:SSL:10m;\n"
        "ssl_session_tickets off;\n"
        "ssl_stapling on;\n"
        "ssl_stapling_verify on;"
    )

    apache = (
        "# Apache: Modern Cryptographic Profile\n"
        "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
        "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384\n"
        "SSLHonorCipherOrder off\n"
        "SSLSessionTickets off"
    )

    return {
        "title": "Harden SSL/TLS Protocol & Cipher Suites",
        "nginx": nginx,
        "apache": apache
    }


def generate_dns_remediation(domain: str) -> Dict[str, str]:
    """Generates authoritative SPF and DMARC DNS record entries."""
    spf_record = f"{domain}. IN TXT \"v=spf1 mx -all\""
    dmarc_record = f"_dmarc.{domain}. IN TXT \"v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@{domain}; ruf=mailto:dmarc-forensics@{domain}; adkim=s; aspf=s\""

    explanation = (
        f"# Recommended DNS Resource Records for {domain}\n\n"
        f"1. Strict SPF Record (Prevents Unauthorized Sending Servers):\n"
        f"   Host: @\n"
        f"   Type: TXT\n"
        f"   Value: v=spf1 mx -all\n\n"
        f"2. Strict DMARC Policy (Instructs Receivers to Reject Spoofed Emails):\n"
        f"   Host: _dmarc\n"
        f"   Type: TXT\n"
        f"   Value: v=DMARC1; p=reject; pct=100; rua=mailto:security-dmarc@{domain}\n"
    )

    return {
        "title": "Email Spoofing & Phishing Defense (SPF & DMARC)",
        "dns_records": explanation,
        "spf_syntax": spf_record,
        "dmarc_syntax": dmarc_record
    }


def generate_port_firewall_remediation(port: int, service: str) -> Dict[str, str]:
    """Generates firewall rules to restrict exposed management ports."""
    iptables = (
        f"# Restrict {service} (Port {port}) to local or management subnet only\n"
        f"sudo iptables -A INPUT -p tcp -s 127.0.0.1 --dport {port} -j ACCEPT\n"
        f"sudo iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport {port} -j ACCEPT\n"
        f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP"
    )

    ufw = (
        f"# UFW firewall rules for Port {port} ({service})\n"
        f"sudo ufw delete allow {port}/tcp\n"
        f"sudo ufw allow from 10.0.0.0/8 to any port {port} proto tcp"
    )

    return {
        "title": f"Restrict Inbound Access to Port {port} ({service})",
        "iptables": iptables,
        "ufw": ufw
    }
