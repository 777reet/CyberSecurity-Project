#!/usr/bin/env python3
"""
AegisScan: Autonomous Multi-Vector Network & Web Cybersecurity Assessment Platform
Version: 3.0 Pro

Unified Launcher:
- Default: Launches interactive Tactical Cyber Console Web UI (http://127.0.0.1:5000)
- CLI Mode: Runs automated multi-vector terminal scan (e.g., python app.py -t scanme.nmap.org --cli)
"""

import argparse
import os
import sys
import webbrowser
from datetime import datetime
from jinja2 import Template

from core.engine import run_full_assessment, PRESET_PROFILES
from web_server import start_server


class TerminalColors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


def parse_port_range(port_string: str):
    ports = []
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-', 1))
            ports.extend(range(start, end + 1))
        elif part.isdigit():
            ports.append(int(part))
    return sorted(set(ports))


def run_cli_audit(args):
    """Executes full multi-vector cybersecurity audit in the terminal."""
    print(f"\n{TerminalColors.BOLD}{TerminalColors.CYAN}" + "=" * 70)
    print("  AEGIS-SCAN v3.0 PRO // TERMINAL RECONNAISSANCE & RISK ASSESSMENT")
    print("=" * 70 + f"{TerminalColors.END}\n")

    ports = None
    if args.ports:
        try:
            ports = parse_port_range(args.ports)
        except Exception as e:
            print(f"{TerminalColors.RED}[ERROR] Invalid port range: {e}{TerminalColors.END}")
            sys.exit(1)

    profile = args.profile or ("quick" if not ports else "custom")

    print(f"{TerminalColors.YELLOW}[INFO]{TerminalColors.END} Target Host : {args.target}")
    print(f"{TerminalColors.YELLOW}[INFO]{TerminalColors.END} Profile     : {profile.upper()}")
    print(f"{TerminalColors.YELLOW}[INFO]{TerminalColors.END} Threads     : {args.threads}")
    print(f"{TerminalColors.YELLOW}[INFO]{TerminalColors.END} Timeout     : {args.timeout}s\n")

    def progress_callback(evt):
        if evt.get("type") == "status":
            print(f"{TerminalColors.BLUE}[STATUS]{TerminalColors.END} {evt['message']}")
        elif evt.get("type") == "port_found":
            print(f"{TerminalColors.GREEN}[PORT FOUND]{TerminalColors.END} {evt['port']}/TCP  {evt['service']} ({evt['version']}) - {evt['latency_ms']}ms")

    # Run comprehensive assessment
    results = run_full_assessment(
        target=args.target,
        ports=ports,
        profile=profile,
        threads=args.threads,
        timeout=args.timeout,
        progress_callback=progress_callback
    )

    # Display Terminal Summary
    print(f"\n{TerminalColors.BOLD}{TerminalColors.GREEN}RECONNAISSANCE SUMMARY{TerminalColors.END}")
    print("-" * 70)
    print(f"  Target IP Address   : {results['metadata']['resolved_ip']}")
    print(f"  Open Ports Found    : {results['metadata']['open_ports_count']}")
    print(f"  Total Vulnerabilities: {results['risk_summary']['total_findings']}")
    print(f"  Overall Risk Level  : {results['risk_summary']['overall_risk']}")
    print(f"  Average CVSS 3.1    : {results['risk_summary']['cvss_average']}")
    print(f"  Critical / High / Medium / Low : "
          f"{results['risk_summary']['critical']} / {results['risk_summary']['high']} / "
          f"{results['risk_summary']['medium']} / {results['risk_summary']['low']}")
    print(f"  Duration            : {results['metadata']['scan_duration_seconds']}s\n")

    # Display Findings
    if results['vulnerabilities']:
        print(f"{TerminalColors.BOLD}{TerminalColors.RED}QUANTITATIVE VULNERABILITY FINDINGS{TerminalColors.END}")
        print("=" * 70)
        for i, v in enumerate(results['vulnerabilities'], 1):
            sev_color = TerminalColors.RED if v['severity'] in ['Critical', 'High'] else TerminalColors.YELLOW
            print(f"[{i}] {sev_color}{v['title']}{TerminalColors.END}")
            print(f"    Severity: {v['severity']} | CVSS: {v['cvss_score']} | Vector: {v.get('vector_string', 'N/A')}")
            print(f"    Issue: {v['description']}")
            print(f"    Remediation: {v['recommendation']}\n")

    # Export Report HTML
    base_dir = os.path.dirname(os.path.abspath(__file__))
    tmpl_path = os.path.join(base_dir, "templates", "report_template.html")
    with open(tmpl_path, "r", encoding="utf-8") as tf:
        template = Template(tf.read())
    rendered_html = template.render(**results)

    report_filename = args.report or "report.html"
    with open(report_filename, "w", encoding="utf-8") as rf:
        rf.write(rendered_html)
    print(f"{TerminalColors.GREEN}[EXPORT]{TerminalColors.END} Executive HTML report written to: {report_filename}")

    # Optional JSON export
    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as jf:
            json.dump(results, jf, indent=2)
        print(f"{TerminalColors.GREEN}[EXPORT]{TerminalColors.END} JSON assessment exported to: {args.json}")

    # Optional CSV export
    if args.csv:
        import csv
        with open(args.csv, "w", newline="", encoding="utf-8") as cf:
            writer = csv.writer(cf)
            writer.writerow(["Port", "State", "Service", "Version", "Latency_ms", "Banner"])
            for p in results.get("open_ports", []):
                writer.writerow([p["port"], p["state"], p["service"], p["version"], p["latency_ms"], p["banner"]])
        print(f"{TerminalColors.GREEN}[EXPORT]{TerminalColors.END} Port CSV exported to: {args.csv}")

    print(f"\n{TerminalColors.GREEN}[DONE]{TerminalColors.END} Assessment completed.\n")


def main():
    parser = argparse.ArgumentParser(
        description="AegisScan: Autonomous Network & Web Vulnerability Assessment Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Launch Interactive Tactical Web Console (Default):
  python app.py

  # Run Fast CLI Reconnaissance on a domain or IP:
  python app.py -t scanme.nmap.org --cli

  # Web Services & OWASP Assessment:
  python app.py -t example.com --profile web --cli

  # Custom Ports with JSON & HTML Reports:
  python app.py -t 192.168.1.1 -p 22,80,443,3306 --cli --json scan.json --report audit.html
        """
    )

    parser.add_argument("-t", "--target", help="Target IP, hostname, or domain (e.g. 127.0.0.1, scanme.nmap.org)")
    parser.add_argument("-p", "--ports", help="Port range (e.g. 1-1000, 80,443,8080)")
    parser.add_argument("--profile", choices=list(PRESET_PROFILES.keys()), help="Recon profile (quick, web, databases, infrastructure, standard)")
    parser.add_argument("--threads", type=int, default=50, help="Worker threads for port scanning (default: 50)")
    parser.add_argument("--timeout", type=float, default=2.5, help="Socket connect timeout in seconds (default: 2.5)")
    parser.add_argument("--cli", action="store_true", help="Run in headless terminal CLI mode instead of launching Web GUI")
    parser.add_argument("--web", action="store_true", help="Force launching the Web Console")
    parser.add_argument("--port", type=int, default=5000, help="Port to host Web Console on (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface for Web Console (default: 127.0.0.1)")
    parser.add_argument("-o", "--json", help="Export assessment results to JSON file")
    parser.add_argument("--csv", help="Export open ports to CSV file")
    parser.add_argument("--report", help="Output path for HTML report (default: report.html)")

    args = parser.parse_args()

    # Determine execution mode:
    # If explicitly --cli or target specified without --web, run CLI
    if args.cli or (args.target and not args.web):
        if not args.target:
            print(f"{TerminalColors.RED}[ERROR] Target (-t/--target) is required when running in CLI mode.{TerminalColors.END}")
            sys.exit(1)
        run_cli_audit(args)
    else:
        # Default: Launch Web Console
        url = f"http://{args.host}:{args.port}"
        # Automatically open browser in separate thread
        def open_browser():
            import time
            time.sleep(0.8)
            webbrowser.open(url)

        import threading
        threading.Thread(target=open_browser, daemon=True).start()
        start_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
