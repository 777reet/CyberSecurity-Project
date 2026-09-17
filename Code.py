#!/usr/bin/env python3
"""
Network Vulnerability Scanner and Risk Assessment Tool
Version: 3.0 Pro (AegisScan Engine)

This file maintains 100% backward-compatibility with all legacy CLI arguments,
while integrating the upgraded multi-vector reconnaissance engine, NIST CVSS 3.1
scoring, SSL/TLS cryptographic inspection, OWASP web audit, and interactive Web Console.
"""

import argparse
import os
import sys
import webbrowser

from core.engine import run_full_assessment, PRESET_PROFILES
from app import run_cli_audit
from web_server import start_server


def main():
    # If no command-line arguments are provided, launch the Tactical Web Console
    if len(sys.argv) == 1:
        url = "http://127.0.0.1:5000"
        def open_browser():
            import time
            time.sleep(0.8)
            webbrowser.open(url)

        import threading
        threading.Thread(target=open_browser, daemon=True).start()
        start_server(host="127.0.0.1", port=5000)
        return

    parser = argparse.ArgumentParser(
        description='Network Vulnerability Scanner and Risk Assessment Tool (v3.0 Pro)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 -p 1-1000
  %(prog)s -t 192.168.1.0/24 --top-ports
  %(prog)s -t scanme.nmap.org --top-ports -o results.json
  %(prog)s -t scanme.nmap.org -p 1-65535 --csv ports.csv
  %(prog)s --web
        """
    )

    parser.add_argument('-t', '--target',
                        help='Target IP, hostname, or network range (e.g. 192.168.1.1 or scanme.nmap.org)')
    parser.add_argument('-p', '--ports', default='1-1000',
                        help='Port range (e.g. 1-1000, 22,80,443)')
    parser.add_argument('--top-ports', action='store_true',
                        help='Scan the most common ports')
    parser.add_argument('--threads', type=int, default=50,
                        help='Thread count (default: 50)')
    parser.add_argument('--timeout', type=float, default=2.5,
                        help='Connection timeout in seconds (default: 2.5)')
    parser.add_argument('-o', '--output',
                        help='Export results to a JSON file')
    parser.add_argument('--csv',
                        help='Export results to a CSV file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('--web', action='store_true',
                        help='Launch the interactive Web Console UI')
    parser.add_argument('--profile', choices=list(PRESET_PROFILES.keys()),
                        help='Recon profile (quick, web, databases, infrastructure, standard)')

    args = parser.parse_args()

    if args.web or not args.target:
        url = "http://127.0.0.1:5000"
        def open_browser():
            import time
            time.sleep(0.8)
            webbrowser.open(url)

        import threading
        threading.Thread(target=open_browser, daemon=True).start()
        start_server(host="127.0.0.1", port=5000)
        return

    # Adapt arguments to unified audit runner
    class CLIArgsAdapter:
        pass

    cli_args = CLIArgsAdapter()
    cli_args.target = args.target
    cli_args.threads = args.threads
    cli_args.timeout = args.timeout
    cli_args.json = args.output
    cli_args.csv = args.csv
    cli_args.report = "report.html"

    if args.top_ports:
        cli_args.ports = None
        cli_args.profile = "quick"
    elif args.profile:
        cli_args.ports = None
        cli_args.profile = args.profile
    else:
        cli_args.ports = args.ports
        cli_args.profile = "custom"

    run_cli_audit(cli_args)


if __name__ == "__main__":
    main()