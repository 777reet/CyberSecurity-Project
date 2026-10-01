"""
AegisScan: High-Performance Lightweight Asynchronous Web Server
Zero-external-dependency HTTP server with Server-Sent Events (SSE) streaming,
REST API endpoints, and multi-format report exporter.
"""

import csv
import io
import json
import mimetypes
import os
import queue
import sys
import threading
import time
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Dict, Any, Optional

from core.engine import run_full_assessment
from core.recon_intel import run_recon_intelligence, grade_http_headers, lookup_whois_geo, enumerate_subdomains, get_cert_transparency_log, fingerprint_technologies

try:
    from jinja2 import Template
    HAS_JINJA = True
except ImportError:
    HAS_JINJA = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

# Active scan sessions: scan_id -> {"queue": Queue, "result": data, "complete": bool}
ACTIVE_SCANS: Dict[str, Dict[str, Any]] = {}
LATEST_SCAN_RESULT: Optional[Dict[str, Any]] = None


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class AegisWebHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress noisy HTTP request logging
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. API: Server-Sent Events stream
        if path == "/api/stream":
            scan_id = query.get("scan_id", [None])[0]
            if not scan_id or scan_id not in ACTIVE_SCANS:
                self.send_error(404, "Scan ID not found")
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            event_queue = ACTIVE_SCANS[scan_id]["queue"]
            while True:
                try:
                    event = event_queue.get(timeout=25.0)
                    msg = f"data: {json.dumps(event)}\n\n"
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                    if event.get("type") == "complete" or event.get("type") == "error":
                        break
                except queue.Empty:
                    # Send keep-alive comment
                    try:
                        self.wfile.write(b": keep-alive\n\n")
                        self.wfile.flush()
                    except Exception:
                        break
                except Exception:
                    break
            return

        # 2. API: Threat Intelligence / Recon
        elif path == "/api/intel":
            target = query.get("target", [None])[0]
            module = query.get("module", ["all"])[0]
            web_port = int(query.get("port", ["443"])[0])

            if not target:
                self.send_error(400, "target parameter is required")
                return

            try:
                if module == "headers":
                    data = grade_http_headers(target, port=web_port, timeout=8.0)
                elif module == "geo":
                    data = lookup_whois_geo(target, timeout=8.0)
                elif module == "subdomains":
                    data = enumerate_subdomains(target, timeout=12.0)
                elif module == "certs":
                    data = get_cert_transparency_log(target, timeout=12.0)
                elif module == "tech":
                    data = fingerprint_technologies(target, port=web_port, timeout=8.0)
                else:
                    data = run_recon_intelligence(target, web_port=web_port, timeout=10.0)

                resp_data = json.dumps(data).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(resp_data)))
                self.end_headers()
                self.wfile.write(resp_data)
            except Exception as e:
                err = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err)))
                self.end_headers()
                self.wfile.write(err)
            return

        # 3. API: Export Data
        elif path == "/api/export":
            global LATEST_SCAN_RESULT
            if not LATEST_SCAN_RESULT:
                self.send_error(400, "No scan result available to export")
                return

            export_format = query.get("format", ["html"])[0]
            target_name = LATEST_SCAN_RESULT["metadata"]["target"]

            if export_format == "json":
                content = json.dumps(LATEST_SCAN_RESULT, indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Disposition", f'attachment; filename="{target_name}_audit.json"')
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

            elif export_format == "csv":
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["Port", "State", "Service", "Version", "Latency_ms", "Banner"])
                for p in LATEST_SCAN_RESULT.get("open_ports", []):
                    writer.writerow([p["port"], p["state"], p["service"], p["version"], p["latency_ms"], p["banner"]])
                content = output.getvalue().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition", f'attachment; filename="{target_name}_ports.csv"')
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

            else:
                # HTML Report
                template_path = os.path.join(TEMPLATES_DIR, "report_template.html")
                with open(template_path, "r", encoding="utf-8") as tf:
                    tmpl_content = tf.read()

                if HAS_JINJA:
                    template = Template(tmpl_content)
                    rendered = template.render(**LATEST_SCAN_RESULT)
                else:
                    rendered = tmpl_content

                content = rendered.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{target_name}_report.html"')
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        # 3. Static Files
        if path == "/" or path == "/index.html":
            file_path = os.path.join(WEB_DIR, "index.html")
        elif path.startswith("/assets/"):
            asset_sub = path.replace("/assets/", "")
            file_path = os.path.join(ASSETS_DIR, asset_sub)
        else:
            file_path = os.path.join(WEB_DIR, path.lstrip("/"))

        if os.path.isfile(file_path):
            ctype, _ = mimetypes.guess_type(file_path)
            self.send_response(200)
            self.send_header("Content-Type", ctype or "application/octet-stream")
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404, "File not found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                payload = json.loads(body)
            except Exception:
                self.send_error(400, "Invalid JSON payload")
                return

            target = payload.get("target", "").strip()
            profile = payload.get("profile", "quick")
            custom_ports_str = payload.get("custom_ports", "")
            threads = int(payload.get("threads", 50))

            if not target:
                self.send_error(400, "Target cannot be empty")
                return

            # Parse custom ports if supplied
            ports = None
            if profile == "custom" and custom_ports_str:
                ports = []
                for part in custom_ports_str.split(","):
                    part = part.strip()
                    if "-" in part:
                        start, end = map(int, part.split("-", 1))
                        ports.extend(range(start, end + 1))
                    elif part.isdigit():
                        ports.append(int(part))

            scan_id = f"scan_{int(time.time() * 1000)}"
            event_queue = queue.Queue()
            ACTIVE_SCANS[scan_id] = {
                "queue": event_queue,
                "result": None,
                "complete": False
            }

            # Spawn scan thread
            def background_scanner():
                global LATEST_SCAN_RESULT
                try:
                    def progress_cb(evt):
                        event_queue.put(evt)

                    result = run_full_assessment(
                        target=target,
                        ports=ports,
                        profile=profile,
                        threads=threads,
                        progress_callback=progress_cb
                    )
                    ACTIVE_SCANS[scan_id]["result"] = result
                    ACTIVE_SCANS[scan_id]["complete"] = True
                    LATEST_SCAN_RESULT = result

                except Exception as e:
                    event_queue.put({"type": "error", "message": f"Scan failed: {str(e)}"})
                    ACTIVE_SCANS[scan_id]["complete"] = True

            t = threading.Thread(target=background_scanner, daemon=True)
            t.start()

            resp_data = json.dumps({"scan_id": scan_id}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_data)))
            self.end_headers()
            self.wfile.write(resp_data)
            return

        self.send_error(404, "Unknown endpoint")


def start_server(host: str = "127.0.0.1", port: int = 5050):
    """Starts the AegisScan Web Console server."""
    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, AegisWebHandler)
    print(f"\n=======================================================")
    print(f"  \033[96mAEGIS-SCAN PRO // TACTICAL CYBERSECURITY CONSOLE\033[0m")
    print(f"  Web Interface : \033[92mhttp://{host}:{port}\033[0m")
    print(f"  Press Ctrl+C to terminate.")
    print(f"=======================================================\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down AegisScan console.")
        httpd.server_close()


if __name__ == "__main__":
    start_server()
