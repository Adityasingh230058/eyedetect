"""Lightweight Threat Hunting Web Server for eyedetect UI.

Serves the Wazuh-themed dashboard and provides real-time JSON alert streaming from the simulation logs.
"""

import http.server
import json
import socketserver
import webbrowser
from pathlib import Path

PORT = 8080
UI_DIR = Path(__file__).parent.resolve()
ROOT_DIR = UI_DIR.parent
ALERTS_LOG = ROOT_DIR / "samples" / "master_simulation_alerts.ndjson"


class ThreatHuntingHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(UI_DIR), **kwargs)

    def do_GET(self):
        if self.path == "/api/alerts":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            alerts = []
            if ALERTS_LOG.exists():
                with open(ALERTS_LOG, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                raw = json.loads(line)
                                alerts.append(
                                    {
                                        "timestamp": raw.get("timestamp", ""),
                                        "host_id": raw.get("host_id", "UNKNOWN"),
                                        "platform": "Windows 11" if "WS" in raw.get("host_id", "") else ("AWS Cloud" if "AWS" in raw.get("host_id", "") else "Linux / Server"),
                                        "technique": raw.get("mitre_technique", "T1059"),
                                        "tactic": raw.get("mitre_tactic", "Execution"),
                                        "description": raw.get("title", ""),
                                        "level": raw.get("level", 10),
                                        "rule_id": raw.get("rule_id", ""),
                                        "evidence": raw.get("evidence", {}),
                                        "auto_response": raw.get("active_response", {}).get("action") if raw.get("active_response") else "NEUTRALIZED",
                                    }
                                )
                            except Exception:
                                pass

            self.wfile.write(json.dumps(alerts).encode("utf-8"))
            return

        return super().do_GET()


def run_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), ThreatHuntingHandler) as httpd:
        url = f"http://localhost:{PORT}"
        print("=" * 70)
        print("👁️  eyedetect — Threat Hunting Web Dashboard")
        print("=" * 70)
        print(f"[*] Dashboard running live at : {url}")
        print("[*] Press Ctrl+C in terminal to stop.")
        print("=" * 70)

        # Open web browser automatically
        try:
            webbrowser.open(url)
        except Exception:
            pass

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")


if __name__ == "__main__":
    run_server()
