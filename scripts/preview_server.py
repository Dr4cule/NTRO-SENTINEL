#!/usr/bin/env python3
"""Stdlib-only local preview of the dashboard against the real SQLite store.
Mirrors the four API endpoints the dashboard reads. For UI preview only —
production serving is FastAPI in Docker (api/main.py). ponytail: no deps by design."""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run from any cwd
from alertstore.store import AlertStore

store = AlertStore()
INDEX = Path(__file__).parent.parent / "dashboard" / "index.html"  # re-read per request so edits preview live


def incidents():
    grouped = {}
    for a in store.list(limit=1000):
        k = a["flow_id"]["src_ip"]
        x = grouped.setdefault(k, {"source": k, "risk": 0, "classes": set(), "alerts": []})
        x["risk"] = min(100, x["risk"] + round(a["confidence"] * 18))
        x["classes"].add(a["threat_class"]); x["alerts"].append(a)
    return [{**x, "classes": sorted(x["classes"]), "alerts": x["alerts"][:6]} for x in grouped.values()]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, obj, ctype="application/json"):
        body = (obj if isinstance(obj, str) else json.dumps(obj)).encode()
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path); q = parse_qs(p.query)
        if p.path in ("/", "/index.html"): return self._send(INDEX.read_text(), "text/html")
        if p.path == "/api/alerts":
            return self._send(store.list(q.get("threat_class", [None])[0], q.get("severity", [None])[0], 250))
        if p.path == "/api/dashboard/summary": return self._send(store.summary())
        if p.path == "/api/evidence/verify": return self._send(store.verify_chain())
        if p.path == "/api/incidents": return self._send(incidents())
        self.send_response(404); self.end_headers()

    def do_POST(self):
        if urlparse(self.path).path != "/api/ingest":
            self.send_response(404); self.end_headers(); return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= 300 * 1024 * 1024: raise ValueError("empty upload or exceeds 300 MB cap")
            data = self.rfile.read(length)
            from ingest.service import ingest_upload  # lazy: keep viewer startup dependency-free
            self._send(ingest_upload(self.headers.get("X-Filename", "upload.jsonl"), data))
        except Exception as ex:
            body = json.dumps({"error": str(ex)}).encode()
            self.send_response(400); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8001
    print(f"preview on http://localhost:{port}"); HTTPServer(("127.0.0.1", port), H).serve_forever()
