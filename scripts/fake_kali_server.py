#!/usr/bin/env python3
"""fake_kali_server.py — minimal stand-in for the kali-tools HTTP service.

Mirrors the two endpoints the bridge consumes:
    GET  /            -> 200 (health probe)
    POST /run         -> {"stdout": ..., "stderr": ..., "exit_code": 0}

Use it to smoke-test `kali.run` routing and health without bringing up the
real Kali container:

    python3 scripts/fake_kali_server.py 127.0.0.1:3801 &
    KALI_TOOLS_URL=http://127.0.0.1:3801 python3 -m bridge.raphael_bridge

Not a pentest tool; test fixture only.
"""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._send(200, {"service": "fake-kali", "ok": True})

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        req = json.loads(self.rfile.read(n) or b"{}")
        self._send(200, {
            "stdout": (f"[fake-kali] ran {req.get('tool')} "
                       f"{req.get('args')} against {req.get('target')}"),
            "stderr": "",
            "exit_code": 0,
        })

    def log_message(self, fmt, *args):  # quiet
        pass


def main():
    host, _, port = (sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:3801").rpartition(":")
    srv = HTTPServer((host or "127.0.0.1", int(port or 3801)), Handler)
    print(f"fake-kali listening on {srv.server_address}", file=sys.stderr)
    srv.serve_forever()


if __name__ == "__main__":
    main()
