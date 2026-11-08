"""Tiny local web server for the dashboard (standard library only).

Routes:
    GET  /              dashboard page
    GET  /static/<f>    css/js
    GET  /api/state     current snapshot (JSON)
    GET  /api/stream    live snapshots (Server-Sent Events)
    POST /api/scan      start an ARP scan

It listens on 127.0.0.1 only, so nobody else on the Wi-Fi can open it.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .engine import Engine

WEB_DIR = Path(__file__).parent / "web"
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}
HEARTBEAT = 2.0  # seconds; also refreshes counters in the UI


def make_handler(engine: Engine):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep the terminal quiet
            pass

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data, status: int = 200) -> None:
            self._send(status, json.dumps(data).encode(), "application/json")

        def _static(self, name: str) -> None:
            path = (WEB_DIR / name).resolve()
            if WEB_DIR.resolve() not in path.parents or not path.is_file():
                return self._send(404, b"Not found", "text/plain")
            self._send(200, path.read_bytes(), CONTENT_TYPES.get(path.suffix, "application/octet-stream"))

        def do_GET(self):
            route = self.path.split("?", 1)[0]
            if route == "/":
                self._static("index.html")
            elif route.startswith("/static/"):
                self._static(route[len("/static/"):])
            elif route == "/api/state":
                self._json(engine.snapshot())
            elif route == "/api/stream":
                self._stream()
            else:
                self._send(404, b"Not found", "text/plain")

        def do_POST(self):
            if self.path == "/api/scan":
                started = engine.start_scan()
                self._json({"started": started}, 200 if started else 409)
            else:
                self._send(404, b"Not found", "text/plain")

        def _stream(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            last = None
            try:
                while True:
                    with engine.cond:
                        engine.cond.wait_for(lambda: engine.version != last, timeout=HEARTBEAT)
                        last = engine.version
                        payload = json.dumps(engine.snapshot())
                    self.wfile.write(f"data: {payload}\n\n".encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return

    return Handler


def make_server(engine: Engine, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(engine))
    server.daemon_threads = True
    return server
