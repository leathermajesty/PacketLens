"""Tiny local web server for the dashboard (standard library only).

Routes:
    GET  /              dashboard page
    GET  /static/<f>    css/js
    GET  /api/state       current snapshot (JSON)
    GET  /api/stream      live updates (Server-Sent Events):
                            event "state"   - devices, log, status
                            event "packets" - new packet rows since the last batch
    GET  /api/packet/<n>  all layers + hex dump of packet number n
    POST /api/scan        start an ARP scan

It listens on 127.0.0.1 only, so nobody else on the Wi-Fi can open it.
"""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .engine import Engine

WEB_DIR = Path(__file__).parent / "web"
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}
HEARTBEAT = 2.0        # seconds; also refreshes counters in the UI
BATCH_INTERVAL = 0.25  # group packets into ~4 updates per second
BACKLOG = 500          # packets a newly opened page gets straight away


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
            elif route.startswith("/api/packet/") and route[len("/api/packet/"):].isdigit():
                detail = engine.packet_detail(int(route[len("/api/packet/"):]))
                if detail is None:
                    self._json({"error": "That packet is no longer in the buffer"}, 404)
                else:
                    self._json(detail)
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
            last_version, last_sent = None, 0.0
            last_packet = max(engine.packet_seq - BACKLOG, 0)
            try:
                while True:
                    with engine.cond:
                        engine.cond.wait_for(lambda: engine.version != last_version
                                             or engine.packet_seq != last_packet, timeout=HEARTBEAT)
                        version, newest = engine.version, engine.packet_seq
                    now = time.monotonic()
                    if version != last_version or now - last_sent >= HEARTBEAT:
                        self._event("state", engine.snapshot())
                        last_version, last_sent = version, now
                    if newest != last_packet:
                        batch = engine.packets_since(last_packet)
                        if batch:
                            self._event("packets", batch)
                        last_packet = batch[-1]["no"] if batch else newest
                    self.wfile.flush()
                    time.sleep(BATCH_INTERVAL)
            except (BrokenPipeError, ConnectionResetError):
                return

        def _event(self, name: str, data) -> None:
            self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())

    return Handler


def make_server(engine: Engine, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(engine))
    server.daemon_threads = True
    return server
