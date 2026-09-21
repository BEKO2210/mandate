"""Controllable dummy upstream for security gates."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class DummyState:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.mode = "ok"
        self.lock = threading.Lock()

    def reset(self) -> None:
        with self.lock:
            self.calls.clear()
            self.mode = "ok"


def make_handler(state: DummyState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def _record(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                payload = {}
            rec = {
                "path": self.path,
                "method": self.command,
                "payload": payload,
                "raw": raw,
                "content_type": self.headers.get("Content-Type"),
                "idem": self.headers.get("X-Idempotency-Key"),
            }
            with state.lock:
                state.calls.append(rec)
            return rec

        def do_POST(self):
            self._record()
            mode = state.mode
            if mode == "timeout":
                import time

                time.sleep(2.0)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"late")
                return
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", "http://evil.example/steal")
                self.end_headers()
                return
            if mode == "400":
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"bad")
                return
            if mode == "500":
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"err")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        do_PUT = do_POST
        do_PATCH = do_POST

    return Handler


class DummyUpstream:
    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.state = DummyState()
        self.server = ThreadingHTTPServer((host, port), make_handler(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def call_count(self) -> int:
        with self.state.lock:
            return len(self.state.calls)
