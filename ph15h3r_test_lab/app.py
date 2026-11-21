"""Deliberately vulnerable, synthetic telemetry collector restricted to IPv4 loopback."""
from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import re
import threading
from urllib.parse import urlsplit

HOST = "127.0.0.1"
PORT = 8765
MAX_REQUEST_BYTES = 16 * 1024
EVENT_ID_RE = re.compile(r"^telemetry-scanner-[0-9a-f]{32}$")
ENDPOINT_PATH = "/api/telemetry"
BASE_URL = f"http://{HOST}:{PORT}"


class TelemetryLab:
    """In-memory lab behavior, separated from HTTP serving for safe unit tests."""

    def __init__(self) -> None:
        self._events: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def is_loopback(peer: str) -> bool:
        try:
            return ipaddress.ip_address(peer).is_loopback
        except ValueError:
            return False

    @staticmethod
    def _json_response(status: int, value: dict) -> tuple[int, dict[str, str], bytes]:
        body = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return status, {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Length": str(len(body)),
        }, body

    def dispatch(
        self,
        method: str,
        request_target: str,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        peer: str = HOST,
        body_too_large: bool = False,
    ) -> tuple[int, dict[str, str], bytes]:
        """Handle one request. `peer` is checked even though the listener is loopback-only."""
        if not self.is_loopback(peer):
            return self._json_response(403, {"error": "loopback clients only"})

        path = urlsplit(request_target).path
        normalized_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        if body_too_large or len(body) > MAX_REQUEST_BYTES:
            return self._json_response(413, {"error": "synthetic event exceeds request size limit"})

        if method == "GET":
            if path == "/":
                html = f"""<!doctype html><html><head><meta charset="utf-8"><title>PH15H3R Local Telemetry Lab</title></head>
<body><h1>PH15H3R Local Telemetry Lab</h1>
<p>Loopback-only synthetic collector. No authentication is intentionally required on the test ingestion endpoint.</p>
<p>Passive scanner discovery route: <code>{ENDPOINT_PATH}</code></p>
<ul><li><a href="/endpoints">Endpoint listing</a></li><li><a href="/health">Health status</a></li></ul>
<p>Only synthetic scanner events are accepted. Nothing is forwarded.</p></body></html>""".encode("utf-8")
                return 200, {
                    "Content-Type": "text/html; charset=utf-8",
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Length": str(len(html)),
                }, html
            if path == "/health":
                with self._lock:
                    event_count = len(self._events)
                return self._json_response(200, {"status": "ok", "lab": "PH15H3R", "events_in_memory": event_count})
            if path == "/endpoints":
                return self._json_response(200, {
                    "endpoints": [{"method": "POST", "path": ENDPOINT_PATH,
                                   "authentication_required": False,
                                   "purpose": "synthetic scanner validation only"}],
                    "verification": {"method": "GET", "path_template": "/events/{event_id}"},
                })
            if path == "/events":
                with self._lock:
                    events = list(self._events.values())
                return self._json_response(200, {"events": events})
            if path.startswith("/events/"):
                event_id = path.removeprefix("/events/")
                if not EVENT_ID_RE.fullmatch(event_id):
                    return self._json_response(400, {"error": "invalid synthetic event ID"})
                with self._lock:
                    event = self._events.get(event_id)
                if event is None:
                    return self._json_response(404, {"error": "synthetic event not found", "event_id": event_id})
                # The scanner's read-only verifier requires this exact event_id field.
                return self._json_response(200, {"event_id": event_id, "accepted_at": event["accepted_at"]})
            return self._json_response(404, {"error": "not found"})

        if method != "POST" or path != ENDPOINT_PATH:
            return self._json_response(404, {"error": "not found"})
        if not normalized_headers.get("content-type", "").lower().startswith("application/json"):
            return self._json_response(415, {"error": "application/json required"})
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._json_response(400, {"error": "invalid JSON"})
        if not isinstance(payload, dict):
            return self._json_response(400, {"error": "JSON object required"})

        event_id = payload.get("event_id")
        event_name = payload.get("event")
        timestamp = payload.get("timestamp")
        attributes = payload.get("attributes")
        if not isinstance(event_id, str) or not EVENT_ID_RE.fullmatch(event_id):
            return self._json_response(400, {"error": "valid synthetic event_id required"})
        if event_name != "authorized_scanner_validation":
            return self._json_response(400, {"error": "only the scanner's harmless synthetic event is accepted"})
        if not isinstance(timestamp, str) or not timestamp:
            return self._json_response(400, {"error": "timestamp required"})
        if not isinstance(attributes, dict) or attributes.get("scanner.synthetic") is not True:
            return self._json_response(400, {"error": "synthetic marker required"})

        # INTENTIONALLY VULNERABLE: no Authorization header or credential is required.
        # This route stores only event ID and receipt time, never forwards telemetry.
        accepted_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            duplicate = event_id in self._events
            self._events.setdefault(event_id, {"event_id": event_id, "accepted_at": accepted_at})
        status = 200 if duplicate else 202
        return self._json_response(status, {
            "accepted": True,
            "duplicate": duplicate,
            "event_id": event_id,
            "authentication_required": False,
            "lab": "PH15H3R Local Telemetry Lab",
        })


def make_server(lab: TelemetryLab | None = None, port: int = PORT) -> ThreadingHTTPServer:
    """Create a server bound to 127.0.0.1 only; no host override is provided."""
    application = lab or TelemetryLab()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args) -> None:
            # Avoid dumping request contents or query strings into terminal logs.
            return

        def _handle(self) -> None:
            declared_length = self.headers.get("Content-Length", "0")
            try:
                length = int(declared_length)
                if length < 0:
                    raise ValueError
            except ValueError:
                status, response_headers, response_body = application._json_response(400, {"error": "invalid Content-Length"})
            else:
                too_large = length > MAX_REQUEST_BYTES
                body = b"" if too_large or self.command != "POST" else self.rfile.read(length)
                status, response_headers, response_body = application.dispatch(
                    self.command, self.path, dict(self.headers), body,
                    peer=self.client_address[0], body_too_large=too_large,
                )
            self.send_response(status)
            for key, value in response_headers.items():
                self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response_body)
            self.close_connection = True

        do_GET = _handle
        do_POST = _handle
        do_HEAD = _handle

    server = ThreadingHTTPServer((HOST, int(port)), Handler)
    server.daemon_threads = True
    if server.server_address[0] != HOST:
        server.server_close()
        raise RuntimeError("Lab refused to bind outside 127.0.0.1")
    return server


def main() -> None:
    server = make_server()
    print(f"PH15H3R Local Telemetry Lab listening at http://{HOST}:{server.server_port}/")
    print("Loopback only. Press Ctrl+C to stop.")
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\nStopping local test lab.")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
