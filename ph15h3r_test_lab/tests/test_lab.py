import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

import httpx

LAB_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = LAB_DIR.parent
sys.path.insert(0, str(LAB_DIR))
sys.path.insert(0, str(PROJECT_DIR))

from app import BASE_URL, ENDPOINT_PATH, HOST, PORT, MAX_REQUEST_BYTES, TelemetryLab, make_server
from telemetry_scanner.active import ActiveConfig, ActiveValidator
from telemetry_scanner.discovery import analyze_document
from telemetry_scanner.models import Endpoint, Status
from telemetry_scanner.scanner import MAX_RESOURCES, scan
from telemetry_scanner.verification import ReadOnlyVerifier


SYNTHETIC = {
    "event": "authorized_scanner_validation",
    "event_id": "telemetry-scanner-0123456789abcdef0123456789abcdef",
    "timestamp": "2026-11-21T00:00:00+00:00",
    "attributes": {"scanner.synthetic": True},
}


def response_for(app, request, peer=HOST):
    status, headers, body = app.dispatch(
        request.method, str(request.url), dict(request.headers), request.content, peer=peer
    )
    return httpx.Response(status, headers=headers, content=body, request=request)


class LabEndpointTests(unittest.TestCase):
    def setUp(self):
        self.app = TelemetryLab()

    def test_loopback_configuration_and_non_loopback_rejection(self):
        self.assertEqual(HOST, "127.0.0.1")
        self.assertEqual(PORT, 8765)
        self.assertTrue(self.app.is_loopback("127.0.0.1"))
        self.assertFalse(self.app.is_loopback("192.0.2.9"))
        status, _, body = self.app.dispatch("GET", "/health", peer="192.0.2.9")
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error"], "loopback clients only")

    def test_server_binds_only_to_loopback(self):
        try:
            server = make_server(port=0)
        except PermissionError:
            self.skipTest("Sandbox denies local listening sockets; address policy is covered in-process")
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
        finally:
            server.server_close()

    def test_homepage_and_endpoint_listing_are_discoverable(self):
        status, headers, body = self.app.dispatch("GET", "/")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        endpoints, _ = analyze_document(body.decode(), BASE_URL + "/", headers["Content-Type"])
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].url, BASE_URL + ENDPOINT_PATH)
        self.assertEqual(endpoints[0].service, "Custom telemetry API")
        listed = self.app.dispatch("GET", "/endpoints")
        self.assertEqual(listed[0], 200)
        self.assertEqual(json.loads(listed[2])["endpoints"][0]["path"], ENDPOINT_PATH)

    def test_unauthenticated_synthetic_event_acknowledges_exact_id(self):
        # No Authorization header is supplied: this missing-auth control is intentional.
        status, headers, body = self.app.dispatch(
            "POST", ENDPOINT_PATH, {"content-type": "application/json"}, json.dumps(SYNTHETIC).encode()
        )
        ack = json.loads(body)
        self.assertEqual(status, 202)
        self.assertTrue(headers["Content-Type"].startswith("application/json"))
        self.assertTrue(ack["accepted"])
        self.assertFalse(ack["authentication_required"])
        self.assertEqual(ack["event_id"], SYNTHETIC["event_id"])

    def test_invalid_request_handling_and_size_limit(self):
        status, _, _ = self.app.dispatch("POST", ENDPOINT_PATH, {"content-type": "application/json"}, b"{")
        self.assertEqual(status, 400)
        status, _, _ = self.app.dispatch("POST", ENDPOINT_PATH, {"content-type": "text/plain"}, b"hello")
        self.assertEqual(status, 415)
        status, _, _ = self.app.dispatch("POST", ENDPOINT_PATH, {"content-type": "application/json"}, b"{}")
        self.assertEqual(status, 400)
        status, _, _ = self.app.dispatch(
            "POST", ENDPOINT_PATH, {"content-type": "application/json"}, b"x" * (MAX_REQUEST_BYTES + 1)
        )
        self.assertEqual(status, 413)

    def test_read_only_event_id_verification(self):
        self.app.dispatch("POST", ENDPOINT_PATH, {"content-type": "application/json"}, json.dumps(SYNTHETIC).encode())
        status, headers, body = self.app.dispatch("GET", f"/events/{SYNTHETIC['event_id']}")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("application/json"))
        self.assertEqual(json.loads(body)["event_id"], SYNTHETIC["event_id"])
        self.assertEqual(self.app.dispatch("GET", "/events/telemetry-scanner-missing")[0], 400)

    def test_no_external_network_client_or_forwarding(self):
        # App dispatch has no outbound client. Fail if it tries the common socket helper.
        with patch.object(socket, "create_connection", side_effect=AssertionError("outbound connection attempted")):
            status, _, _ = self.app.dispatch("GET", "/health")
            self.assertEqual(status, 200)
            status, _, _ = self.app.dispatch(
                "POST", ENDPOINT_PATH, {"content-type": "application/json"}, json.dumps(SYNTHETIC).encode()
            )
            self.assertEqual(status, 202)
        self.assertNotIn("forwarded_to", self.app._events[SYNTHETIC["event_id"]])


class ScannerCompatibilityTests(unittest.TestCase):
    def test_full_passive_scan_finds_lab_endpoint_without_network(self):
        app = TelemetryLab()
        def transport(request):
            return response_for(app, request)
        real_client = httpx.Client
        with patch("telemetry_scanner.scanner.httpx.Client", side_effect=lambda **kw: real_client(transport=httpx.MockTransport(transport), **kw)):
            report = scan(BASE_URL + "/")
        self.assertEqual(len(report.endpoints), 1)
        self.assertEqual(report.endpoints[0].url, BASE_URL + ENDPOINT_PATH)
        self.assertEqual(report.endpoints[0].status, Status.DISCOVERED)

    def test_active_validator_and_read_only_verifier_confirm_ingestion_not_vulnerability(self):
        app = TelemetryLab()
        real_client = httpx.Client
        transport = httpx.MockTransport(lambda request: response_for(app, request))
        with real_client(transport=transport, follow_redirects=False) as client:
            endpoint = Endpoint(BASE_URL + ENDPOINT_PATH, "Custom telemetry API")
            validator = ActiveValidator(ActiveConfig([endpoint.url], timeout=2, min_interval=0), client)
            validator.submit(endpoint, authorized=True)
            self.assertEqual(endpoint.status, Status.INCONCLUSIVE)  # 202 alone proves neither storage nor a finding.
            self.assertTrue(endpoint.test_event_id.startswith("telemetry-scanner-"))
            self.assertNotIn("Authorization", [k for k in client.headers.keys()])
            verifier_url = f"{BASE_URL}/events/{endpoint.test_event_id}"
            with ReadOnlyVerifier(f"{BASE_URL}/events/{{event_id}}", [verifier_url], client=client) as verifier:
                verifier.verify(endpoint)
            self.assertEqual(endpoint.status, Status.INGESTED)
            self.assertNotEqual(endpoint.status, Status.FINDING)


if __name__ == "__main__":
    unittest.main()
