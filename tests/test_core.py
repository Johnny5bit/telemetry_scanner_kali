"""Offline quality and safety tests; all HTTP traffic is mocked in memory."""
import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import httpx
from PySide6.QtCore import QPoint
from PySide6.QtWidgets import QApplication, QMessageBox, QFileDialog, QLabel, QScrollArea

from telemetry_scanner.active import ActiveConfig, ActiveValidator
from telemetry_scanner.discovery import analyze_document, classify
from telemetry_scanner.gui import MainWindow, Worker, make_assessment_item
from telemetry_scanner.models import Endpoint, ScanReport, Status
from telemetry_scanner.reports import export_html, export_json
from telemetry_scanner.scanner import MAX_RESOURCES, scan
from telemetry_scanner.scope import ScopeError, enforce_allowlist, enforce_same_origin, normalize_http_url, redact_sensitive_url
from telemetry_scanner.verification import ReadOnlyVerifier

REAL_HTTPX_CLIENT = httpx.Client
NOW = datetime.now(timezone.utc).isoformat()


def mocked_scan_client(handler):
    """Patch scanner's client factory with an in-memory HTTPX transport."""
    transport = httpx.MockTransport(handler)
    return patch(
        "telemetry_scanner.scanner.httpx.Client",
        side_effect=lambda **kwargs: REAL_HTTPX_CLIENT(transport=transport, **kwargs),
    )


def wait_until(predicate, timeout=3.0):
    app = QApplication.instance()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.005)
    app.processEvents()
    return predicate()


class ScopeTests(unittest.TestCase):
    def test_normalizes_scheme_host_path_and_discards_fragment(self):
        self.assertEqual(
            normalize_http_url(" HTTPS://APP.EXAMPLE/Path?q=1#section "),
            "https://app.example/Path?q=1",
        )
        self.assertEqual(normalize_http_url("http://app.example"), "http://app.example/")

    def test_rejects_invalid_or_ambiguous_urls(self):
        for value in (
            "", "ftp://app.example", "https:///missing-host", "https://user:secret@app.example/",
            "https://app.example:bad/path", "https://app.example:65536/", "https://app.example/a b",
            "https://app.example\\@evil.example/", "https://app.example/\nnext",
        ):
            with self.subTest(value=value), self.assertRaises(ScopeError):
                normalize_http_url(value)

    def test_same_origin_enforcement_checks_scheme_host_and_port(self):
        base = "https://app.example:8443/"
        self.assertEqual(enforce_same_origin(base, "https://app.example:8443/x"), "https://app.example:8443/x")
        for candidate in (
            "http://app.example:8443/x", "https://app.example/x", "https://sub.app.example:8443/x",
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ScopeError):
                enforce_same_origin(base, candidate)

    def test_redacts_common_secret_query_values(self):
        safe = redact_sensitive_url("https://app.example/ingest?region=west&api_key=top-secret&X-Amz-Signature=sig123")
        self.assertIn("region=west", safe)
        self.assertNotIn("top-secret", safe)
        self.assertNotIn("sig123", safe)
        self.assertIn("REDACTED", safe)

    def test_allowlist_is_exact_after_safe_normalization(self):
        allowed = "https://owned.example/v1/traces?tenant=blue"
        self.assertEqual(enforce_allowlist("https://OWNED.example/v1/traces?tenant=blue", [allowed]), allowed)
        for candidate in (
            "https://owned.example/v1/traces?tenant=red",
            "https://owned.example/v1/../v1/traces?tenant=blue",
            "https://owned.example:443/v1/traces?tenant=blue",
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ScopeError):
                enforce_allowlist(candidate, [allowed])
        with self.assertRaises(ScopeError):
            enforce_allowlist(allowed, [])
        with self.assertRaises(ScopeError):
            enforce_allowlist(allowed, None)


class DiscoveryTests(unittest.TestCase):
    def test_identifies_supported_services_and_evidence(self):
        examples = (
            ("instrumentationKey=abc ingestionEndpoint", "https://app.example/ingest", "Azure Application Insights"),
            ("OTLP exporter", "https://app.example/v1/traces", "OpenTelemetry OTLP HTTP"),
            ("jaeger collector", "https://app.example/api/traces", "Jaeger"),
            ("zipkin reporter", "https://app.example/api/v2/spans", "Zipkin"),
            ("prometheus remote_write", "https://app.example/api/write", "Prometheus remote-write"),
            ("custom telemetry client", "https://app.example/api/telemetry", "Custom telemetry API"),
        )
        for context, url, expected in examples:
            with self.subTest(service=expected):
                service, evidence = classify(context, url)
                self.assertEqual(service, expected)
                self.assertTrue(evidence)
                self.assertTrue(any(expected.split()[0].lower() in item.lower() or item.startswith("Matched") for item in evidence))

    def test_extracts_same_origin_script_and_endpoint_evidence(self):
        body = '<html><script src="/bundle.js"></script><script>const exporter="otlp"; const url="/v1/traces";</script></html>'
        endpoints, resources = analyze_document(body, "https://app.example/", "text/html")
        self.assertEqual(resources, ["https://app.example/bundle.js"])
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].url, "https://app.example/v1/traces")
        self.assertEqual(endpoints[0].service, "OpenTelemetry OTLP HTTP")
        self.assertEqual(endpoints[0].status, Status.DISCOVERED)
        self.assertTrue(endpoints[0].evidence)
        self.assertEqual(endpoints[0].source, "https://app.example/")

    def test_external_urls_are_not_rehomed_or_crawled(self):
        body = '<html><script src="https://cdn.example/app.js"></script><script>const e="https://collector.example/v1/traces"; const otlp=true;</script></html>'
        endpoints, resources = analyze_document(body, "https://app.example/", "text/html")
        self.assertEqual(endpoints, [])
        self.assertEqual(resources, [])

    def test_duplicate_endpoint_in_document_merges_evidence(self):
        body = 'const first="otlp"; const a="https://app.example/v1/traces"; const second="opentelemetry"; const b="https://app.example/v1/traces";'
        endpoints, _ = analyze_document(body, "https://app.example/bundle.js", "application/javascript")
        self.assertEqual(len(endpoints), 1)
        self.assertGreaterEqual(len(endpoints[0].evidence), 2)


class ScannerTests(unittest.TestCase):
    def test_scan_deduplicates_endpoints_across_documents_and_reports_progress(self):
        calls = []
        def handler(request):
            calls.append(str(request.url))
            if request.url.path == "/":
                content = '<html><script src="/bundle.js"></script><script>const otlp="otlp"; const endpoint="/v1/traces";</script></html>'
                return httpx.Response(200, headers={"content-type": "text/html"}, text=content)
            if request.url.path == "/bundle.js":
                return httpx.Response(200, headers={"content-type": "application/javascript"}, text='const endpoint="/v1/traces"; const otlp="opentelemetry";')
            return httpx.Response(404)
        progress = []
        with mocked_scan_client(handler):
            report = scan("https://app.example/", lambda current, total: progress.append((current, total)))
        self.assertEqual(calls, ["https://app.example/", "https://app.example/bundle.js"])
        self.assertEqual(len(report.endpoints), 1)
        self.assertEqual(report.endpoints[0].service, "OpenTelemetry OTLP HTTP")
        self.assertEqual(report.endpoints[0].url, "https://app.example/v1/traces")
        self.assertEqual(report.mode, "Discovery")
        self.assertTrue(report.started_at and report.finished_at)
        self.assertEqual(progress[0], (0, 0))
        self.assertEqual(progress[-1], (2, 2))
        self.assertEqual([current for current, _ in progress[1:-1]], [1, 2])
        self.assertTrue(all(total == 0 for _, total in progress[1:-1]))

    def test_scan_reports_unavailable_server_without_raising(self):
        def handler(request):
            raise httpx.ConnectError("synthetic unavailable host", request=request)
        with mocked_scan_client(handler):
            report = scan("https://app.example/")
        self.assertEqual(report.endpoints, [])
        self.assertTrue(report.errors)
        self.assertIn("ConnectError", report.errors[0])

    def test_scan_cancellation_stops_before_next_resource(self):
        calls = []
        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(200, headers={"content-type": "text/html"}, text='<html><script src="/one.js"></script></html>')
        checks = iter((False, True))
        progress = []
        with mocked_scan_client(handler):
            report = scan("https://app.example/", lambda a, b: progress.append((a, b)), lambda: next(checks, True))
        self.assertEqual(calls, ["https://app.example/"])
        self.assertEqual(progress, [(0, 0), (1, 0)])
        self.assertTrue(report.finished_at)

    def test_scan_fetches_no_more_than_25_same_origin_resources(self):
        calls = []
        def handler(request):
            calls.append(str(request.url))
            if request.url.path == "/":
                links = "".join(f'<script src="/r{i}.js"></script>' for i in range(40))
                return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<html>{links}</html>")
            return httpx.Response(200, headers={"content-type": "application/javascript"}, text="// no endpoints")
        with mocked_scan_client(handler):
            scan("https://app.example/")
        self.assertEqual(len(calls), MAX_RESOURCES)

    def test_non_success_http_response_is_recorded(self):
        with mocked_scan_client(lambda request: httpx.Response(503)):
            report = scan("https://app.example/")
        self.assertIn("HTTP 503", report.errors[0])


class ActiveValidationTests(unittest.TestCase):
    URL = "https://owned.example/otlp"

    def make_validator(self, status=202, *, handler=None, interval=0):
        requests = []
        def response_handler(request):
            requests.append(request)
            if handler:
                return handler(request)
            return httpx.Response(status)
        client = REAL_HTTPX_CLIENT(transport=httpx.MockTransport(response_handler))
        validator = ActiveValidator(ActiveConfig([self.URL], timeout=1, min_interval=interval), client)
        return validator, requests, client

    def test_empty_allowlist_and_missing_authorization_block_without_network(self):
        with self.assertRaises(ScopeError):
            ActiveConfig([])
        with self.assertRaises(ScopeError):
            ActiveConfig(["not-a-url"])
        validator, requests, client = self.make_validator()
        endpoint = Endpoint(self.URL, "OpenTelemetry OTLP HTTP")
        with self.assertRaises(ScopeError):
            validator.submit(endpoint, False)
        with self.assertRaises(ScopeError):
            validator.submit(endpoint, 1)
        self.assertEqual(requests, [])
        client.close()

    def test_non_allowlisted_endpoint_blocked_before_mock_post(self):
        validator, requests, client = self.make_validator()
        endpoint = Endpoint("https://owned.example/other", "Custom telemetry API")
        with self.assertRaises(ScopeError):
            validator.submit(endpoint, True)
        self.assertEqual(requests, [])
        client.close()

    def test_path_normalization_does_not_expand_allowlisted_scope(self):
        validator, requests, client = self.make_validator()
        endpoint = Endpoint("https://owned.example/a/../otlp", "OTLP")
        with self.assertRaises(ScopeError):
            validator.submit(endpoint, True)
        self.assertEqual(requests, [])
        client.close()

    def test_simulated_http_statuses_are_classified_safely(self):
        for code, expected in ((200, Status.INCONCLUSIVE), (202, Status.INCONCLUSIVE), (401, Status.AUTH_REQUIRED), (403, Status.AUTH_REQUIRED), (500, Status.INCONCLUSIVE)):
            with self.subTest(status=code):
                validator, requests, client = self.make_validator(code)
                endpoint = Endpoint(self.URL, "OpenTelemetry OTLP HTTP")
                validator.submit(endpoint, True)
                self.assertEqual(endpoint.status, expected)
                self.assertEqual(len(requests), 1)
                self.assertTrue(endpoint.test_event_id.startswith("telemetry-scanner-"))
                self.assertIn("synthetic event", endpoint.test_condition)
                if code in (200, 202):
                    self.assertIn("does not prove", endpoint.auth_evidence)
                client.close()

    def test_submission_contains_only_synthetic_event_and_redirects_are_disabled(self):
        validator, requests, client = self.make_validator(202)
        endpoint = Endpoint(self.URL, "OpenTelemetry OTLP HTTP")
        self.assertFalse(validator.client.follow_redirects)
        validator.submit(endpoint, True)
        request = requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.headers["x-telemetry-test-id"], endpoint.test_event_id)
        self.assertIn("authorized_scanner_validation", request.content.decode())
        self.assertNotIn("injection", request.content.decode().lower())
        client.close()

    def test_rate_limit_waits_for_configured_interval(self):
        validator, _, client = self.make_validator(202, interval=2.0)
        endpoint = Endpoint(self.URL, "OpenTelemetry OTLP HTTP")
        with patch("telemetry_scanner.active.time.monotonic", side_effect=[100.0, 100.5, 102.0]), patch("telemetry_scanner.active.time.sleep") as sleep:
            validator.submit(endpoint, True)
            validator.submit(Endpoint(self.URL, "OpenTelemetry OTLP HTTP"), True)
        sleep.assert_called_once_with(1.5)
        client.close()

    def test_owned_http_client_closes(self):
        validator = ActiveValidator(ActiveConfig([self.URL]))
        owned_client = validator.client
        validator.close()
        self.assertTrue(owned_client.is_closed)

    def test_timeout_and_connection_errors_are_inconclusive(self):
        def timeout(request):
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        validator, _, client = self.make_validator(handler=timeout)
        endpoint = Endpoint(self.URL, "OpenTelemetry OTLP HTTP")
        validator.submit(endpoint, True)
        self.assertEqual(endpoint.status, Status.INCONCLUSIVE)
        self.assertIn("ReadTimeout", endpoint.auth_evidence)
        client.close()

    def test_config_rejects_invalid_rate_and_timeout(self):
        for kwargs in ({"timeout": 0}, {"timeout": float("inf")}, {"timeout": "5"}, {"min_interval": -1}, {"min_interval": float("nan")}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ActiveConfig([self.URL], **kwargs)


class VerificationTests(unittest.TestCase):
    def test_matching_synthetic_event_confirms_ingestion(self):
        endpoint = Endpoint("https://owned.example/otlp", "OTLP")
        endpoint.test_event_id = "event-123"
        calls = []
        client = REAL_HTTPX_CLIENT(transport=httpx.MockTransport(lambda request: (calls.append(request) or httpx.Response(200, json={"event_id": "event-123"}))))
        verifier = ReadOnlyVerifier("https://owned.example/query/{event_id}", ["https://owned.example/query/event-123"], client=client)
        verifier.verify(endpoint)
        self.assertEqual(endpoint.status, Status.INGESTED)
        self.assertEqual(calls[0].method, "GET")
        client.close()

    def test_mismatched_event_id_does_not_confirm_ingestion(self):
        endpoint = Endpoint("https://owned.example/otlp", "OTLP")
        endpoint.test_event_id = "expected"
        client = REAL_HTTPX_CLIENT(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"event_id": "other"})))
        verifier = ReadOnlyVerifier("https://owned.example/query/{event_id}", ["https://owned.example/query/expected"], client=client)
        verifier.verify(endpoint)
        self.assertNotEqual(endpoint.status, Status.INGESTED)
        self.assertTrue(endpoint.limitations)
        client.close()

    def test_verifier_scope_and_no_event_id_are_enforced(self):
        with self.assertRaises(ValueError):
            ReadOnlyVerifier("https://owned.example/query", ["https://owned.example/query"])
        endpoint = Endpoint("https://owned.example/otlp", "OTLP")
        client = REAL_HTTPX_CLIENT(transport=httpx.MockTransport(lambda request: self.fail("no request expected")))
        verifier = ReadOnlyVerifier("https://owned.example/query/{event_id}", ["https://owned.example/query/other"], client=client)
        verifier.verify(endpoint)
        self.assertIn("no synthetic", endpoint.limitations[0])
        endpoint.test_event_id = "not-allowlisted"
        with self.assertRaises(ScopeError):
            verifier.verify(endpoint)
        client.close()

    def test_owned_verifier_client_closes(self):
        verifier = ReadOnlyVerifier("https://owned.example/query/{event_id}", ["https://owned.example/query/event-1"])
        owned_client = verifier.client
        verifier.close()
        self.assertTrue(owned_client.is_closed)

    def test_verifier_rejects_invalid_timeout_and_non_object_json_safely(self):
        with self.assertRaises(ValueError):
            ReadOnlyVerifier("https://owned.example/query/{event_id}", [], timeout=0)
        endpoint = Endpoint("https://owned.example/otlp", "OTLP")
        endpoint.test_event_id = "event-list"
        client = REAL_HTTPX_CLIENT(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=["not", "an", "object"])))
        verifier = ReadOnlyVerifier("https://owned.example/query/{event_id}", ["https://owned.example/query/event-list"], client=client)
        verifier.verify(endpoint)
        self.assertNotEqual(endpoint.status, Status.INGESTED)
        self.assertTrue(endpoint.limitations)
        client.close()

    def test_verifier_http_errors_are_inconclusive(self):
        endpoint = Endpoint("https://owned.example/otlp", "OTLP")
        endpoint.test_event_id = "event-1"
        client = REAL_HTTPX_CLIENT(transport=httpx.MockTransport(lambda request: httpx.Response(403)))
        verifier = ReadOnlyVerifier("https://owned.example/query/{event_id}", ["https://owned.example/query/event-1"], client=client)
        verifier.verify(endpoint)
        self.assertTrue(any("verification inconclusive" in item.lower() for item in endpoint.limitations))
        client.close()


class ReportTests(unittest.TestCase):
    def fixture_report(self):
        endpoint = Endpoint(
            "https://app.example/v1/traces", "OpenTelemetry OTLP HTTP",
            evidence=["Matched configuration: otlp"], source="https://app.example/app.js",
            auth_evidence="No credential evidence observed", remediation="Restrict ingestion.",
        )
        endpoint.test_event_id = "synthetic-test-123"
        endpoint.test_condition = "Synthetic mocked test data only"
        endpoint.limitations = ["HTTP 202 alone is not proof"]
        return ScanReport("https://app.example/", NOW, NOW, [endpoint], ["Synthetic fixture error"], "Discovery", ["No external scan"])

    def test_json_export_has_complete_report_and_is_parseable(self):
        report = self.fixture_report()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            export_json(report, str(path))
            data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["target"], report.target)
        self.assertEqual(data["endpoints"][0]["evidence"], report.endpoints[0].evidence)
        self.assertEqual(data["endpoints"][0]["test_event_id"], "synthetic-test-123")
        self.assertEqual(data["errors"], ["Synthetic fixture error"])
        self.assertIn("finished_at", data)

    def test_json_export_redacts_secret_query_values(self):
        report = self.fixture_report()
        report.target = "https://app.example/?token=target-secret"
        report.endpoints[0].url = "https://app.example/v1/traces?api_key=endpoint-secret"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "safe.json"
            export_json(report, str(path))
            content = path.read_text(encoding="utf-8")
        self.assertNotIn("target-secret", content)
        self.assertNotIn("endpoint-secret", content)
        self.assertIn("REDACTED", content)

    def test_html_report_redacts_secret_query_values(self):
        report = self.fixture_report()
        report.target = "https://app.example/?api_key=target-secret"
        report.endpoints[0].url = "https://app.example/v1/traces?token=endpoint-secret"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "safe.html"
            export_html(report, str(path))
            content = path.read_text(encoding="utf-8")
        self.assertNotIn("target-secret", content)
        self.assertNotIn("endpoint-secret", content)
        self.assertIn("REDACTED", content)

    def test_html_report_has_sections_and_escapes_untrusted_content(self):
        report = self.fixture_report()
        report.endpoints[0].evidence = ["<script>alert('synthetic')</script>"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            export_html(report, str(path))
            html = path.read_text(encoding="utf-8")
        self.assertIn("Telemetry Injection Vulnerability Scanner", html)
        self.assertIn("Evidence", html)
        self.assertIn("Limitations", html)
        self.assertIn("Remediation", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>alert", html)
        self.assertIn("Synthetic fixture error", html)


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setStyle("Fusion")

    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        if self.window.worker_thread is not None:
            self.window.stop_event.set()
            wait_until(lambda: self.window.worker_thread is None)
        self.window.close()
        self.app.processEvents()

    def test_main_window_initialization_and_controls(self):
        self.assertEqual(self.window.windowTitle(), "Telemetry Injection Vulnerability Scanner")
        self.assertEqual(self.window.target.text(), "")
        self.assertEqual(self.window.table.columnCount(), 5)
        self.assertFalse(self.window.stop_btn.isEnabled())
        self.assertTrue(self.window.scan_btn.isEnabled())
        self.assertEqual(self.window.export_btn.text(), "EXPORT  /  JSON")
        self.assertEqual(self.window.html_export_btn.text(), "EXPORT  /  HTML")
        self.assertEqual(self.window.credit_label.text(), "DESIGNED & ENHANCED BY Ph15h3r")
        self.assertIsNotNone(self.window.findChild(QScrollArea, "dashboardScroll"))
        self.assertIn("#050508", self.window.styleSheet())
        self.assertIn("#E11D8A", self.window.styleSheet())
        self.assertTrue(any("THREAT ANALYSIS MATRIX" in label.text() for label in self.window.findChildren(QLabel)))
        finding = make_assessment_item(Status.FINDING)
        potential = make_assessment_item(Status.POTENTIAL)
        self.assertEqual(finding.text(), "FINDING")
        self.assertEqual(finding.foreground().color().name(), "#ff5577")
        self.assertEqual(potential.text(), "REVIEW")
        self.assertEqual(potential.foreground().color().name(), "#f0abfc")

    def test_minimum_window_size_keeps_dashboard_scrollable_and_footer_visible(self):
        self.window.resize(1020, 740)
        self.window.show()
        self.app.processEvents()
        scroll = self.window.findChild(QScrollArea, "dashboardScroll")
        self.assertTrue(scroll.verticalScrollBar().maximum() > 0)
        self.assertTrue(self.window.credit_label.isVisible())
        self.assertTrue(self.window.target.isVisible())
        footer_y = self.window.credit_label.parentWidget().mapTo(self.window, QPoint(0, 0)).y()
        scroll_bottom = scroll.mapTo(self.window, QPoint(0, 0)).y() + scroll.height()
        self.assertGreaterEqual(footer_y, scroll_bottom)

    def test_scan_button_rejects_invalid_target_and_active_mode_requires_confirmation(self):
        with patch("telemetry_scanner.gui.QMessageBox.warning") as warning:
            self.window.target.setText("file:///etc/passwd")
            self.window.scan_btn.click()
            warning.assert_called_once()
            self.assertIsNone(self.window.worker_thread)
            self.window.target.setText("https://owned.example/")
            self.window.mode.setCurrentIndex(1)
            self.window.scan_btn.click()
            warning.assert_called()
            self.assertIsNone(self.window.worker_thread)

    def test_worker_progress_results_details_and_lifecycle(self):
        endpoint = Endpoint("https://owned.example/v1/traces", "OpenTelemetry OTLP HTTP", evidence=["synthetic evidence"], remediation="synthetic remediation")
        report = ScanReport("https://owned.example/", NOW, NOW, [endpoint])
        def fake_scan(target, progress, stop, status=None):
            if status:
                status("DISCOVERING RESOURCES")
            progress(7, 0)
            progress(7, 7)
            return report
        with patch("telemetry_scanner.gui.scan", side_effect=fake_scan):
            self.window.target.setText("https://owned.example/")
            self.window.scan_btn.click()
            self.assertFalse(self.window.scan_btn.isEnabled())
            self.assertTrue(self.window.stop_btn.isEnabled())
            self.assertTrue(wait_until(lambda: self.window.worker_thread is None))
        self.assertTrue(self.window.scan_btn.isEnabled())
        self.assertFalse(self.window.stop_btn.isEnabled())
        self.assertEqual(self.window.progress.value(), 100)
        self.assertEqual(self.window.progress_state.text(), "SCAN COMPLETE")
        self.assertEqual(self.window.progress_counts.text(), "RESOURCES: 7 / 7")
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 0).text(), "OBSERVED")
        self.assertEqual(self.window.metric_endpoints.text(), "01")
        self.assertEqual(self.window.metric_confirmed.text(), "00")
        self.window.table.selectRow(0)
        self.app.processEvents()
        self.assertIn("synthetic evidence", self.window.details.toPlainText())
        self.assertIn("synthetic remediation", self.window.details.toPlainText())

    def test_worker_progress_signal_updates_gui_while_scan_is_still_running(self):
        progress_sent = threading.Event()
        release_worker = threading.Event()
        def fake_scan(target, progress, stop, status=None):
            if status:
                status("DISCOVERING RESOURCES")
            progress(0, 0)
            progress(2, 0)
            progress_sent.set()
            release_worker.wait(2)
            progress(2, 2)
            return ScanReport(target, NOW, NOW)
        with patch("telemetry_scanner.gui.scan", side_effect=fake_scan):
            self.window.target.setText("https://owned.example/")
            self.window.scan_btn.click()
            self.assertTrue(wait_until(progress_sent.is_set))
            self.assertTrue(wait_until(lambda: "RESOURCES: 2 / DISCOVERING" == self.window.progress_counts.text()))
            self.assertEqual(self.window.progress.minimum(), 0)
            self.assertEqual(self.window.progress.maximum(), 0)  # truthful unknown-workload state
            self.assertTrue(self.window.elapsed_timer.isActive())
            release_worker.set()
            self.assertTrue(wait_until(lambda: self.window.worker_thread is None))
        self.assertEqual(self.window.progress.value(), 100)
        self.assertFalse(self.window.elapsed_timer.isActive())

    def test_stop_button_cancels_mock_worker_and_gui_remains_responsive(self):
        started = threading.Event()
        def fake_scan(target, progress, stop, status=None):
            started.set()
            progress(1, 0)
            while not stop():
                time.sleep(0.005)
            return ScanReport(target, NOW, NOW)
        heartbeat = []
        from PySide6.QtCore import QTimer
        heartbeat_timer = QTimer(self.window)
        heartbeat_timer.timeout.connect(lambda: heartbeat.append(True))
        heartbeat_timer.start(5)
        with patch("telemetry_scanner.gui.scan", side_effect=fake_scan):
            self.window.target.setText("https://owned.example/")
            self.window.scan_btn.click()
            self.assertTrue(wait_until(started.is_set))
            self.assertTrue(self.window.stop_btn.isEnabled())
            self.window.stop_btn.click()
            self.assertTrue(wait_until(lambda: self.window.worker_thread is None))
        heartbeat_timer.stop()
        self.assertTrue(heartbeat)
        self.assertIn("STOPPED", self.window.run_state.text())
        self.assertEqual(self.window.progress_state.text(), "SCAN CANCELLED")
        self.assertNotEqual(self.window.progress.value(), 100)
        self.assertTrue(self.window.scan_btn.isEnabled())

    def test_worker_failure_surfaces_report_and_restores_controls(self):
        with patch("telemetry_scanner.gui.scan", side_effect=RuntimeError("synthetic worker failure")):
            self.window.target.setText("https://owned.example/")
            self.window.scan_btn.click()
            self.assertTrue(wait_until(lambda: self.window.worker_thread is None))
        self.assertTrue(self.window.report.errors[0].startswith("Unexpected worker failure: RuntimeError"))
        self.assertTrue(self.window.scan_btn.isEnabled())

    def test_gui_export_buttons_write_json_and_html(self):
        self.window.report = ReportTests().fixture_report()
        with tempfile.TemporaryDirectory() as directory:
            json_path = str(Path(directory) / "gui.json")
            html_path = str(Path(directory) / "gui.html")
            with patch.object(QFileDialog, "getSaveFileName", return_value=(json_path, "JSON (*.json)")), patch.object(QMessageBox, "information"):
                self.window.export_btn.click()
            with patch.object(QFileDialog, "getSaveFileName", return_value=(html_path, "HTML (*.html)")), patch.object(QMessageBox, "information"):
                self.window.html_export_btn.click()
            self.assertTrue(Path(json_path).is_file())
            self.assertTrue(Path(html_path).is_file())

    def test_close_during_worker_requests_stop_and_waits_for_thread(self):
        self.window.show()
        started = threading.Event()
        def fake_scan(target, progress, stop, status=None):
            started.set()
            while not stop():
                time.sleep(0.005)
            return ScanReport(target, NOW, NOW)
        with patch("telemetry_scanner.gui.scan", side_effect=fake_scan):
            self.window.target.setText("https://owned.example/")
            self.window.scan_btn.click()
            self.assertTrue(wait_until(started.is_set))
            self.assertFalse(self.window.close())
            self.assertTrue(self.window.stop_event.is_set())
            self.assertTrue(wait_until(lambda: self.window.worker_thread is None))
            self.assertTrue(wait_until(lambda: not self.window.isVisible()))

    def test_export_errors_show_dialog(self):
        self.window.report = ReportTests().fixture_report()
        with patch("telemetry_scanner.gui.QFileDialog.getSaveFileName", return_value=("/root/no-permission/report.json", "JSON")), patch("telemetry_scanner.gui.export_json", side_effect=OSError("synthetic export failure")), patch.object(QMessageBox, "critical") as critical:
            self.window.export("json")
            critical.assert_called_once()

    def test_progress_uses_known_total_and_reserves_100_for_success(self):
        self.window._progress_finished = False
        self.window._set_progress(8, 19, "FETCHING RESOURCE", 8, 19)
        self.assertEqual(self.window.progress.value(), 42)
        self.assertEqual(self.window.progress_counts.text(), "RESOURCES: 8 / 19")
        self.assertEqual(self.window.work_counts.text(), "WORK UNITS: 8 / 19")
        self.assertLess(self.window.progress.value(), 100)

    def test_zero_findings_success_reaches_100_and_new_scan_resets(self):
        def fake_scan(target, progress, stop, status=None):
            progress(0, 0)
            progress(1, 0)
            progress(1, 1)
            return ScanReport(target, NOW, NOW, endpoints=[])
        with patch("telemetry_scanner.gui.scan", side_effect=fake_scan):
            self.window.target.setText("https://owned.example/")
            self.window.scan_btn.click()
            self.assertTrue(wait_until(lambda: self.window.worker_thread is None))
        self.assertEqual(self.window.progress.value(), 100)
        self.assertEqual(self.window.table.rowCount(), 0)
        self.assertEqual(self.window.metric_endpoints.text(), "00")
        with patch("telemetry_scanner.gui.scan", side_effect=fake_scan):
            self.window.scan_btn.click()
            self.assertEqual(self.window.progress.value(), 0)
            self.assertEqual(self.window.progress_counts.text(), "RESOURCES: 0 / DISCOVERING")
            self.assertTrue(wait_until(lambda: self.window.worker_thread is None))
        self.assertEqual(self.window.progress.value(), 100)

    def test_report_errors_do_not_reach_success_state(self):
        def fake_scan(target, progress, stop, status=None):
            progress(1, 0)
            progress(1, 1)
            report = ScanReport(target, NOW, NOW)
            report.errors.append("synthetic timeout")
            return report
        with patch("telemetry_scanner.gui.scan", side_effect=fake_scan):
            self.window.target.setText("https://owned.example/")
            self.window.scan_btn.click()
            self.assertTrue(wait_until(lambda: self.window.worker_thread is None))
        self.assertNotEqual(self.window.progress.value(), 100)
        self.assertEqual(self.window.progress_state.text(), "SCAN ERROR")
        self.assertIn("FAILED", self.window.run_state.text())

    def test_worker_ignores_progress_callbacks_after_completion(self):
        saved = {}
        def fake_scan(target, progress, stop, status=None):
            saved["callback"] = progress
            progress(1, 0)
            progress(1, 1)
            return ScanReport(target, NOW, NOW)
        with patch("telemetry_scanner.gui.scan", side_effect=fake_scan):
            worker = Worker("https://owned.example/", threading.Event())
            updates = []
            worker.progress.connect(lambda *args: updates.append(args))
            worker.run()
            before = len(updates)
            saved["callback"](99, 100)
        self.assertEqual(len(updates), before)

    def test_active_validation_timeout_is_reported_as_failed_work(self):
        allowed = "https://owned.example/approved"
        endpoint = Endpoint(allowed, "Custom telemetry API")
        report = ScanReport("https://owned.example/", NOW, NOW, [endpoint])
        def timeout(request):
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        client = REAL_HTTPX_CLIENT(transport=httpx.MockTransport(timeout), follow_redirects=False)
        with patch("telemetry_scanner.gui.scan", return_value=report), patch(
            "telemetry_scanner.active.httpx.Client", return_value=client
        ):
            worker = Worker(
                "https://owned.example/", threading.Event(), active=True,
                approved=[allowed], authorized=True,
            )
            emitted = []
            worker.done.connect(emitted.append)
            worker.run()
        self.assertEqual(endpoint.status, Status.INCONCLUSIVE)
        self.assertTrue(any("ReadTimeout" in error for error in emitted[0].errors))
        self.assertTrue(client.is_closed)

    def test_authorized_worker_skips_unlisted_endpoint(self):
        allowed = "https://owned.example/approved"
        endpoints = [Endpoint(allowed, "Custom telemetry API"), Endpoint("https://third.example/collector", "Custom telemetry API")]
        report = ScanReport("https://owned.example/", NOW, NOW, endpoints)
        requests = []
        client = REAL_HTTPX_CLIENT(transport=httpx.MockTransport(lambda request: (requests.append(request) or httpx.Response(202))))
        with patch("telemetry_scanner.gui.scan", return_value=report), patch("telemetry_scanner.active.httpx.Client", return_value=client):
            worker = Worker("https://owned.example/", threading.Event(), active=True, approved=[allowed], authorized=True)
            emitted = []
            worker.done.connect(emitted.append)
            worker.run()
        self.assertEqual(len(requests), 1)
        self.assertTrue(any("not explicitly allowlisted" in limitation for limitation in endpoints[1].limitations))
        self.assertEqual(endpoints[0].status, Status.INCONCLUSIVE)
        client.close()

    def test_active_worker_error_preserves_discovered_findings(self):
        endpoint = Endpoint("https://owned.example/approved", "Custom telemetry API")
        report = ScanReport("https://owned.example/", NOW, NOW, [endpoint])
        with patch("telemetry_scanner.gui.scan", return_value=report), patch("telemetry_scanner.gui.ActiveValidator.submit", side_effect=RuntimeError("synthetic active failure")):
            worker = Worker("https://owned.example/", threading.Event(), active=True, approved=[endpoint.url], authorized=True)
            emitted = []
            worker.done.connect(emitted.append)
            worker.run()
        self.assertEqual(len(emitted[0].endpoints), 1)
        self.assertEqual(emitted[0].endpoints[0].url, endpoint.url)
        self.assertTrue(emitted[0].errors)

    def test_worker_requires_authorization_confirmation_before_active_submit(self):
        allowed = "https://owned.example/approved"
        report = ScanReport("https://owned.example/", NOW, NOW, [Endpoint(allowed, "Custom telemetry API")])
        requests = []
        client = REAL_HTTPX_CLIENT(transport=httpx.MockTransport(lambda request: (requests.append(request) or httpx.Response(202))))
        with patch("telemetry_scanner.gui.scan", return_value=report), patch("telemetry_scanner.active.httpx.Client", return_value=client):
            worker = Worker("https://owned.example/", threading.Event(), active=True, approved=[allowed])
            emitted = []
            worker.done.connect(emitted.append)
            worker.run()
        self.assertEqual(requests, [])
        self.assertEqual(emitted[0].errors, [])
        self.assertTrue(any("authorization was not confirmed" in item for item in emitted[0].endpoints[0].limitations))
        client.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
