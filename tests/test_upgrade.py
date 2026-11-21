import json
import tempfile
import unittest
from pathlib import Path
import httpx
from telemetry_scanner.payloads import generate, GENERATORS
from telemetry_scanner.lab import LocalTelemetryLab
from telemetry_scanner.models import Endpoint, ScanReport
from telemetry_scanner.active import ActiveConfig, ActiveValidator
from telemetry_scanner.scope import ScopeError
from telemetry_scanner.reports import export_jsonl, export_har, sanitize

class PayloadGeneratorTests(unittest.TestCase):
    def test_all_protocol_generators_are_unique_and_size_bounded(self):
        for protocol in GENERATORS:
            with self.subTest(protocol=protocol):
                a=generate(protocol); b=generate(protocol)
                self.assertNotEqual(a.event_id,b.event_id)
                self.assertLessEqual(len(a.body),65536)
                self.assertTrue(a.sha256)
                self.assertIn("Content-Type",a.headers)
                with self.assertRaises(ValueError): generate(protocol,max_bytes=1)
    def test_otlp_json_schema_and_binary_encoding_headers(self):
        payload=generate("otlp-http",encoding="json")
        body=json.loads(payload.body)
        span=body["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        self.assertEqual(span["attributes"][0]["value"]["stringValue"],payload.event_id)
        self.assertEqual(payload.headers["Content-Type"],"application/json")
        binary=generate("otlp-http",encoding="protobuf")
        self.assertEqual(binary.headers["Content-Type"],"application/x-protobuf")
        self.assertTrue(binary.body)
    def test_zipkin_jaeger_azure_custom_shapes(self):
        self.assertEqual(json.loads(generate("zipkin").body)[0]["name"],"authorized_scanner_validation")
        self.assertIn("data",json.loads(generate("jaeger").body))
        self.assertEqual(json.loads(generate("azure-application-insights").body)["name"],"Microsoft.ApplicationInsights.Event")
        self.assertIn("event_id",json.loads(generate("custom-http-json").body))
    def test_prometheus_headers_and_snappy_roundtrip(self):
        p=generate("prometheus-remote-write")
        import snappy
        self.assertEqual(p.headers["Content-Encoding"],"snappy")
        self.assertTrue(snappy.decompress(p.body))

class AuthorizedActiveTests(unittest.TestCase):
    def test_dry_run_is_local_and_authorization_scoped(self):
        endpoint=Endpoint("https://owned.invalid/v1/traces","OpenTelemetry OTLP HTTP")
        validator=ActiveValidator(ActiveConfig([endpoint.url]))
        with self.assertRaises(ScopeError): validator.preview(endpoint,False)
        with self.assertRaises(ScopeError): validator.preview(Endpoint("https://other.invalid/","OTLP"),True)
        preview=validator.preview(endpoint,True)
        self.assertIn("event_id",preview)
        validator.close()
    def test_request_cap_checked_before_request(self):
        calls=[]
        client=httpx.Client(transport=httpx.MockTransport(lambda r:(calls.append(r) or httpx.Response(202))),follow_redirects=False)
        url="https://owned.invalid/v1/traces"
        validator=ActiveValidator(ActiveConfig([url],min_interval=0,max_requests=1),client)
        validator.submit(Endpoint(url,"OTLP"),True)
        with self.assertRaises(ScopeError): validator.submit(Endpoint(url,"OTLP"),True)
        self.assertEqual(len(calls),1); client.close()

class LocalLabTests(unittest.TestCase):
    def test_auth_boundary_ingestion_and_read_only_inspection(self):
        lab=LocalTelemetryLab(token="lab-secret",tenant="a")
        def transport(request):
            status,data=lab.handle_request(request.method,request.url.path,dict(request.headers),request.content)
            return httpx.Response(status,json=data,request=request)
        with httpx.Client(transport=httpx.MockTransport(transport)) as client:
            noauth=client.post("http://lab.invalid/ingest",json={"event_id":"synthetic-1"})
            self.assertEqual(noauth.status_code,401)
            cross=client.post("http://lab.invalid/ingest",headers={"Authorization":"Bearer lab-secret","X-Test-Tenant":"b"},json={"event_id":"synthetic-2"})
            self.assertEqual(cross.status_code,403)
            accepted=client.post("http://lab.invalid/ingest",headers={"Authorization":"Bearer lab-secret"},json={"event_id":"synthetic-3"})
            self.assertEqual(accepted.status_code,202)
            events=client.get("http://lab.invalid/events").json()["events"]
            self.assertEqual([e["payload"]["event_id"] for e in events],["synthetic-3"])
    def test_duplicate_event_policy_and_configured_error(self):
        lab=LocalTelemetryLab(duplicate_mode="deduplicate")
        def transport(request):
            status,data=lab.handle_request(request.method,request.url.path,dict(request.headers),request.content)
            return httpx.Response(status,json=data,request=request)
        with httpx.Client(transport=httpx.MockTransport(transport)) as client:
            event={"event_id":"duplicate-synthetic"}
            self.assertFalse(client.post("http://lab.invalid/ingest",json=event).json()["duplicate"])
            second=client.post("http://lab.invalid/ingest",json=event).json()
            self.assertTrue(second["duplicate"]); self.assertFalse(second["stored"])
            self.assertEqual(len(client.get("http://lab.invalid/events").json()["events"]),1)
        self.assertEqual(LocalTelemetryLab(forced_status=503).handle_request("POST","/ingest",{},b'{"event_id":"x"}')[0],503)
    def test_loopback_only_address(self):
        lab=LocalTelemetryLab()
        try:
            lab.start()
        except PermissionError:
            self.skipTest("Sandbox prevents opening localhost listening sockets")
        try: self.assertTrue(lab.base_url.startswith("http://127.0.0.1:"))
        finally: lab.stop()

class ExtendedReportsTests(unittest.TestCase):
    def test_jsonl_and_har_valid_and_sensitive_fields_redacted(self):
        report=ScanReport("https://owned.invalid/?token=secret","now",endpoints=[Endpoint("https://owned.invalid/?api_key=secret","OTLP",test_event_id="hidden-event")])
        with tempfile.TemporaryDirectory() as d:
            j=Path(d)/"r.jsonl"; h=Path(d)/"r.har"
            export_jsonl(report,str(j)); export_har(report,str(h))
            rows=[json.loads(line) for line in j.read_text().splitlines()]
            self.assertGreaterEqual(len(rows),2)
            har=json.loads(h.read_text()); self.assertEqual(har["log"]["version"],"1.2")
            full=j.read_text()+h.read_text()
            self.assertNotIn("secret",full); self.assertIn("hidden-event",j.read_text()); self.assertIn("hidden-event",h.read_text())
    def test_sensitive_json_fields_redacted(self):
        self.assertEqual(sanitize({"authorization":"Bearer abc"})["authorization"],"[REDACTED]")

if __name__=="__main__": unittest.main()
