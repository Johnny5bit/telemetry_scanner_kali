# Hyperject capability comparison

**Research basis:** Hyperject's public product page and vendored package README available from that site. The linked source tree was not retrievable in this review, so implementation claims about Hyperject internals are treated as documentation claims rather than source-verified facts. Hyperject advertises v0.8.0, 37 target modules, config-driven per-ecosystem plugins, CLI workflows (`run`, `list`, `init`, `validate`, `mock`, `detect`, `capture`, `export`), dry-run, allowlist middleware, request/response hooks, transcript formats, and ingest-log detection.

| Capability | Hyperject advertised | This scanner: inspected/verified | Gap / qualification |
|---|---|---|---|
| Passive same-origin discovery | Not the primary advertised workflow | Implemented; at most 25 HTML/JS resources | Discovery only sees reachable same-origin documents |
| Protocol coverage | 37 telemetry ecosystem modules | Six payload families: Azure App Insights, OTLP HTTP, Jaeger, Zipkin, Prometheus remote-write, custom JSON | Not parity with 37 ecosystems |
| JSON protocol payloads | Multiple protocol-specific formats | Generated for Azure, OTLP JSON, Jaeger, Zipkin, custom | Receiver-specific variations need controlled fixtures |
| OTLP protobuf | Advertised format coverage | Small OTLP trace protobuf wire encoder implemented | No official generated bindings in environment; semantic interoperability not independently validated against collector |
| Prometheus remote-write | Advertised module | WriteRequest protobuf + Snappy block encoding and required headers | No live or collector compatibility run; compression requires `python-snappy` |
| Dry-run | `run --dry-run` advertised | Payload CLI preview plus validator preview; local generation only | Does not preview credential-bearing request headers |
| Active safety | Allowlist and middleware advertised | Exact normalized URL allowlist, operator confirmation, no redirects, configurable timeout/delay, hard cap of 25 requests, stop still handled by GUI worker | Existing GUI has endpoint selection/active controls; no new per-technique test suite in GUI yet |
| Authentication checks | Module/config dependent | Existing validator classifies 401/403 as auth required; synthetic submissions otherwise inconclusive | No exhaustive missing/invalid credential matrix against services |
| Backend verification | `detect` reads ingest logs per page | Existing read-only verifier matches event IDs; local lab stores/inspects events | No generic backend query adapters, timestamp/attribute correlation is not comprehensive |
| Local mock | `mock` advertised | Loopback-only configurable auth and tenant boundary lab, JSON events, read-only inspection | Socket-based test is skipped when environment forbids bind; logic integration is mock-transport tested |
| Reports/transcripts | JSON/JSONL/HAR/pretty advertised | Existing JSON/HTML plus JSONL and sanitized HAR summary | HAR intentionally omits raw request/response payloads and credentials; not a wire capture |
| Capture/proxy | Capture/proxy support advertised | Not implemented | Deliberately out of scope for this increment |
| Detection/evasion grade payloads | Basic/bulk/large/covert advertised | Not implemented; no stealth, evasion or uncontrolled-volume behavior | Explicitly excluded by safe operating requirements |
| Test evidence for Hyperject claims | Public docs/product page only | No Hyperject source was available in the reviewed site | Do not treat advertised features as source-audited facts |

## Verified status

This project was inspected and tested locally with synthetic payload construction, HTTPX mock transports, and a localhost-lab handler adapter. No public target was contacted, no external scan was run, and no active injection was performed. A mock response or HTTP 200/202 remains insufficient to establish ingestion or a security finding.
