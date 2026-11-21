# PH15H3R Local Telemetry Test Lab

A deliberately vulnerable **loopback-only** telemetry collector for testing the existing scanner. The intentional weakness is narrow: `POST /api/telemetry` accepts a valid, harmless synthetic scanner event without authentication. It stores only the event ID and receipt time in memory. It does not execute input, save files, collect credentials, or forward data.

The server binds only to `127.0.0.1:8765`; the request handler also rejects non-loopback peer addresses. There is no configurable bind host. The application uses only Python's standard library. Its tests use the parent project's existing HTTPX dependency and in-memory transports.

## Start

In a terminal:

```bash
cd ~/telemetry_scanner_kali/ph15h3r_test_lab
source ../.venv/bin/activate
python app.py
```

Expected startup line:

```text
PH15H3R Local Telemetry Lab listening at http://127.0.0.1:8765/
```

The lab exits when you press `Ctrl+C`.

## Confirm it is listening

Use a second terminal:

```bash
curl -i http://127.0.0.1:8765/health
curl -i http://127.0.0.1:8765/endpoints
```

The health route returns JSON with `status: ok`; the endpoint listing identifies the unauthenticated synthetic ingestion route. The homepage at `http://127.0.0.1:8765/` includes a scanner-discoverable `/api/telemetry` route.

## Passive discovery

1. Keep the lab running.
2. Start the scanner from another terminal:

   ```bash
   cd ~/telemetry_scanner_kali
   source .venv/bin/activate
   python -m telemetry_scanner
   ```

3. Set the target URL to:

   ```text
   http://127.0.0.1:8765/
   ```

4. Leave the scan mode at passive discovery and click **START SCAN**.

The scanner should list this discovered endpoint:

```text
http://127.0.0.1:8765/api/telemetry
```

Discovery means the page exposed a telemetry-like endpoint. It is not itself a vulnerability verdict.

## Authorized active validation

Only continue if you intend to test this local lab:

1. Select **ACTIVE VALIDATION / AUTHORIZED ONLY**.
2. Add this exact URL to the endpoint allowlist:

   ```text
   http://127.0.0.1:8765/api/telemetry
   ```

3. Check the authorization confirmation box and click **START SCAN**.

The scanner sends one protocol-compatible custom JSON synthetic event to the discovered, allowlisted endpoint. The lab validates the synthetic event name, ID, timestamp, and marker; it does not require an Authorization header. The scanner's event identifier starts with `telemetry-scanner-`.

The scanner treats the lab's HTTP 202 response as **Inconclusive**, because acceptance alone is not proof that the event was stored. The active result details include the event ID and response status.

## Verify event storage

The lab has a read-only, ID-specific verification route:

```text
http://127.0.0.1:8765/events/<event-id>
```

Copy the event ID from the scanner's selected endpoint details or exported JSON, then run:

```bash
cd ~/telemetry_scanner_kali/ph15h3r_test_lab
source ../.venv/bin/activate
python verify_event.py telemetry-scanner-0123456789abcdef0123456789abcdef
```

Replace the sample ID with the actual ID. The helper uses the scanner's existing `ReadOnlyVerifier` and exact URL allowlist. It prints **Confirmed Ingestion** only if the read-only route returns the matching ID. You can also inspect synthetic IDs directly:

```bash
curl -i http://127.0.0.1:8765/events
curl -i http://127.0.0.1:8765/events/telemetry-scanner-0123456789abcdef0123456789abcdef
```

The scanner GUI does not invoke `ReadOnlyVerifier`; verification through the helper does not update a report already shown in the GUI. The scanner also has no production code that assigns `Confirmed Security Finding`, severity, or confidence. Therefore this lab can demonstrate **discovery**, **unauthenticated synthetic acceptance**, and **confirmed storage** through the read-only verifier, but the existing scanner cannot produce a confirmed vulnerability finding from those facts. No fake finding is generated.

## Export reports

After the GUI scan completes, use its JSON and HTML export controls. These reports capture the scanner's own result: the discovered endpoint, active test event ID, and HTTP response evidence. The active result will remain Inconclusive until a verifier is run; the helper prints ingestion verification separately and does not mutate the GUI's in-memory report.

## Routes

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/` | Lab homepage; exposes the telemetry route to passive discovery |
| `GET` | `/endpoints` | Endpoint listing and auth-test description |
| `GET` | `/health` | Health and in-memory event count |
| `POST` | `/api/telemetry` | Intentionally unauthenticated, synthetic-only ingestion |
| `GET` | `/events` | Read-only list of stored synthetic event IDs |
| `GET` | `/events/{event_id}` | Read-only event-ID verification for `ReadOnlyVerifier` |

Invalid JSON, missing fields, malformed IDs, wrong content types, non-synthetic events, and oversized requests are rejected. Events are kept in memory and disappear when the process exits.

## Tests

```bash
cd ~/telemetry_scanner_kali/ph15h3r_test_lab
../.venv/bin/python -m unittest discover -s tests -v
```

The test suite includes endpoint discovery, unauthenticated synthetic acceptance, exact event acknowledgement, verifier matching, invalid requests, loopback policy, and no-forwarding checks. A real listening-socket bind test is skipped if the execution sandbox denies local sockets; the routing and scanner integration tests use an in-process transport and make no network requests.

## Safety boundary

Use only `http://127.0.0.1:8765/` as the scanner target. Do not change the lab bind address. The scanner still requires its active authorization checkbox and exact endpoint allowlist. The lab does not contact or forward to any other host.
