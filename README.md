# Telemetry Injection Vulnerability Scanner

**Created and maintained by Ph15h3r.**

A Python desktop tool for discovering telemetry ingestion endpoints exposed in an application's same-origin HTML and JavaScript resources. It also includes optional, explicitly authorized synthetic validation and report export. Discovery is evidence of a configured endpoint; it is not, by itself, evidence of a vulnerability.

## Table of contents

- [Overview](#overview)
- [Implemented features and limitations](#implemented-features-and-limitations)
- [Requirements](#requirements)
- [Installation](#installation)
- [Launch the GUI](#launch-the-gui)
- [Use the scanner](#use-the-scanner)
- [Local test labs](#local-test-labs)
- [Payload previews](#payload-previews)
- [Automated tests](#automated-tests)
- [Safety and responsible use](#safety-and-responsible-use)
- [Troubleshooting](#troubleshooting)

## Overview

Telemetry services collect events such as traces, metrics, and application activity. If an application exposes an ingestion URL or configuration in its browser-delivered files, that endpoint may deserve review. Whether it accepts data, requires authentication, or creates a security impact depends on the service and its configuration.

This scanner passively inspects reachable HTML and JavaScript resources from the target's origin and reports telemetry-like endpoint evidence. In its optional active mode, it can send a low-volume synthetic event to a discovered endpoint only when the operator confirms authorization and that exact endpoint is on the allowlist. The scanner does not treat a successful HTTP response as proof of ingestion or as a vulnerability.

## Implemented features and limitations

### Implemented

- **Passive discovery:** Fetches and analyzes up to 25 same-origin HTML and JavaScript resources. External origins and redirects are not followed. Endpoint candidates are deduplicated and evidence is retained.
- **Service identification:** Recognizes Azure Application Insights, OpenTelemetry OTLP HTTP, Jaeger, Zipkin, Prometheus remote-write, and custom telemetry API patterns in reachable content.
- **Optional active validation:** Requires the GUI authorization checkbox and an explicit endpoint allowlist. Only discovered endpoints that exactly match the normalized allowlist are submitted. The GUI uses a 5-second request timeout, a 2-second minimum interval, no redirects, and an active request cap of 25 per run. Active requests contain generated synthetic telemetry.
- **Progress and cancellation:** Shows the current phase, elapsed time, completed resources and work units. The progress bar stays indeterminate while the crawl's total workload can still grow, then becomes determinate. It reaches 100% only on a successful completion. Errors and cancellation are shown as separate outcomes. Stop requests are checked between resources and active submissions; an in-flight HTTP request can continue until it returns or times out.
- **Evidence and reports:** The GUI displays endpoint status, service, authentication evidence, discovery evidence, test conditions, limitations, and remediation notes. Reports can be exported as JSON, HTML, JSONL, or a sanitized HAR summary.
- **Payload generation:** Reusable synthetic payload generators are available for Azure Application Insights, OTLP HTTP JSON and protobuf, Jaeger, Zipkin, Prometheus remote-write, and custom JSON. The CLI can show a local payload preview; generating a preview does not send a request.
- **Read-only ingestion verifier module:** `ReadOnlyVerifier` can query an operator-configured allowlisted URL and confirm ingestion only when it finds the matching unique event ID. The GUI does not currently invoke this verifier automatically.

### Important limitations

- A discovered endpoint is **not** automatically a finding. The scanner does not set a severity or confidence score.
- The current GUI/worker implements `Discovered`, `Authentication Required`, and `Inconclusive` outcomes for its scan flow. The model also defines `Potential Exposure`, `Confirmed Ingestion`, and `Confirmed Security Finding` labels, but the GUI scan flow does not currently generate `Potential Exposure` or `Confirmed Security Finding`. A matching read-only verifier can set `Confirmed Ingestion`, but it is not wired into GUI scan/report generation.
- HTTP 200 or 202 alone remains inconclusive. The application does not determine unauthorized impact merely from public telemetry acceptance.
- Discovery analyzes content delivered in HTML/JavaScript responses; it does not run a browser or execute page JavaScript.
- The project does not implement full Hyperject parity. See [the capability comparison](docs/HYPERJECT_COMPARISON.md) for verified scope and gaps.
- Payload generation and mock fixtures do not prove interoperability with every real telemetry backend. Use only a controlled, authorized test environment for validation.

## Requirements

- Kali Linux or another Linux desktop environment.
- Python **3.11 or newer** (`StrEnum` is used by the application models).
- Python packages listed in `requirements.txt`:
  - PySide6
  - HTTPX
  - Beautiful Soup 4
  - python-snappy
- A graphical desktop session to show the GUI. Headless test runs use Qt's offscreen platform plugin.

The local lab's `app.py` uses the Python standard library. The lab integration tests use the project's installed HTTPX and scanner packages.

## Installation

From a terminal, enter the project and create a virtual environment only if one does not already exist. These commands preserve an existing `.venv`:

```bash
cd ~/telemetry_scanner_kali
python3 --version
if [ ! -x .venv/bin/python ]; then python3 -m venv .venv; fi
. .venv/bin/activate
python -m pip install -r requirements.txt
```

If virtual environment creation reports that `venv` is unavailable, install Kali's `python3-venv` package using the system package manager, then repeat the creation command. Do not remove a working environment to resolve an ordinary package issue.

## Launch the GUI

From the project root:

```bash
cd ~/telemetry_scanner_kali
.venv/bin/python -m telemetry_scanner
```

This starts the PySide6 graphical interface. A visible Linux desktop session is required for an on-screen window.

The auxiliary CLI has payload-preview and local-lab commands; it does **not** provide a scan command:

```bash
.venv/bin/python -m telemetry_scanner.cli --help
```

## Use the scanner

### Passive discovery

1. Launch the GUI with the command above.
2. Enter the HTTP or HTTPS URL of an application you own or are authorized to assess.
3. Leave **DISCOVERY / PASSIVE** selected.
4. Click **INITIALIZE SCAN**.
5. Review discovered endpoints in the results table and select a row to inspect its evidence and limitations.

The scanner fetches only same-origin HTML/JavaScript resources, up to the 25-resource limit. It does not follow redirects or fetch a third-party endpoint simply because a script mentions it. The progress display reports resource counts while the crawl's final workload is unknown.

### Authorized active validation

Active validation is opt-in and should only be used against systems you own or have explicit permission to test.

1. Select **ACTIVE VALIDATION / AUTHORIZED ONLY**.
2. Enter the exact discovered endpoint URL(s) to be tested in the allowlist field. Separate multiple URLs with commas.
3. Check **I OWN OR AM EXPLICITLY AUTHORIZED TO TEST EVERY ENDPOINT LISTED ABOVE**.
4. Click **INITIALIZE SCAN**.

The scanner first performs its same-origin discovery, then submits one synthetic event to each discovered endpoint that exactly matches the normalized allowlist. Endpoints not on the allowlist are skipped. Keep the allowlist narrow and include only endpoints within your authorized scope.

A 401 or 403 response is classified as **Authentication Required**. Other HTTP responses, including 200 and 202, are **Inconclusive** unless matching-event evidence is obtained through the separate read-only verifier. A timeout or connection failure is reported as a scan error/partial result; it is not a successful scan completion.

### Stop and export

- Click **ABORT / STOP** to request cancellation. The worker checks between requests; an in-flight request may need to finish or time out before the GUI can show the cancelled state.
- After a result is available, use the footer controls to export **JSON**, **HTML**, **JSONL**, or **HAR**.
- The HAR export is a sanitized summary, not a full network capture. Sensitive URL values and report fields are redacted according to the report sanitizer.

## Local test labs

This project contains two separate localhost test collectors. Neither forwards telemetry to an external service.

### Dedicated PH15H3R lab (port 8765)

The dedicated lab is at `ph15h3r_test_lab/app.py`. It binds exclusively to `127.0.0.1:8765`, accepts the scanner's harmless synthetic event without authentication for controlled testing, and stores event IDs in memory.

Start it in a terminal:

```bash
cd ~/telemetry_scanner_kali/ph15h3r_test_lab
source ../.venv/bin/activate
python app.py
```

Use this target in the scanner:

```text
http://127.0.0.1:8765/
```

For authorized active validation, the exact allowlist entry is:

```text
http://127.0.0.1:8765/api/telemetry
```

In a second terminal, check the health and endpoint-listing routes:

```bash
curl -i http://127.0.0.1:8765/health
curl -i http://127.0.0.1:8765/endpoints
```

The lab's homepage exposes `/api/telemetry` for passive discovery. Active submission normally receives HTTP 202, which the scanner correctly treats as inconclusive. The lab's read-only verifier helper can separately check whether the event ID was stored:

Use the event ID shown in the scanner result or report; for example:

```bash
cd ~/telemetry_scanner_kali/ph15h3r_test_lab
source ../.venv/bin/activate
python verify_event.py telemetry-scanner-0123456789abcdef0123456789abcdef
```

The helper checks `GET /events/{event_id}` against the exact localhost URL allowlist. Its ingestion confirmation does not update the GUI's current report or establish a confirmed security finding. Press **Ctrl+C** in the lab terminal to stop it. More details are in [the lab README](ph15h3r_test_lab/README.md).

### CLI mock collector

The CLI also starts `telemetry_scanner.lab.LocalTelemetryLab`, which binds to loopback and can be configured with an optional bearer token and simulated tenant boundary. Its default port is 8080; port 0 selects an available local port.

```bash
cd ~/telemetry_scanner_kali
.venv/bin/python -m telemetry_scanner.cli lab --port 8080 --token local-test-token
```

This mock collector accepts JSON requests on `POST /ingest`, `POST /v1/traces`, `POST /api/v2/spans`, `POST /api/traces`, and `POST /v1/metrics`; `GET /events` provides read-only inspection. It is a separate fixture from the dedicated port-8765 PH15H3R lab. Stop it with **Ctrl+C**.

## Payload previews

Payload generation is local and does not contact a target. For example:

```bash
cd ~/telemetry_scanner_kali
.venv/bin/python -m telemetry_scanner.cli payload otlp-http
.venv/bin/python -m telemetry_scanner.cli payload otlp-http --max-bytes 4096
```

Replace `otlp-http` with one of the protocol choices printed by:

```bash
.venv/bin/python -m telemetry_scanner.cli payload --help
```

## Automated tests

Run the project's suite from the project root:

```bash
cd ~/telemetry_scanner_kali
QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest discover -s tests -v
```

The suite covers URL and scope rules, passive discovery and resource limits, duplicate handling, mocked HTTP errors/timeouts, progress and GUI worker behavior, cancellation, active-validation authorization and allowlisting, synthetic payloads, read-only verification, report generation/redaction, and the CLI mock laboratory. The dedicated port-8765 lab has its own tests:

```bash
.venv/bin/python -m unittest discover -s ph15h3r_test_lab/tests -v
```

Tests rely on synthetic data and mocked transports. Tests that require opening a real localhost listening socket may be skipped in restricted environments. Passing tests are useful regression evidence, not proof that every real-world server, GUI environment, or telemetry backend behaves identically.

## Safety and responsible use

- Test only systems you own or for which you have explicit authorization.
- Keep passive discovery within the intended application origin. The scanner enforces same-origin fetching and a 25-resource cap.
- Active validation requires both explicit operator confirmation and an exact endpoint allowlist. Never add third-party endpoints merely because they appear in application code.
- Active requests are bounded synthetic events with redirects disabled and a request cap. Do not use this project for uncontrolled traffic, stealth, or testing outside the approved scope.
- Prefer the included loopback labs for development and demonstrations. Keep the dedicated lab bound to `127.0.0.1`.
- Treat discovered configuration and HTTP acceptance as evidence to investigate, not proof of a vulnerability.

## Troubleshooting

### `python3 -m venv .venv` fails

Check the Python version and install the Linux distribution's `python3-venv` package if the module is missing. Keep an existing working `.venv`; do not delete it as a first troubleshooting step.

### Package import or installation errors

Activate the project environment and install the declared requirements:

```bash
cd ~/telemetry_scanner_kali
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Confirm the interpreter and core GUI/network packages:

```bash
.venv/bin/python --version
.venv/bin/python -c "from PySide6 import QtCore, QtGui, QtWidgets; import httpx, bs4, snappy; print('imports ok')"
```

If `python-snappy` fails to install, read the package/build error and satisfy Kali's documented build prerequisites before retrying; do not remove the virtual environment.

### GUI does not appear

Run the launch command from a graphical desktop session. A headless shell or SSH session without display forwarding cannot show the window. `QT_QPA_PLATFORM=offscreen` is for tests and is not a way to display the GUI.

### Lab port is already in use

The dedicated PH15H3R lab always uses port 8765. Stop the process already using that port before starting it. The CLI mock collector accepts another port with `--port`, and port `0` asks the operating system for an available local port.

### Scan is slow or appears to pause

The crawler's HTTP timeout is 8 seconds per resource and it processes requests sequentially, up to 25 same-origin resources. During discovery the final workload is unknown, so the bar is indeterminate while the completed-resource counter and elapsed time continue to show actual state. A network request may remain in flight until its response or timeout; Stop does not forcibly interrupt an in-flight HTTPX request. Review any HTTP/connection errors in the findings/evidence area.

### No endpoint appears

Discovery only analyzes HTML/JavaScript returned by the target and same-origin resources it can reach. It does not execute page scripts or observe runtime browser traffic. Confirm the target URL is valid and that its delivered content contains a recognizable telemetry URL, path, or service identifier. An empty discovery result is not proof that the application has no telemetry collector.

### Active validation is blocked or inconclusive

Check that the active mode is selected, the authorization box is checked, and every intended endpoint is entered exactly in the allowlist. Only discovered endpoints matching that allowlist are tested. A 200/202 response is intentionally inconclusive without a matching event from a configured read-only verification source.
