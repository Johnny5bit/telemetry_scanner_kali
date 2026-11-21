from datetime import datetime, timezone
import httpx
from .discovery import analyze_document
from .models import ScanReport
from .scope import normalize_http_url, redact_sensitive_url

MAX_RESOURCES = 25

def scan(target: str, progress=None, stop=None, status=None) -> ScanReport:
    """Perform bounded same-origin discovery.

    During crawling the final resource count is not knowable until all fetched
    documents have been inspected, so progress reports completed attempts with
    total=0 (unknown). A final count is sent once the queue is exhausted.
    ``progress(current, total)`` remains compatible with existing callbacks.
    """
    target = normalize_http_url(target)
    report = ScanReport(target=target, started_at=datetime.now(timezone.utc).isoformat())
    queue = [target]
    visited: set[str] = set()
    found = {}
    completed = 0
    headers = {"User-Agent": "TelemetryInjectionVulnerabilityScanner/1.0 (passive discovery)"}

    def emit_status(message):
        if status:
            status(message)

    def emit_progress(current, total=0):
        if progress:
            progress(current, total)

    emit_status("INITIALIZING SCANNER")
    emit_progress(0, 0)
    try:
        with httpx.Client(timeout=8, follow_redirects=False, headers=headers) as client:
            while queue and len(visited) < MAX_RESOURCES:
                if stop and stop():
                    break
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                emit_status("CONNECTING TO TARGET" if completed == 0 else "FETCHING RESOURCE")
                try:
                    response = client.get(url)
                    if response.status_code in (401, 403):
                        report.errors.append(f"{redact_sensitive_url(url)}: authentication required (HTTP {response.status_code})")
                    elif response.status_code >= 400:
                        report.errors.append(f"{redact_sensitive_url(url)}: HTTP {response.status_code}")
                    else:
                        mime = response.headers.get("content-type", "")
                        is_document = (
                            "html" in mime.lower()
                            or "javascript" in mime.lower()
                            or "ecmascript" in mime.lower()
                            or "<html" in response.text[:500].lower()
                        )
                        if is_document:
                            emit_status("ANALYZING ENDPOINTS")
                            items, resources = analyze_document(response.text, url, mime)
                            for item in items:
                                if item.url not in found:
                                    found[item.url] = item
                                else:
                                    found[item.url].evidence.extend(
                                        x for x in item.evidence if x not in found[item.url].evidence
                                    )
                            for resource in resources:
                                if resource not in visited and resource not in queue and len(visited) + len(queue) < MAX_RESOURCES:
                                    queue.append(resource)
                except (httpx.HTTPError, UnicodeError, ValueError) as exc:
                    report.errors.append(f"{redact_sensitive_url(url)}: {type(exc).__name__}")
                finally:
                    # Every attempted resource, including errors and unsupported
                    # content types, contributes exactly one completed work unit.
                    completed += 1
                    emit_progress(completed, 0)  # total stays unknown while discovery can expand.
                    emit_status("DISCOVERING RESOURCES")
    except Exception as exc:
        report.errors.append(f"Scan setup failed: {type(exc).__name__}")

    report.endpoints = list(found.values())
    report.finished_at = datetime.now(timezone.utc).isoformat()
    report.limitations = [
        "Passive browser-visible configuration discovery only.",
        "A discovered endpoint does not prove public write permission or vulnerability.",
        "At most 25 same-origin HTML/JavaScript resources are fetched; external origins are excluded.",
    ]
    # The crawl total is only final when discovery ends naturally. A cancelled
    # crawl may still have queued resources, so keep its total indeterminate.
    workload_known = not (stop and stop()) and not queue
    if workload_known:
        emit_status("DISCOVERY COMPLETE")
        emit_progress(completed, completed)
    return report
