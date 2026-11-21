import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from .models import Endpoint
from .scope import enforce_same_origin, ScopeError

URL_RE = re.compile(r"https?://[^\s\"'<>`]+", re.I)
PATH_RE = re.compile(r"(?:/v1/(?:traces|metrics|logs)|/api/(?:v\d+/)?(?:track|telemetry|events?)|/v\d+/(?:traces|metrics)|/api/trace|/ingest(?:/[^\s\"']*)?)", re.I)
KEYWORDS = ("applicationinsights", "application insights", "opentelemetry", "otlp", "jaeger", "zipkin", "prometheus", "telemetry", "instrumentationkey", "connectionstring")


def classify(text: str, url: str) -> tuple[str, list[str]] | None:
    low = text.lower() + " " + url.lower()
    evidence = []
    for key in KEYWORDS:
        if key in low: evidence.append(f"Matched configuration/service identifier: {key}")
    if "applicationinsights" in low or "instrumentationkey" in low or "ingestionendpoint" in low:
        return "Azure Application Insights", evidence or ["Azure Application Insights URL pattern"]
    if "opentelemetry" in low or "otlp" in low or "/v1/traces" in low or "/v1/metrics" in low:
        return "OpenTelemetry OTLP HTTP", evidence
    if "jaeger" in low: return "Jaeger", evidence
    if "zipkin" in low: return "Zipkin", evidence
    if "prometheus" in low or "remote_write" in low: return "Prometheus remote-write", evidence
    if any(k in low for k in ("telemetry", "instrumentation", "/ingest", "/track")):
        return "Custom telemetry API", evidence
    return None


def analyze_document(body: str, base_url: str, content_type: str = "") -> tuple[list[Endpoint], list[str]]:
    found: dict[str, Endpoint] = {}
    resources: list[str] = []
    candidates: list[tuple[str, str]] = []
    if "html" in content_type.lower() or "<html" in body[:500].lower():
        soup = BeautifulSoup(body, "html.parser")
        for tag in soup.find_all(["script", "link"]):
            src = tag.get("src") or tag.get("href")
            if src:
                try: resources.append(enforce_same_origin(base_url, urljoin(base_url, src)))
                except ScopeError: pass
        for tag in soup.find_all(True):
            serialized = str(tag.attrs)
            for raw in URL_RE.findall(serialized): candidates.append((raw.rstrip(".,);"), serialized))
        text = soup.get_text(" ", strip=True) + " " + body
    else:
        text = body
    absolute_spans = []
    for m in URL_RE.finditer(text):
        raw = m.group(0)
        candidate = raw.rstrip(".,);]")
        try:
            enforce_same_origin(base_url, candidate)
            candidates.append((candidate, text[max(0, m.start()-200):m.end()+200]))
        except ScopeError:
            absolute_spans.append((m.start(), m.end()))
    for m in PATH_RE.finditer(text):
        # Do not re-home the path portion of an explicitly external absolute URL.
        if any(start <= m.start() < end for start, end in absolute_spans):
            continue
        candidates.append((urljoin(base_url, m.group(0)), text[max(0, m.start()-200):m.end()+200]))
    for candidate, context in candidates:
        try: u = enforce_same_origin(base_url, urljoin(base_url, candidate))
        except ScopeError: continue
        result = classify(context, u)
        if not result: continue
        service, evidence = result
        item = found.setdefault(u, Endpoint(url=u, service=service, source=base_url,
            remediation="Restrict ingestion to trusted clients where supported; avoid embedding privileged credentials in browser code; monitor quotas and abuse."))
        for e in evidence:
            if e not in item.evidence: item.evidence.append(e)
    return list(found.values()), list(dict.fromkeys(resources))
