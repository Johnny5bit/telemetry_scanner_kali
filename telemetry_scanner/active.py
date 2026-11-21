"""Opt-in, one-event protocol submissions. Never invoked during discovery."""
import math
import time
from dataclasses import dataclass
import httpx
from .models import Endpoint, Status
from .scope import enforce_allowlist, normalize_http_url, ScopeError
from .payloads import generate

@dataclass
class ActiveConfig:
    allowlist: list[str]
    timeout: float = 5.0
    min_interval: float = 2.0
    max_requests: int = 25

    def __post_init__(self):
        if isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float)):
            raise ValueError("Active validation timeout must be a positive finite number.")
        if isinstance(self.min_interval, bool) or not isinstance(self.min_interval, (int, float)):
            raise ValueError("Active validation interval must be a finite non-negative number.")
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("Active validation timeout must be a positive finite number.")
        if not math.isfinite(self.min_interval) or self.min_interval < 0:
            raise ValueError("Active validation interval must be a finite non-negative number.")
        if isinstance(self.max_requests, bool) or not isinstance(self.max_requests, int) or not 1 <= self.max_requests <= 25:
            raise ValueError("Active validation request cap must be between 1 and 25.")
        if not isinstance(self.allowlist, (list, tuple)):
            raise ScopeError("Active validation requires an explicit endpoint allowlist.")
        normalized = []
        for item in self.allowlist:
            if not isinstance(item, str):
                raise ScopeError("Active validation allowlist entries must be URLs.")
            if item.strip():
                normalized.append(normalize_http_url(item))
        if not normalized:
            raise ScopeError("Active validation requires an explicit endpoint allowlist.")
        self.allowlist = list(dict.fromkeys(normalized))

class ActiveValidator:
    def __init__(self, config: ActiveConfig, client: httpx.Client | None = None):
        self.config = config
        self._owns_client = client is None
        self.client = client if client is not None else httpx.Client(timeout=config.timeout, follow_redirects=False)
        self._last = None
        self._request_count = 0

    @staticmethod
    def _protocol(endpoint: Endpoint) -> str:
        hint=(endpoint.service + " " + endpoint.url).lower()
        if "application insights" in hint or "appinsights" in hint: return "azure-application-insights"
        if "prometheus" in hint or "remote-write" in hint: return "prometheus-remote-write"
        if "zipkin" in hint: return "zipkin"
        if "jaeger" in hint: return "jaeger"
        if "otlp" in hint or "/v1/traces" in hint: return "otlp-http"
        return "custom-http-json"

    def preview(self, endpoint: Endpoint, authorized: bool = False) -> dict:
        """Build a local-only dry-run; still requires allowlist and operator confirmation."""
        if authorized is not True:
            raise ScopeError("Operator authorization confirmation is required.")
        enforce_allowlist(endpoint.url, self.config.allowlist)
        return generate(self._protocol(endpoint)).preview()

    def submit(self, endpoint: Endpoint, authorized: bool) -> Endpoint:
        if authorized is not True:
            raise ScopeError("Operator authorization confirmation is required.")
        url = enforce_allowlist(endpoint.url, self.config.allowlist)
        if self._request_count >= self.config.max_requests:
            raise ScopeError("Active validation request cap reached for this run.")
        if self._last is not None:
            delay = self.config.min_interval - (time.monotonic() - self._last)
            if delay > 0:
                time.sleep(delay)
        protocol=self._protocol(endpoint)
        payload=generate(protocol)
        event_id=payload.event_id
        headers={**payload.headers,"User-Agent":"TelemetryInjectionVulnerabilityScanner/1.0 (authorized synthetic validation)","X-Telemetry-Test-Id":event_id}
        endpoint.test_event_id = event_id
        endpoint.test_condition = f"One protocol-aware synthetic event ({protocol}); operator authorization asserted; exact allowlist; redirects disabled; max {self.config.max_requests} requests; SHA-256 {payload.sha256}."
        self._request_count += 1
        self._last = time.monotonic()
        try:
            response = self.client.post(url, content=payload.body, headers=headers, timeout=self.config.timeout)
            endpoint.evidence.append(f"Synthetic {protocol} request; payload bytes={len(payload.body)}; SHA-256={payload.sha256}; event ID={event_id}.")
            if response.status_code in (401, 403):
                endpoint.status = Status.AUTH_REQUIRED
                endpoint.auth_evidence = f"HTTP {response.status_code}; submission requires authentication or authorization."
            else:
                endpoint.status = Status.INCONCLUSIVE
                endpoint.auth_evidence = f"HTTP {response.status_code}; response alone does not prove ingestion or permission to submit."
                endpoint.limitations.append("No read-only backend verifier was configured; ingestion and authorization impact are unconfirmed.")
        except (httpx.HTTPError, ValueError) as exc:
            endpoint.auth_evidence = f"Request failed: {type(exc).__name__}"
            endpoint.status = Status.INCONCLUSIVE
        return endpoint

    def close(self):
        """Close only the HTTPX client created and owned by this validator."""
        if self._owns_client:
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
