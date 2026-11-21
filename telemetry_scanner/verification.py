"""Read-only ingestion verification against an operator-owned backend query API."""
import math
import httpx
from .models import Endpoint, Status
from .scope import enforce_allowlist

class ReadOnlyVerifier:
    def __init__(self, query_url_template: str, allowlist: list[str], bearer_token: str = "", timeout: float = 5.0, client: httpx.Client | None = None):
        if "{event_id}" not in query_url_template:
            raise ValueError("Verifier URL must include the literal {event_id} placeholder.")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Verifier timeout must be a positive finite number.")
        self.template, self.allowlist, self.token, self.timeout = query_url_template, allowlist, bearer_token, timeout
        self._owns_client = client is None
        self.client = client if client is not None else httpx.Client(timeout=timeout, follow_redirects=False)

    def verify(self, endpoint: Endpoint) -> Endpoint:
        if not endpoint.test_event_id:
            endpoint.limitations.append("Verification skipped: no synthetic test event was submitted.")
            return endpoint
        url = self.template.replace("{event_id}", endpoint.test_event_id)
        url = enforce_allowlist(url, self.allowlist)
        headers = {"Accept": "application/json"}
        if self.token: headers["Authorization"] = "Bearer " + self.token
        try:
            response = self.client.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Verifier response is not a JSON object.")
            observed = data.get("event_id") or data.get("test_event_id")
            if observed == endpoint.test_event_id:
                endpoint.status = Status.INGESTED
                endpoint.auth_evidence += " Read-only backend query found the matching unique event ID."
            else:
                endpoint.limitations.append("Verifier response did not contain the matching event ID; ingestion is unconfirmed.")
        except (httpx.HTTPError, ValueError) as exc:
            endpoint.limitations.append(f"Read-only verification inconclusive: {type(exc).__name__}")
        return endpoint

    def close(self):
        """Close only a client created and owned by this verifier."""
        if self._owns_client:
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
