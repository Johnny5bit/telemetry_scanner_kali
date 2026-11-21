from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from .scope import redact_sensitive_url, redact_urls_in_text

class Status(StrEnum):
    DISCOVERED = "Discovered"
    AUTH_REQUIRED = "Authentication Required"
    POTENTIAL = "Potential Exposure"
    INGESTED = "Confirmed Ingestion"
    FINDING = "Confirmed Security Finding"
    INCONCLUSIVE = "Inconclusive"

@dataclass
class Endpoint:
    url: str
    service: str
    evidence: list[str] = field(default_factory=list)
    source: str = ""
    auth_evidence: str = "Unknown"
    status: str = Status.DISCOVERED
    test_event_id: str = ""
    test_condition: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    limitations: list[str] = field(default_factory=list)
    remediation: str = ""

@dataclass
class ScanReport:
    target: str
    started_at: str
    finished_at: str = ""
    endpoints: list[Endpoint] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    mode: str = "Discovery"
    limitations: list[str] = field(default_factory=list)
    def to_dict(self) -> dict[str, Any]:
        endpoints = [asdict(e) for e in self.endpoints]
        for endpoint in endpoints:
            endpoint["url"] = redact_sensitive_url(endpoint["url"])
            endpoint["source"] = redact_sensitive_url(endpoint["source"])
        return {"target": redact_sensitive_url(self.target), "started_at": self.started_at, "finished_at": self.finished_at,
                "mode": self.mode, "endpoints": endpoints,
                "errors": [redact_urls_in_text(item) for item in self.errors], "limitations": self.limitations}
