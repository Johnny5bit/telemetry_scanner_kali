"""Protocol-neutral, bounded synthetic telemetry payload models."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import uuid

@dataclass(frozen=True)
class SyntheticPayload:
    protocol: str
    event_id: str
    timestamp: str
    body: bytes
    headers: dict[str, str]
    content_type: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def preview(self, limit: int = 4096) -> dict:
        return {"protocol": self.protocol, "event_id": self.event_id,
                "timestamp": self.timestamp, "headers": dict(self.headers),
                "content_type": self.content_type, "sha256": self.sha256,
                "body_bytes": len(self.body), "body_preview": self.body[:limit].decode("utf-8", "replace")}

def identity() -> tuple[str, str, str]:
    return "telemetry-scanner-" + uuid.uuid4().hex, datetime.now(timezone.utc).isoformat(), uuid.uuid4().hex

def json_payload(protocol: str, body: object, headers: dict[str,str] | None = None) -> SyntheticPayload:
    event_id = _find_id(body)
    timestamp = _find_timestamp(body)
    data=json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return SyntheticPayload(protocol,event_id,timestamp,data,{"Content-Type":"application/json", **(headers or {})},"application/json")

def _find_id(body):
    text=json.dumps(body)
    import re
    m=re.search(r"telemetry-scanner-[0-9a-f]{32}", text)
    return m.group(0) if m else ""
def _find_timestamp(body):
    text=json.dumps(body)
    import re
    m=re.search(r"\d{4}-\d\d-\d\dT[^\"]+", text)
    return m.group(0) if m else ""
