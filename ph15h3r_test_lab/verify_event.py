"""Use the scanner's existing read-only verifier against this localhost lab."""
from pathlib import Path
import re
import sys

# Make the parent project importable without installing or editing the scanner.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from telemetry_scanner.models import Endpoint
from telemetry_scanner.verification import ReadOnlyVerifier

BASE = "http://127.0.0.1:8765"
EVENT_ID_RE = re.compile(r"^telemetry-scanner-[0-9a-f]{32}$")


def main() -> int:
    if len(sys.argv) != 2 or not EVENT_ID_RE.fullmatch(sys.argv[1]):
        print("Usage: python verify_event.py telemetry-scanner-<32 lowercase hex characters>", file=sys.stderr)
        return 2
    event_id = sys.argv[1]
    endpoint = Endpoint(f"{BASE}/api/telemetry", "Custom telemetry API")
    endpoint.test_event_id = event_id
    verify_url = f"{BASE}/events/{event_id}"
    try:
        with ReadOnlyVerifier(f"{BASE}/events/{{event_id}}", [verify_url], timeout=2.0) as verifier:
            verifier.verify(endpoint)
    except Exception as exc:
        print(f"Verification could not run: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(f"Status: {endpoint.status}")
    print(f"Evidence: {endpoint.auth_evidence}")
    print("Note: Confirmed Ingestion verifies storage of the synthetic event; it is not a Confirmed Security Finding.")
    return 0 if str(endpoint.status) == "Confirmed Ingestion" else 1


if __name__ == "__main__":
    raise SystemExit(main())
