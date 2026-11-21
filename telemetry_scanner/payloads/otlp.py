from datetime import datetime, timezone
import time
from .common import SyntheticPayload, identity
from ._proto import otlp_trace

def generate(encoding: str = "json", max_bytes: int = 65536) -> SyntheticPayload:
    event_id, timestamp, trace = identity(); span=trace[:16]; ns=time.time_ns()
    if encoding.lower() in ("json", "http/json"):
        body={"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"telemetry-scanner"}}]},"scopeSpans":[{"scope":{"name":"telemetry-scanner"},"spans":[{"traceId":trace,"spanId":span,"name":"authorized_scanner_validation","kind":2,"startTimeUnixNano":str(ns),"endTimeUnixNano":str(ns+1000000),"attributes":[{"key":"scanner.test_id","value":{"stringValue":event_id}}]}]}]}]}
        import json
        data=json.dumps(body,separators=(",", ":")).encode()
        headers={"Content-Type":"application/json"}
    elif encoding.lower() in ("protobuf","http/protobuf","binary"):
        data=otlp_trace(event_id,ns,trace,span); headers={"Content-Type":"application/x-protobuf"}
    else: raise ValueError("OTLP encoding must be json or protobuf")
    if len(data)>max_bytes: raise ValueError(f"Generated payload exceeds configured {max_bytes}-byte limit")
    return SyntheticPayload("otlp-http-"+encoding,event_id,timestamp,data,headers,headers["Content-Type"])
