import time
from .common import json_payload, identity

def generate(max_bytes: int=65536):
    event_id, timestamp, trace=identity()
    body=[{"traceId":trace,"id":trace[:16],"name":"authorized_scanner_validation","timestamp":time.time_ns()//1000,"duration":1000,"localEndpoint":{"serviceName":"telemetry-scanner"},"tags":{"scanner.test_id":event_id,"scanner.synthetic":"true"}}]
    p=json_payload("zipkin-v2",body)
    if len(p.body)>max_bytes: raise ValueError("Generated payload exceeds configured size limit")
    return p
