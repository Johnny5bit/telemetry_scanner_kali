import time
from .common import json_payload, identity

def generate(max_bytes: int=65536):
    event_id, timestamp, trace=identity()
    body={"data":[{"traceID":trace,"spans":[{"traceID":trace,"spanID":trace[:16],"operationName":"authorized_scanner_validation","startTime":time.time_ns()//1000,"duration":1000,"tags":[{"key":"scanner.test_id","type":"string","value":event_id},{"key":"scanner.synthetic","type":"bool","value":True}],"process":{"serviceName":"telemetry-scanner","tags":[]}}],"processes":{}}]}
    p=json_payload("jaeger",body)
    if len(p.body)>max_bytes: raise ValueError("Generated payload exceeds configured size limit")
    return p
