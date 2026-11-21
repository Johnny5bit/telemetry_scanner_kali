from .common import json_payload, identity

def generate(max_bytes: int=65536):
    event_id,timestamp,_=identity()
    p=json_payload("custom-http-json",{"event":"authorized_scanner_validation","event_id":event_id,"timestamp":timestamp,"attributes":{"scanner.synthetic":True}}, {"X-Telemetry-Test-Id":event_id})
    if len(p.body)>max_bytes: raise ValueError("Generated payload exceeds configured size limit")
    return p
