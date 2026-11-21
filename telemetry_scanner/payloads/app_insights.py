from .common import json_payload, identity

def generate(max_bytes: int=65536):
    event_id, timestamp, _=identity()
    body={"name":"Microsoft.ApplicationInsights.Event","time":timestamp,"iKey":"00000000-0000-0000-0000-000000000000","data":{"baseType":"EventData","baseData":{"ver":2,"name":"authorized_scanner_validation","properties":{"scanner.test_id":event_id,"scanner.synthetic":"true"}}}}
    result=json_payload("azure-application-insights",body,{"User-Agent":"TelemetryScanner/1.0"})
    if len(result.body)>max_bytes: raise ValueError("Generated payload exceeds configured size limit")
    return result
