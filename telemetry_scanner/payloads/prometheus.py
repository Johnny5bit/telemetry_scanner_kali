import time
from .common import SyntheticPayload, identity
from ._proto import prometheus_write

def generate(max_bytes: int=65536):
    event_id,timestamp,_=identity()
    try:
        import snappy
    except ImportError as exc:
        raise RuntimeError("Prometheus remote-write requires the optional python-snappy module") from exc
    raw=prometheus_write(event_id,int(time.time()*1000)); body=snappy.compress(raw)
    if len(body)>max_bytes: raise ValueError("Generated payload exceeds configured size limit")
    headers={"Content-Type":"application/x-protobuf","Content-Encoding":"snappy","User-Agent":"TelemetryScanner/1.0","X-Prometheus-Remote-Write-Version":"0.1.0"}
    return SyntheticPayload("prometheus-remote-write",event_id,timestamp,body,headers,headers["Content-Type"])
