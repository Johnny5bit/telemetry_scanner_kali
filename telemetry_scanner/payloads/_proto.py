"""Tiny protobuf wire helpers for the specific telemetry schemas used here."""
def varint(n: int) -> bytes:
    n=int(n)
    if n < 0: n=(1<<64)+n
    out=bytearray()
    while n > 0x7f:
        out.append((n&0x7f)|0x80); n >>= 7
    out.append(n); return bytes(out)
def field_bytes(number: int, value: bytes) -> bytes:
    return varint((number<<3)|2)+varint(len(value))+value
def field_varint(number: int, value: int) -> bytes:
    return varint(number<<3)+varint(value)
def field_fixed64(number: int, value: int) -> bytes:
    return varint((number<<3)|1)+int(value).to_bytes(8,'little',signed=False)
def kv_string(key: str, value: str) -> bytes:
    return field_bytes(1,key.encode())+field_bytes(2,field_bytes(1,value.encode()))
def otlp_trace(event_id: str, timestamp_ns: int, trace_hex: str, span_hex: str) -> bytes:
    attr=field_bytes(1,b"scanner.test_id")+field_bytes(2,field_bytes(1,event_id.encode()))
    span=(field_bytes(1,bytes.fromhex(trace_hex))+field_bytes(2,bytes.fromhex(span_hex))+
          field_bytes(5,b"authorized_scanner_validation")+
          field_varint(6,2)+field_fixed64(7,timestamp_ns)+field_fixed64(8,timestamp_ns+1_000_000)+field_bytes(9,attr))
    scope_spans=field_bytes(2,span)
    resource=field_bytes(1,field_bytes(1,b"service.name")+field_bytes(2,field_bytes(1,b"telemetry-scanner")))
    resource_spans=field_bytes(1,resource)+field_bytes(2,scope_spans)
    return field_bytes(1,resource_spans)
def prometheus_write(event_id: str, timestamp_ms: int) -> bytes:
    """Prometheus WriteRequest wire encoding for one uniquely named synthetic gauge."""
    labels=field_bytes(1,b"__name__")+field_bytes(2,b"telemetry_scanner_synthetic")
    labels+=field_bytes(1,b"scanner_test_id")+field_bytes(2,event_id.encode())
    # Sample: fixed64 double 1.0 (field 1), timestamp int64 milliseconds (field 2)
    sample=varint((1<<3)|1)+(1.0).hex().encode() if False else b""
    import struct
    sample=varint((1<<3)|1)+struct.pack('<d',1.0)+field_varint(2,timestamp_ms)
    timeseries=field_bytes(1,labels)+field_bytes(2,sample)
    return field_bytes(1,timeseries)
