import html, json, re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from .models import ScanReport
from .scope import redact_sensitive_url, redact_urls_in_text

_SECRET = re.compile(r'(?i)(authorization|x-api-key|api[_-]?key|token|password|secret)(\s*[:=]\s*)([^\s,}]+)')
def sanitize(value):
    if isinstance(value, dict):
        return {str(k):("[REDACTED]" if str(k).lower().replace("-","_") in {"authorization","api_key","x_api_key","token","password","secret","access_token"} else sanitize(v)) for k,v in value.items()}
    if isinstance(value,list): return [sanitize(x) for x in value]
    if isinstance(value,str):
        if "://" in value: return redact_urls_in_text(value)
        return _SECRET.sub(r'\1\2[REDACTED]',value)
    return value

def export_json(report: ScanReport, path: str) -> None:
    Path(path).write_text(json.dumps(sanitize(report.to_dict()), indent=2, ensure_ascii=False), encoding="utf-8")

def export_jsonl(report: ScanReport, path: str) -> None:
    safe=sanitize(report.to_dict())
    lines=[{"record_type":"report","target":safe["target"],"started_at":safe["started_at"],"finished_at":safe["finished_at"],"mode":safe["mode"],"limitations":safe["limitations"]}]
    lines += [{"record_type":"endpoint",**item} for item in safe["endpoints"]]
    lines += [{"record_type":"error","message":item} for item in safe["errors"]]
    Path(path).write_text("".join(json.dumps(row,ensure_ascii=False)+"\n" for row in lines),encoding="utf-8")

def export_har(report: ScanReport, path: str) -> None:
    entries=[]
    for endpoint in report.endpoints:
        url=redact_sensitive_url(endpoint.url)
        entries.append({"startedDateTime":endpoint.timestamp,"time":0,"request":{"method":"POST","url":url,"httpVersion":"HTTP/1.1","headers":[{"name":"X-Telemetry-Test-Id","value":endpoint.test_event_id}],"queryString":[],"headersSize":-1,"bodySize":-1},"response":{"status":0,"statusText":"Not retained","httpVersion":"HTTP/1.1","headers":[],"content":{"size":0,"mimeType":"application/octet-stream","text":"[response body not retained]"},"redirectURL":"","headersSize":-1,"bodySize":-1},"cache":{},"timings":{"send":0,"wait":0,"receive":0},"comment":"Sanitized summary only; raw credentials and payloads are not exported."})
    doc={"log":{"version":"1.2","creator":{"name":"Telemetry Scanner","version":"1.0"},"entries":entries}}
    Path(path).write_text(json.dumps(doc,indent=2),encoding="utf-8")

def export_html(report: ScanReport, path: str) -> None:
    rows = []
    for e in report.endpoints:
        esc = lambda v: html.escape(str(v))
        rows.append("<section><h2>"+esc(sanitize(e.service))+" — "+esc(sanitize(e.status))+"</h2><p><b>Endpoint:</b> "+esc(redact_sensitive_url(e.url))+"<br><b>Source:</b> "+esc(redact_sensitive_url(e.source))+"<br><b>Timestamp:</b> "+esc(sanitize(e.timestamp))+"<br><b>Auth evidence:</b> "+esc(sanitize(e.auth_evidence))+"</p><h3>Evidence</h3><ul>"+"".join("<li>"+esc(sanitize(x))+"</li>" for x in e.evidence)+"</ul><p><b>Test conditions:</b> "+esc(sanitize(e.test_condition))+"<br><b>Test event:</b> "+esc(sanitize(e.test_event_id))+"</p><h3>Limitations</h3><ul>"+"".join("<li>"+esc(sanitize(x))+"</li>" for x in e.limitations)+"</ul><p><b>Remediation:</b> "+esc(sanitize(e.remediation))+"</p></section>")
    doc = "<!doctype html><meta charset='utf-8'><title>Telemetry Scanner Report</title><style>body{font:15px sans-serif;max-width:1000px;margin:2em auto}section{border:1px solid #aaa;padding:1em;margin:1em 0;overflow-wrap:anywhere}</style><h1>Telemetry Injection Vulnerability Scanner</h1><p>Target: "+html.escape(redact_sensitive_url(report.target))+"<br>Mode: "+html.escape(report.mode)+"<br>Started: "+html.escape(report.started_at)+"<br>Finished: "+html.escape(report.finished_at)+"</p>"+"".join(rows)+"<h2>Scan errors</h2><ul>"+"".join("<li>"+html.escape(redact_urls_in_text(e))+"</li>" for e in report.errors)+"</ul><h2>Report limitations</h2><ul>"+"".join("<li>"+html.escape(x)+"</li>" for x in report.limitations)+"</ul>"
    Path(path).write_text(doc, encoding="utf-8")
