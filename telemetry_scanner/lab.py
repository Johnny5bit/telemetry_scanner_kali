"""Private localhost-only synthetic telemetry collector for QA and demonstrations."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, threading

class _Server(ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=False

class LocalTelemetryLab:
    def __init__(self, token: str="", tenant: str="default", foreign_tenant: str="other", duplicate_mode: str="accept", forced_status: int | None=None):
        if duplicate_mode not in ("accept", "deduplicate"): raise ValueError("duplicate_mode must be accept or deduplicate")
        if forced_status is not None and forced_status not in (400,401,403,413,429,500,503): raise ValueError("Unsupported simulated response status")
        self.token=token; self.tenant=tenant; self.foreign_tenant=foreign_tenant
        self.duplicate_mode=duplicate_mode; self.forced_status=forced_status
        self.events=[]; self._lock=threading.Lock(); self._httpd=None; self._thread=None
    def start(self, port: int=0):
        if self._httpd: return self
        lab=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def _send(self,status,obj):
                data=json.dumps(obj).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
            def do_GET(self):
                status,obj=lab.handle_request("GET",self.path,dict(self.headers),b""); return self._send(status,obj)
            def do_POST(self):
                try: body=self.rfile.read(min(int(self.headers.get("Content-Length","0")),65536))
                except (ValueError, OSError): body=b""
                status,obj=lab.handle_request("POST",self.path,dict(self.headers),body); return self._send(status,obj)
        self._httpd=_Server(("127.0.0.1",int(port)),Handler)
        if self._httpd.server_address[0]!="127.0.0.1": raise RuntimeError("Lab must bind to localhost")
        self._thread=threading.Thread(target=self._httpd.serve_forever,name="telemetry-lab",daemon=True); self._thread.start(); return self
    def handle_request(self, method: str, path: str, headers: dict, body: bytes):
        """In-process transport hook used by tests as well as the localhost server."""
        headers={str(k).lower():v for k,v in headers.items()}
        if method=="GET" and path=="/events":
            with self._lock: return 200,{"events":list(self.events)}
        if method!="POST" or path not in ("/ingest","/v1/traces","/api/v2/spans","/api/traces","/v1/metrics"):
            return 404,{"error":"not found"}
        if len(body)>65536: return 413,{"error":"payload too large"}
        if self.token and headers.get("authorization")!="Bearer "+self.token: return 401,{"error":"authentication required"}
        if self.forced_status is not None: return self.forced_status,{"error":"configured synthetic lab response"}
        try: payload=json.loads(body)
        except (ValueError, TypeError): return 400,{"error":"invalid JSON synthetic payload"}
        tenant=headers.get("x-test-tenant",self.tenant)
        if tenant!=self.tenant: return 403,{"error":"tenant boundary enforced"}
        event_id=self._event_id(payload)
        with self._lock:
            duplicate=bool(event_id and any(self._event_id(item["payload"])==event_id for item in self.events))
            if not duplicate or self.duplicate_mode=="accept": self.events.append({"payload":payload,"tenant":tenant})
        return 202,{"accepted":True,"duplicate":duplicate,"stored":not duplicate or self.duplicate_mode=="accept"}
    @classmethod
    def _event_id(cls, value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key.lower() in ("event_id","test_event_id","scanner.test_id"): return str(item)
                found=cls._event_id(item)
                if found: return found
        elif isinstance(value,list):
            for item in value:
                found=cls._event_id(item)
                if found: return found
        return ""
    @property
    def base_url(self):
        if not self._httpd: raise RuntimeError("Start lab before accessing base_url")
        return f"http://127.0.0.1:{self._httpd.server_port}"
    def stop(self):
        if self._httpd:
            self._httpd.shutdown(); self._httpd.server_close(); self._thread.join(timeout=2); self._httpd=None; self._thread=None
    def __enter__(self): return self.start()
    def __exit__(self,*args): self.stop()
