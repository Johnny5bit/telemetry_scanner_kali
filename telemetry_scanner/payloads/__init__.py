"""Protocol-aware synthetic payloads. Generation is local and never sends traffic."""
from . import app_insights, custom, jaeger, otlp, prometheus, zipkin
GENERATORS={"azure-application-insights":app_insights.generate,"otlp-http":otlp.generate,"jaeger":jaeger.generate,"zipkin":zipkin.generate,"prometheus-remote-write":prometheus.generate,"custom-http-json":custom.generate}
def generate(protocol: str, **options):
    try: factory=GENERATORS[protocol]
    except KeyError as exc: raise ValueError(f"Unsupported telemetry protocol: {protocol}") from exc
    return factory(**options)
