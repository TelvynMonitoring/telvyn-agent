import json
import os
import platform
import sys
from opentelemetry import trace
from opentelemetry.distro import OpenTelemetryDistro
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor


class QuerySafeExporter(OTLPSpanExporter):
    def export(self, spans):
        clean = []
        for span in spans:
            attributes = dict(span.attributes)
            attributes.update({"telvyn.sdk.name": "telvyn-python-agent", "telvyn.sdk.version": "0.1.0",
                "process.runtime.version": platform.python_version()})
            for key in ("http.url", "http.target", "url.full"):
                if isinstance(attributes.get(key), str):
                    attributes[key] = attributes[key].split("?", 1)[0]
            attributes.pop("url.query", None)
            clean.append(ReadableSpan(name=span.name, context=span.context, parent=span.parent,
                resource=span.resource, attributes=attributes, events=span.events, links=span.links,
                kind=span.kind, status=span.status, start_time=span.start_time, end_time=span.end_time,
                instrumentation_scope=span.instrumentation_scope))
        return super().export(clean)


class CompletionLogs(SpanProcessor):
    def on_end(self, span):
        if span.kind != trace.SpanKind.SERVER or not span.context.is_valid:
            return
        status = span.attributes.get("http.response.status_code", span.attributes.get("http.status_code"))
        print(json.dumps(dict(service=span.resource.attributes.get("service.name"),
            level="error" if status is not None and status >= 500 else "info",
            message="HTTP request completed", method=span.attributes.get("http.request.method", span.attributes.get("http.method")),
            status=status, trace_id=f"{span.context.trace_id:032x}", span_id=f"{span.context.span_id:016x}")), flush=True)


def record_flask_exception(sender, exception, **kwargs):
    trace.get_current_span().record_exception(exception)


class TelvynDistro(OpenTelemetryDistro):
    def load_instrumentor(self, entry_point, **kwargs):
        if not getattr(self, "_logs_added", False):
            trace.get_tracer_provider().add_span_processor(CompletionLogs())
            self._logs_added = True
        super().load_instrumentor(entry_point, **kwargs)
        if entry_point.name == "flask":
            from flask import got_request_exception
            got_request_exception.connect(record_flask_exception, weak=False)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: telvyn-python python app.py (or gunicorn ...)")
    if os.environ.get("OTEL_SDK_DISABLED", "").lower() == "true":
        os.execvp(sys.argv[1], sys.argv[1:])
    os.execvp("opentelemetry-instrument", ["opentelemetry-instrument", "--distro", "telvyn", "--traces_exporter", "telvyn", *sys.argv[1:]])
