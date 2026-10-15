import json
import os
import platform
import sys
from opentelemetry import trace
from opentelemetry.distro import OpenTelemetryConfigurator, OpenTelemetryDistro
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import Event, ReadableSpan, SpanProcessor
from telvyn_runtime import ConfigurationReporter, SDK_VERSION
from telvyn_privacy import clean_attributes, clean_url, sql_mask
from telvyn_context import DatabaseProvider, requests


runtime = None


def request_hook(span, request):
    if runtime and runtime.security:
        runtime.security.prepare(span, request)


def instrument_asgi(app):
    if os.environ.get("OTEL_SDK_DISABLED", "").lower() == "true":
        return app
    from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware
    return OpenTelemetryMiddleware(app, server_request_hook=request_hook)


def instrument_wsgi(app):
    if os.environ.get("OTEL_SDK_DISABLED", "").lower() == "true":
        return app
    from opentelemetry.instrumentation.wsgi import OpenTelemetryMiddleware
    return OpenTelemetryMiddleware(app, request_hook=request_hook)


class QuerySafeExporter(OTLPSpanExporter):
    def export(self, spans):
        clean = []
        for span in spans:
            attributes = clean_attributes(span.attributes)
            attributes.update({"telvyn.sdk.name": "telvyn-python-agent", "telvyn.sdk.version": SDK_VERSION,
                "process.runtime.version": platform.python_version()})
            name = sql_mask(span.name) if any(key.startswith("db.") for key in attributes) else span.name
            if span.kind in (trace.SpanKind.SERVER, trace.SpanKind.CLIENT) and any(key.startswith(("http.", "url.")) for key in attributes):
                name = clean_url(name)
            clean.append(ReadableSpan(name=name, context=span.context, parent=span.parent,
                resource=span.resource, attributes=attributes,
                events=[Event(event.name, clean_attributes(event.attributes), event.timestamp) for event in span.events],
                links=[trace.Link(link.context, clean_attributes(link.attributes)) for link in span.links],
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
    def _configure(self, **kwargs):
        os.environ.setdefault("OTEL_PYTHON_CONFIGURATOR", "telvyn")
        os.environ.setdefault("OTEL_TRACES_EXPORTER", "telvyn")
        os.environ.setdefault("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
        super()._configure(**kwargs)

    def load_instrumentor(self, entry_point, **kwargs):
        if entry_point.name in ("flask", "django", "falcon"):
            kwargs["request_hook"] = request_hook
        elif entry_point.name in ("fastapi", "starlette", "tornado"):
            kwargs["server_request_hook"] = request_hook
        if entry_point.name == "starlette":
            # FastAPI must retain the original Starlette base, avoiding two HTTP middlewares.
            import importlib.util
            if importlib.util.find_spec("fastapi") is not None:
                import fastapi
        if entry_point.name in ("psycopg2", "psycopg", "asyncpg", "pymysql", "mysqlclient", "sqlite3"):
            kwargs.update(tracer_provider=DatabaseProvider(trace.get_tracer_provider()),
                capture_parameters=False, enable_commenter=False)
        super().load_instrumentor(entry_point, **kwargs)
        if entry_point.name == "flask":
            from flask import got_request_exception
            got_request_exception.connect(record_flask_exception, weak=False)


class TelvynConfigurator(OpenTelemetryConfigurator):
    def _configure(self, **kwargs):
        global runtime
        if getattr(self, "_configured", False):
            return
        super()._configure(**kwargs)
        self._configured = True
        if os.environ.get("OTEL_SDK_DISABLED", "").lower() == "true":
            return
        provider = trace.get_tracer_provider()
        provider.add_span_processor(requests)
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=requests.reset_after_fork)
        provider.add_span_processor(CompletionLogs())
        try:
            runtime = ConfigurationReporter(provider.resource)
            provider.add_span_processor(runtime)
        except Exception:
            print("[Telvyn] SDK configuration reporting could not start.", file=sys.stderr)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: telvyn-python python app.py (or gunicorn ...)")
    if os.environ.get("OTEL_SDK_DISABLED", "").lower() == "true":
        os.execvp(sys.argv[1], sys.argv[1:])
    os.execvp("opentelemetry-instrument", ["opentelemetry-instrument", "--distro", "telvyn", "--traces_exporter", "telvyn", *sys.argv[1:]])
