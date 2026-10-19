import threading
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.sdk.trace import SpanProcessor


class RequestState:
    def __init__(self, span):
        self.span = span
        self.active = True
        self.path = ""
        self.method = ""
        self.sources = {}
        self.findings = set()


class Requests(SpanProcessor):
    def __init__(self):
        self.spans = {}
        # Requisições ativas por thread: a thread do profiler lê daqui o trace da pilha que amostrou.
        self.threads = {}
        self.lock = threading.RLock()

    def on_start(self, span, parent_context=None):
        parent = trace.get_current_span(parent_context).get_span_context()
        with self.lock:
            request = self.spans.get(parent.span_id)
            if span.kind == trace.SpanKind.SERVER:
                request = RequestState(span)
                request.thread = threading.get_ident()
                active = self.threads.setdefault(request.thread, [])
                if len(active) < 256:
                    active.append(request)
            if request and request.active and len(self.spans) < 65536:
                self.spans[span.get_span_context().span_id] = request

    def on_end(self, span):
        with self.lock:
            request = self.spans.pop(span.context.span_id, None)
            if request and span.kind == trace.SpanKind.SERVER:
                request.active = False
                request.sources.clear()
                active = self.threads.get(getattr(request, "thread", None))
                if active and request in active:
                    active.remove(request)
                    if not active:
                        del self.threads[request.thread]

    def current(self, context=None):
        with self.lock:
            request = self.spans.get(trace.get_current_span(context).get_span_context().span_id)
            return request if request and request.active else None

    def thread_context(self, ident):
        """Trace, span e rota da requisição da thread, só se ela tiver exatamente uma ativa (servidor síncrono).
        Num event loop com várias requisições ao mesmo tempo não há como saber qual estava na CPU: sem vínculo."""
        with self.lock:
            active = self.threads.get(ident)
            if not active or len(active) != 1:
                return None
            span = active[0].span
            context = span.get_span_context()
            route = span.attributes.get("http.route") if span.attributes else None
            return (f"{context.trace_id:032x}", f"{context.span_id:016x}", route)

    def reset_after_fork(self):
        self.spans = {}
        self.threads = {}
        self.lock = threading.RLock()


requests = Requests()


class DatabaseTracer(trace.Tracer):
    def __init__(self, tracer):
        self.tracer = tracer

    def start_span(self, name, context=None, **kwargs):
        if requests.current(context) is None or name.lower() in ("connect", "connection", "pool.connect"):
            return trace.NonRecordingSpan(trace.INVALID_SPAN_CONTEXT)
        return self.tracer.start_span(name, context=context, **kwargs)

    @contextmanager
    def start_as_current_span(self, name, context=None, end_on_exit=True,
            record_exception=True, set_status_on_exception=True, **kwargs):
        span = self.start_span(name, context=context, record_exception=record_exception,
            set_status_on_exception=set_status_on_exception, **kwargs)
        with trace.use_span(span, end_on_exit=end_on_exit, record_exception=record_exception,
                set_status_on_exception=set_status_on_exception):
            yield span


class DatabaseProvider(trace.TracerProvider):
    def __init__(self, provider):
        self.provider = provider

    def get_tracer(self, *args, **kwargs):
        return DatabaseTracer(self.provider.get_tracer(*args, **kwargs))
