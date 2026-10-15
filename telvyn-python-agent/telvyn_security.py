import inspect
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid
from importlib.resources import files
from urllib.parse import urlsplit

from wrapt import ObjectProxy, register_post_import_hook, wrap_function_wrapper
from telvyn_context import requests
from telvyn_privacy import clean_url, sql_mask
from telvyn_profiler import source_file, stack_frames


def sources(value):
    return value.origins if isinstance(value, InputString) and value.request is requests.current() else ()


class InputString(str):
    def __new__(cls, value, origins):
        result = super().__new__(cls, value)
        result.origins = tuple(dict.fromkeys(origins))[:16]
        result.request = requests.current()
        return result

    def __add__(self, other):
        return InputString(super().__add__(other), sources(self) + sources(other))

    def __radd__(self, other):
        return InputString(str.__add__(other, self), sources(other) + sources(self))

    def __mod__(self, other):
        values = other.values() if isinstance(other, dict) else other if isinstance(other, tuple) else (other,)
        origins = sources(self) + tuple(origin for value in values for origin in sources(value))
        return InputString(super().__mod__(other), origins)

    def format(self, *args, **kwargs):
        origins = sources(self) + tuple(origin for value in (*args, *kwargs.values()) for origin in sources(value))
        return InputString(super().format(*args, **kwargs), origins)

    def __getitem__(self, index):
        return InputString(super().__getitem__(index), sources(self))

    def strip(self, chars=None):
        return InputString(super().strip(chars), sources(self))

    def lstrip(self, chars=None):
        return InputString(super().lstrip(chars), sources(self))

    def rstrip(self, chars=None):
        return InputString(super().rstrip(chars), sources(self))

    def casefold(self):
        return InputString(super().casefold(), sources(self))

    def lower(self):
        return InputString(super().lower(), sources(self))

    def upper(self):
        return InputString(super().upper(), sources(self))

    def replace(self, old, new, count=-1):
        return InputString(super().replace(old, new, count), sources(self) + sources(new))

    def join(self, iterable):
        values = list(iterable)
        origins = sources(self) + tuple(origin for value in values for origin in sources(value))
        return InputString(super().join(values), origins)

    def split(self, sep=None, maxsplit=-1):
        return [InputString(value, sources(self)) for value in super().split(sep, maxsplit)]

    def rsplit(self, sep=None, maxsplit=-1):
        return [InputString(value, sources(self)) for value in super().rsplit(sep, maxsplit)]

    def partition(self, sep):
        return tuple(InputString(value, sources(self)) for value in super().partition(sep))

    def rpartition(self, sep):
        return tuple(InputString(value, sources(self)) for value in super().rpartition(sep))

    def removeprefix(self, prefix):
        return InputString(super().removeprefix(prefix), sources(self))

    def removesuffix(self, suffix):
        return InputString(super().removesuffix(suffix), sources(self))


class InputMap(ObjectProxy):
    def __init__(self, wrapped, source):
        super().__init__(wrapped)
        self._self_source = source

    def __getitem__(self, key):
        return mark(self.__wrapped__[key], self._self_source + ":" + str(key))

    def get(self, key, default=None, *args, **kwargs):
        value = self.__wrapped__.get(key, default, *args, **kwargs)
        return mark(value, self._self_source + ":" + str(key)) if key in self.__wrapped__ else value

    def getlist(self, key, *args, **kwargs):
        return mark(self.__wrapped__.getlist(key, *args, **kwargs), self._self_source + ":" + str(key))

    def items(self, *args, **kwargs):
        for key, value in self.__wrapped__.items(*args, **kwargs):
            yield key, mark(value, self._self_source + ":" + str(key))

    def values(self):
        for _, value in self.items():
            yield value


def mark(value, origin, depth=0):
    if not sensor or sensor.closed or not (sensor.attack_state == "active" or sensor.iast_state == "active"):
        return value
    request = requests.current()
    if request and sensor and not hasattr(request, "security_selected"):
        attributes = request.span.attributes
        path = attributes.get("url.path") or attributes.get("http.target")
        if not path and isinstance(attributes.get("http.url"), str):
            try:
                path = urlsplit(attributes["http.url"]).path
            except ValueError:
                path = ""
        sensor.prepare(request.span, dict(path=path or "", method=attributes.get("http.request.method", attributes.get("http.method", ""))))
    if not request or not getattr(request, "security_selected", False) or depth > 8:
        return value
    count = getattr(request, "source_count", 0)
    if count >= 512:
        return value
    request.source_count = count + 1
    origin = re.sub(r"[^a-zA-Z0-9_.:-]", "_", origin)[:80]
    kind, _, field = origin.partition(":")
    origin = kind[:20] + ":" + (re.sub(r"[^A-Za-z0-9_.-]", "_", field)[:64] or "body")
    if isinstance(value, str):
        if len(value) > 4096:
            return value
        if sensor:
            sensor.inspect(value, request)
        return InputString(value, (origin,)) if sensor and sensor.iast_state == "active" else value
    if type(value) is dict:
        return {key: mark(item, ("body:" if origin == "body:body" else origin + ".") + str(key), depth + 1) for key, item in value.items()} if len(value) <= 128 else value
    if type(value) is list:
        return [mark(item, origin + "." + str(index), depth + 1) for index, item in enumerate(value)] if len(value) <= 128 else value
    return value


class SourceProperty:
    def __init__(self, original, name, kind):
        self.original, self.name, self.kind = original, name, kind

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        # cached_property implementations store the raw value in the instance dictionary.
        namespace = getattr(instance, "__dict__", {})
        value = namespace[self.name] if self.name in namespace else self.original.__get__(instance, owner)
        request = requests.current()
        return InputMap(value, self.kind) if request and hasattr(value, "get") else value

    def __set__(self, instance, value):
        if hasattr(self.original, "__set__"):
            self.original.__set__(instance, value)
        else:
            instance.__dict__[self.name] = value

    def __delete__(self, instance):
        if hasattr(self.original, "__delete__"):
            self.original.__delete__(instance)
        else:
            instance.__dict__.pop(self.name, None)


sensor = None


class Security:
    def __init__(self, runtime):
        global sensor
        self.runtime = runtime
        self.closed = False
        self.attack_state = "disabled"
        self.iast_state = "disabled"
        enabled = os.environ.get("TELVYN_SECURITY_ENABLED") == "true"
        iast = os.environ.get("TELVYN_IAST_ENABLED") == "true"
        if not enabled and not iast:
            return
        paths = [item.strip() for item in os.environ.get("TELVYN_SECURITY_ROUTES", "").split(",") if item.strip()]
        root = os.environ.get("TELVYN_PROFILE_SOURCE_ROOT")
        if not paths or not runtime.transport.identity["environment"] or not root:
            raise ValueError("Security requires routes, environment and source root")
        if any(not path.startswith("/") or "?" in path or "**" in path for path in paths):
            raise ValueError("Invalid security routes")
        self.routes = [re.compile("^" + re.escape(path).replace(r"\*", "[^/]+") + "$", re.ASCII) for path in paths]
        self.root = Path(root).resolve()
        self.rules = json.loads(files("telvyn_python_data").joinpath("security-rules.json").read_text(encoding="utf-8"))
        self.patterns = [(row["id"], re.compile(row["pattern"], re.I)) for row in self.rules["attack"]]
        self.attack_state = "active" if enabled else "disabled"
        self.iast_state = "active" if iast else "disabled"
        sensor = self
        self._install()

    def prepare(self, span, request):
        try:
            self._prepare(span, request)
        except Exception:
            return

    def _prepare(self, span, request):
        if self.closed:
            return
        state = requests.spans.get(span.get_span_context().span_id)
        if not state:
            return
        if isinstance(request, dict):
            path = request.get("path") or request.get("PATH_INFO", "")
            method = request.get("method") or request.get("REQUEST_METHOD", "")
        else:
            raw = getattr(request, "request", request)
            path = getattr(raw, "path", "")
            method = getattr(raw, "method", "")
        if isinstance(path, str):
            state.path = clean_url(path)[:1024]
            state.method = method if isinstance(method, str) and re.fullmatch("[A-Z]{1,20}", method) else ""
            state.security_selected = any(pattern.fullmatch(state.path) for pattern in self.routes)

    def inspect(self, value, request):
        if self.attack_state != "active" or self.closed:
            return
        started = time.perf_counter_ns()
        for rule, pattern in self.patterns:
            if rule in request.findings or not pattern.search(value):
                continue
            request.findings.add(rule)
            self._report("security/events", request, started, rule, "python-input-patterns-1", {})

    def finding(self, rule, value, sink, flaw=False):
        try:
            self._finding(rule, value, sink, flaw)
        except Exception:
            return

    def _finding(self, rule, value, sink, flaw=False):
        request = requests.current()
        if self.closed or self.iast_state != "active" or not request or not getattr(request, "security_selected", False):
            return
        origins = sources(value)
        if not flaw and not origins:
            return
        started = time.perf_counter_ns()
        frame = sys._getframe(1)
        while frame and not source_file(frame.f_code.co_filename, self.root):
            frame = frame.f_back
        if frame is None:
            return
        file = source_file(frame.f_code.co_filename, self.root)
        name = getattr(frame.f_code, "co_qualname", frame.f_code.co_name)
        if not re.fullmatch(r"[A-Za-z_][\w.]*", name, re.ASCII):
            return
        method = file + "#" + name
        key = (rule, method, frame.f_lineno)
        if key in request.findings or len(request.findings) >= 64:
            return
        request.findings.add(key)
        stack, lines = stack_frames(frame, self.root)
        finding = dict(code_method=method, code_line=frame.f_lineno, sink=sink,
            stack=[f"{label}:{line}"[:300] for label, line in list(zip(stack.split(";"), lines))[-64:]])
        if origins:
            finding["source"] = origins[0]
        if request.method:
            finding["request_method"] = request.method
        finding["request_path"] = request.path
        if rule == "SQL_INJECTION":
            finding["sql"] = sql_mask(value)[:2000]
        self._report("security/iast", request, started, rule, "iast-python-1", finding)

    def _report(self, channel, request, started, rule, rules, finding):
        span = request.span.get_span_context()
        report = dict(id=str(uuid.uuid4()), outcome="match", rule_id=rule, rules_version=rules,
            engine_version=self.rules["engine_version"], elapsed_us=min(60000000, (time.perf_counter_ns() - started) // 1000), **finding)
        if span.is_valid:
            report.update(trace_id=f"{span.trace_id:032x}", span_id=f"{span.span_id:016x}")
        self.runtime.send(channel, report)

    def _install(self):
        def hook(module_name, callback):
            def loaded(module):
                try:
                    callback(module)
                except Exception:
                    self.iast_state = "error" if self.iast_state != "disabled" else "disabled"
                    self.attack_state = "error" if self.attack_state != "disabled" else "disabled"
                    print("[Telvyn] Security integration unavailable: " + module_name, file=sys.stderr)
            register_post_import_hook(loaded, module_name)

        def properties(module, class_name, entries):
            cls = getattr(module, class_name)
            for name, kind in entries:
                original = inspect.getattr_static(cls, name)
                if not isinstance(original, SourceProperty):
                    setattr(cls, name, SourceProperty(original, name, kind))

        def json_result(wrapped, instance, args, kwargs):
            result = wrapped(*args, **kwargs)
            if inspect.isawaitable(result):
                async def awaited():
                    return mark(await result, "body:body")
                return awaited()
            return mark(result, "body:body")

        def form_result(wrapped, instance, args, kwargs):
            async def awaited():
                result = await wrapped(*args, **kwargs)
                return InputMap(result, "body")
            return awaited()

        hook("werkzeug.wrappers.request", lambda module: properties(module, "Request", (("args", "query"), ("form", "body"), ("cookies", "cookie"))))
        hook("flask.wrappers", lambda module: wrap_function_wrapper(module, "Request.get_json", json_result))
        hook("werkzeug.wrappers.request", lambda module: wrap_function_wrapper(module, "Request.__init__", self._request_headers))
        hook("starlette.requests", lambda module: (
            properties(module, "HTTPConnection", (("query_params", "query"), ("headers", "header"), ("cookies", "cookie"), ("path_params", "path"))),
            wrap_function_wrapper(module, "Request.json", json_result),
            wrap_function_wrapper(module, "Request._get_form", form_result)))
        hook("django.core.handlers.wsgi", lambda module: properties(module, "WSGIRequest", (("GET", "query"), ("POST", "body"), ("COOKIES", "cookie"))))
        hook("django.core.handlers.asgi", lambda module: properties(module, "ASGIRequest", (("GET", "query"), ("POST", "body"), ("COOKIES", "cookie"))))
        hook("django.http.request", lambda module: properties(module, "HttpRequest", (("headers", "header"),)))
        hook("rest_framework.request", lambda module: (
            properties(module, "Request", (("query_params", "query"),)),
            wrap_function_wrapper(module, "Request._parse", self._drf_parse)))
        hook("flask.app", lambda module: wrap_function_wrapper(module, "Flask.dispatch_request", self._flask_path))
        hook("django.core.handlers.base", lambda module: wrap_function_wrapper(module, "BaseHandler.resolve_request", self._django_path))
        hook("aiohttp.web_request", lambda module: (
            properties(module, "BaseRequest", (("query", "query"), ("headers", "header"), ("cookies", "cookie"))),
            properties(module, "Request", (("match_info", "path"),)),
            wrap_function_wrapper(module, "BaseRequest.json", json_result),
            wrap_function_wrapper(module, "BaseRequest.post", form_result)))
        hook("tornado.web", lambda module: [wrap_function_wrapper(module, "RequestHandler." + method, self._argument(kind))
            for method, kind in (("get_query_argument", "query"), ("get_body_argument", "body"), ("get_cookie", "cookie"))])
        hook("falcon.request", lambda module: (
            wrap_function_wrapper(module, "Request.get_param", self._argument("query")),
            wrap_function_wrapper(module, "Request.get_header", self._argument("header")),
            wrap_function_wrapper(module, "Request.get_media", json_result)))
        hook("webob.request", lambda module: properties(module, "BaseRequest", (("GET", "query"), ("POST", "body"), ("cookies", "cookie"), ("headers", "header"))))
        if self.iast_state != "active":
            return
        hook("opentelemetry.instrumentation.dbapi", lambda module: (
            wrap_function_wrapper(module, "CursorTracer.traced_execution", self._database),
            wrap_function_wrapper(module, "CursorTracer.traced_execution_async", self._database_async)))
        hook("asyncpg.connection", lambda module: [wrap_function_wrapper(module, "Connection." + method, self._query_async)
            for method in ("execute", "executemany", "fetch", "fetchrow", "fetchval", "prepare")])
        for module_name, method, rule, index in (
            ("subprocess", "Popen.__init__", "COMMAND_INJECTION", 0),
            ("os", "system", "COMMAND_INJECTION", 0), ("os", "popen", "COMMAND_INJECTION", 0),
            ("builtins", "open", "PATH_TRAVERSAL", 0), ("io", "open", "PATH_TRAVERSAL", 0),
            ("requests.sessions", "Session.request", "SSRF", 1),
            ("httpx", "Client.request", "SSRF", 1),
            ("urllib.request", "urlopen", "SSRF", 0),
        ):
            hook(module_name, lambda module, method=method, rule=rule, index=index:
                wrap_function_wrapper(module, method, self._sink(rule, module.__name__ + "." + method, index)))
        hook("hashlib", lambda module: [wrap_function_wrapper(module, method, self._weak_hash(method)) for method in ("md5", "sha1", "new")])
        hook("cryptography.hazmat.primitives.ciphers", lambda module: wrap_function_wrapper(module, "Cipher.__init__", self._cipher))
        hook("builtins", lambda module: [wrap_function_wrapper(module, method, self._code(method)) for method in ("eval", "exec")])
        hook("werkzeug.datastructures.headers", lambda module: [wrap_function_wrapper(module, "Headers." + method, self._header) for method in ("set", "add")])
        hook("starlette.datastructures", lambda module: wrap_function_wrapper(module, "MutableHeaders.__setitem__", self._header))
        hook("django.http.response", lambda module: wrap_function_wrapper(module, "HttpResponseBase.__setitem__", self._header))
        for module_name, class_name in (("werkzeug.wrappers.response", "Response"), ("starlette.responses", "Response"), ("django.http.response", "HttpResponseBase")):
            hook(module_name, lambda module, class_name=class_name: wrap_function_wrapper(module, class_name + ".set_cookie", self._cookie))
        for module_name, target in (("werkzeug.utils", "redirect"), ("starlette.responses", "RedirectResponse.__init__"), ("django.http.response", "HttpResponseRedirectBase.__init__")):
            hook(module_name, lambda module, target=target: wrap_function_wrapper(module, target, self._sink("UNVALIDATED_REDIRECT", "http.redirect", 0)))
        hook("httpx", lambda module: wrap_function_wrapper(module, "AsyncClient.request", self._ssrf_async))
        hook("aiohttp.client", lambda module: wrap_function_wrapper(module, "ClientSession._request", self._ssrf_async))
        for module_name in ("pymongo.synchronous.collection", "pymongo.collection"):
            hook(module_name, lambda module: [wrap_function_wrapper(module, "Collection." + method, self._nosql)
                for method in ("find", "find_one", "count_documents", "delete_one", "delete_many", "update_one", "update_many")])
        hook("pymongo.asynchronous.collection", lambda module: (
            wrap_function_wrapper(module, "AsyncCollection.find", self._nosql),
            [wrap_function_wrapper(module, "AsyncCollection." + method, self._nosql_async)
                for method in ("find_one", "count_documents", "delete_one", "delete_many", "update_one", "update_many")]))
        hook("lxml.etree", lambda module: wrap_function_wrapper(module, "XPath", self._sink("XPATH_INJECTION", "lxml.XPath", 0)))
        hook("ldap3.core.connection", lambda module: wrap_function_wrapper(module, "Connection.search", self._ldap))
        hook("jinja2.environment", lambda module: wrap_function_wrapper(module, "Environment.from_string", self._sink("CODE_INJECTION", "jinja2.template", 0)))

    def _argument(self, kind):
        def invoke(wrapped, instance, args, kwargs):
            value = wrapped(*args, **kwargs)
            name = args[0] if args else kwargs.get("name", "field")
            return mark(value, kind + ":" + str(name))
        return invoke

    def _nosql(self, wrapped, instance, args, kwargs):
        try:
            self._inspect_nosql(args[0] if args else kwargs.get("filter"))
        except Exception:
            pass
        return wrapped(*args, **kwargs)

    def _inspect_nosql(self, query):
        pending = [(query, 0)]
        visited = 0
        while pending and visited < 128:
            value, depth = pending.pop()
            visited += 1
            if depth >= 8:
                continue
            if isinstance(value, dict):
                for key, item in list(value.items())[:128]:
                    # Ordinary equality parameters are not executable query strings.
                    if key in ("$where", "$regex"):
                        self.finding("NOSQL_INJECTION", item, "pymongo.query")
                    elif key == "$function" and isinstance(item, dict):
                        self.finding("NOSQL_INJECTION", item.get("body"), "pymongo.function")
                    pending.append((item, depth + 1))
            elif isinstance(value, (list, tuple)):
                pending.extend((item, depth + 1) for item in value[:128])

    def _ldap(self, wrapped, instance, args, kwargs):
        self.finding("LDAP_INJECTION", args[1] if len(args) > 1 else kwargs.get("search_filter"), "ldap3.search")
        return wrapped(*args, **kwargs)

    async def _nosql_async(self, wrapped, instance, args, kwargs):
        return await self._nosql(wrapped, instance, args, kwargs)

    def _request_headers(self, wrapped, instance, args, kwargs):
        result = wrapped(*args, **kwargs)
        instance.headers = InputMap(instance.headers, "header")
        return result

    def _drf_parse(self, wrapped, instance, args, kwargs):
        data, files = wrapped(*args, **kwargs)
        return mark(data, "body:body"), files

    def _flask_path(self, wrapped, instance, args, kwargs):
        from flask import request
        if request.view_args:
            request.view_args = {key: mark(value, "path:" + key) for key, value in request.view_args.items()}
        return wrapped(*args, **kwargs)

    def _django_path(self, wrapped, instance, args, kwargs):
        match = wrapped(*args, **kwargs)
        match.kwargs = {key: mark(value, "path:" + key) for key, value in match.kwargs.items()}
        return match

    def _database(self, wrapped, instance, args, kwargs):
        if len(args) > 2:
            self.finding("SQL_INJECTION", args[2], "dbapi.execute")
        return wrapped(*args, **kwargs)

    async def _database_async(self, wrapped, instance, args, kwargs):
        if len(args) > 2:
            self.finding("SQL_INJECTION", args[2], "dbapi.execute")
        return await wrapped(*args, **kwargs)

    async def _query_async(self, wrapped, instance, args, kwargs):
        self.finding("SQL_INJECTION", args[0] if args else kwargs.get("query"), "asyncpg.execute")
        return await wrapped(*args, **kwargs)

    def _sink(self, rule, name, index):
        def invoke(wrapped, instance, args, kwargs):
            value = args[index] if len(args) > index else kwargs.get("url" if rule in ("SSRF", "UNVALIDATED_REDIRECT") else "args" if rule == "COMMAND_INJECTION" else "file")
            if value is None and rule == "UNVALIDATED_REDIRECT":
                value = kwargs.get("location", kwargs.get("redirect_to"))
            if value is None and rule in ("XPATH_INJECTION", "CODE_INJECTION"):
                value = kwargs.get("path" if rule == "XPATH_INJECTION" else "source")
            # An argv list without a shell is not command injection.
            if rule != "COMMAND_INJECTION" or isinstance(value, str) and (name != "subprocess.Popen.__init__" or kwargs.get("shell") is True):
                self.finding(rule, value, name)
            return wrapped(*args, **kwargs)
        return invoke

    async def _ssrf_async(self, wrapped, instance, args, kwargs):
        self.finding("SSRF", args[1] if len(args) > 1 else kwargs.get("url", kwargs.get("str_or_url")), "http.async_request")
        return await wrapped(*args, **kwargs)

    def _weak_hash(self, algorithm):
        def invoke(wrapped, instance, args, kwargs):
            name = (args[0] if args else kwargs.get("name", "")) if algorithm == "new" else algorithm
            if isinstance(name, str) and name.lower() in ("md4", "md5", "sha1"):
                # Ignore framework-internal ETag/session hashes; only direct application calls count.
                if source_file(sys._getframe(1).f_code.co_filename, self.root):
                    self.finding("WEAK_HASH", None, "hashlib." + algorithm, flaw=True)
            return wrapped(*args, **kwargs)
        return invoke

    def _cipher(self, wrapped, instance, args, kwargs):
        algorithm = args[0] if args else kwargs.get("algorithm")
        mode = args[1] if len(args) > 1 else kwargs.get("mode")
        if type(algorithm).__name__ in ("TripleDES", "ARC4", "Blowfish", "CAST5", "IDEA", "SEED") or type(mode).__name__ == "ECB":
            self.finding("WEAK_CIPHER", None, "cryptography.Cipher", flaw=True)
        return wrapped(*args, **kwargs)

    def _code(self, method):
        def invoke(wrapped, instance, args, kwargs):
            value = args[0] if args else kwargs.get("source")
            self.finding("CODE_INJECTION", value, "builtins." + method)
            # Preserve implicit caller globals/locals; evaluating in this wrapper would change the application.
            caller = sys._getframe(1)
            positional, named = list(args), dict(kwargs)
            supplied_globals = positional[1] if len(positional) > 1 else named.get("globals")
            if supplied_globals is None:
                if len(positional) > 1:
                    positional[1] = caller.f_globals
                else:
                    named["globals"] = caller.f_globals
                if len(positional) > 2:
                    if positional[2] is None:
                        positional[2] = caller.f_locals
                elif named.get("locals") is None:
                    named["locals"] = caller.f_locals
            # Python <=3.12 accepts globals/locals only positionally.
            if sys.version_info < (3, 13) and positional:
                if len(positional) == 1 and "globals" in named:
                    positional.append(named.pop("globals"))
                if len(positional) == 2 and "locals" in named:
                    positional.append(named.pop("locals"))
            return wrapped(*positional, **named)
        return invoke

    def _header(self, wrapped, instance, args, kwargs):
        if len(args) >= 2 and isinstance(args[0], str):
            name, value = args[:2]
            if name.lower() == "location":
                self.finding("UNVALIDATED_REDIRECT", value, "http.header")
            if isinstance(value, str) and ("\r" in value or "\n" in value):
                self.finding("HEADER_INJECTION", value, "http.header")
            if name.lower() == "set-cookie" and isinstance(value, str) and not re.search(r"(?:^|;)\s*max-age=0(?:;|$)", value, re.I):
                attributes = {part.strip().split("=", 1)[0].lower() for part in value.split(";")[1:]}
                for attribute, rule in (("secure", "INSECURE_COOKIE"), ("httponly", "NO_HTTPONLY_COOKIE"), ("samesite", "NO_SAMESITE_COOKIE")):
                    if attribute not in attributes:
                        self.finding(rule, None, "http.cookie", flaw=True)
        return wrapped(*args, **kwargs)

    def _cookie(self, wrapped, instance, args, kwargs):
        result = wrapped(*args, **kwargs)
        try:
            bound = inspect.signature(wrapped).bind(*args, **kwargs)
            bound.apply_defaults()
            values = bound.arguments
            if values.get("value") != "" and values.get("max_age") != 0:
                for name, rule in (("secure", "INSECURE_COOKIE"), ("httponly", "NO_HTTPONLY_COOKIE"), ("samesite", "NO_SAMESITE_COOKIE")):
                    if not values.get(name):
                        self.finding(rule, None, "http.set_cookie", flaw=True)
        except Exception:
            pass
        return result

    def after_fork(self):
        pass

    def stop(self):
        self.closed = True
