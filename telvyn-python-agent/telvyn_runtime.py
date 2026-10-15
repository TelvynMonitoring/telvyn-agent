import http.client
import json
import os
import platform
import re
import socket
import sys
import threading
import queue
from importlib.metadata import version
from urllib.parse import urlencode, urlsplit

from opentelemetry.sdk.trace import SpanProcessor


SDK_VERSION = version("telvyn-python-agent")


def flag(name):
    return {"value": str(os.environ.get(name) == "true").lower(),
        "source": "environment" if name in os.environ else "default"}


def number(name, fallback):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return {"value": str(fallback), "source": "default"}
    value = "invalid"
    if len(raw) <= 128 and re.fullmatch(r"[+-]?[0-9]+", raw):
        parsed = int(raw)
        if -(1 << 63) <= parsed < (1 << 63):
            value = str(parsed)
    return {"value": value, "source": "environment"}


def configurations(security=None):
    return [
        {"name": "telvyn.profiling.enabled", **flag("TELVYN_PROFILING_ENABLED")},
        {"name": "telvyn.profiling.wall.enabled", **flag("TELVYN_PROFILE_WALL_ENABLED")},
        {"name": "telvyn.profiling.alloc.enabled", **flag("TELVYN_PROFILE_ALLOCATION_ENABLED")},
        {"name": "telvyn.profiling.period.ms", **number("TELVYN_PROFILING_PERIOD_MS", 10)},
        {"name": "telvyn.profiling.flush.sec", **number("TELVYN_PROFILING_FLUSH_SEC", 15)},
        {"name": "telvyn.security.attack.state", "source": "runtime",
            "value": security.attack_state if security else "error" if os.environ.get("TELVYN_SECURITY_ENABLED") == "true" else "disabled"},
        {"name": "telvyn.security.iast.state", "source": "runtime",
            "value": security.iast_state if security else "error" if os.environ.get("TELVYN_IAST_ENABLED") == "true" else "disabled"},
    ]


class RuntimeTransport:
    def __init__(self, resource):
        raw = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
        if any(ord(char) <= 32 or ord(char) == 127 for char in raw):
            raise ValueError("Invalid collector endpoint")
        endpoint = urlsplit(raw)
        if (endpoint.scheme not in ("http", "https") or not endpoint.hostname
                or endpoint.username is not None or endpoint.password is not None
                or endpoint.query or endpoint.fragment):
            raise ValueError("Invalid collector endpoint")
        self._connection_type = http.client.HTTPSConnection if endpoint.scheme == "https" else http.client.HTTPConnection
        self._host, self._port = endpoint.hostname, endpoint.port
        self._path = endpoint.path.rstrip("/") + "/v1/"
        attributes = resource.attributes
        service = attributes.get("service.name")
        if not service or service == "unknown_service" or service.startswith("unknown_service:"):
            raise ValueError("Runtime reporting requires service identity")
        self.identity = dict(service=service,
            host=os.environ.get("POD_NAME") or attributes.get("host.name") or socket.gethostname(),
            environment=attributes.get("deployment.environment.name") or attributes.get("deployment.environment"),
            service_version=attributes.get("service.version"))

    def request(self, signal, report=None):
        if signal not in ("sdk/configuration", "profile", "security/events", "security/iast", "debug", "debug/config", "debug/config/applied"):
            raise ValueError("Unsupported runtime signal")
        body, path = None, self._path + signal
        if report is not None:
            body = json.dumps({**self.identity, **report}, allow_nan=False).encode("utf-8")
            limit = 1024 * 1024 if signal == "profile" else 32768 if signal == "security/iast" else 8192 if signal == "security/events" else 65536
            if len(body) > limit:
                raise ValueError("Runtime report too large")
        else:
            if signal != "debug/config":
                raise ValueError("Unsupported runtime read")
            path += "?" + urlencode(dict(service=self.identity["service"],
                env=self.identity["environment"] or "", version=self.identity["service_version"] or ""))
        connection = self._connection_type(self._host, self._port, timeout=5)
        try:
            connection.request("POST" if body is not None else "GET", path, body, {"Content-Type": "application/json"})
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise ValueError("Runtime delivery rejected")
            if body is None:
                raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError("Runtime response too large")
                return json.loads(raw)
        finally:
            connection.close()


class ConfigurationReporter(SpanProcessor):
    def __init__(self, resource):
        self.transport = RuntimeTransport(resource)
        self._closed = False
        self._pending = queue.Queue(maxsize=32)
        self.security = None
        self.profiler = None
        self.debugger = None
        from telvyn_security import Security
        from telvyn_profiler import Profiler
        from telvyn_debugger import Debugger
        for attribute, factory in (("security", Security), ("profiler", Profiler), ("debugger", Debugger)):
            try:
                setattr(self, attribute, factory(self))
            except Exception:
                print("[Telvyn] Runtime sensor could not start: " + attribute, file=sys.stderr)
        self._start()
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork)

    def _start(self):
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="telvyn-sdk-configuration", daemon=True)
        self._thread.start()

    def _after_fork(self):
        # Gunicorn preload copies the reporter but not its thread or a usable Event lock.
        if not self._closed:
            self._pending = queue.Queue(maxsize=32)
            self._start()
            for sensor in (self.security, self.profiler, self.debugger):
                if sensor:
                    sensor.after_fork()

    def send(self, signal, report):
        if self._closed:
            return
        try:
            self._pending.put_nowait((signal, report))
        except queue.Full:
            print("[Telvyn] Runtime delivery queue is full; report omitted.", file=sys.stderr)

    def _run(self):
        import time
        next_configuration = 0
        while not self._stop.is_set():
            try:
                if time.monotonic() >= next_configuration:
                    next_configuration = time.monotonic() + 60
                    self.transport.request("sdk/configuration", dict(sdk_name="telvyn-python-agent",
                        sdk_version=SDK_VERSION, runtime=platform.python_version(), configurations=configurations(self.security)))
                try:
                    signal, report = self._pending.get(timeout=0.5)
                except queue.Empty:
                    continue
                self.transport.request(signal, report)
            except Exception:
                # Never print the URL, response body or environment values on delivery failure.
                print("[Telvyn] Runtime delivery failed.", file=sys.stderr)

    def shutdown(self):
        self._closed = True
        for sensor in (self.security, self.profiler, self.debugger):
            if sensor:
                sensor.stop()
        self._stop.set()
        self._thread.join(timeout=5)
