import math
import inspect
import os
from pathlib import Path
import re
import sys
import threading
import time
import uuid

from opentelemetry import trace, metrics
from telvyn_profiler import source_file, stack_frames


def scalar(name, value):
    if re.search(r"password|secret|token|cookie|auth|credential|key", name, re.I):
        return "[redacted]"
    if value is None or type(value) in (bool, int):
        return value if type(value) is not int or value.bit_length() < 64 else "[redacted]"
    if type(value) is float and math.isfinite(value):
        return value
    return "[redacted]"


class Debugger:
    def __init__(self, runtime):
        self.runtime = runtime
        self.enabled = os.environ.get("TELVYN_DEBUGGER_ENABLED") == "true"
        self.closed = False
        if not self.enabled:
            return
        root = os.environ.get("TELVYN_PROFILE_SOURCE_ROOT")
        if not root or sys.gettrace() is not None or threading.gettrace() is not None:
            raise ValueError("Debugger requires source root and exclusive trace hook")
        self.root = Path(root).resolve()
        self.policies = {}
        self.observed = {}
        self.last_capture = {}
        self.updated = 0
        self.session = uuid.uuid4().hex
        self.frames = {}
        self.errors = []
        self.instruments = {}
        self.meter = metrics.get_meter("telvyn.debugger")
        threading.settrace(self._trace)
        sys.settrace(self._trace)
        self._start()

    def _start(self):
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._refresh, name="telvyn-debugger", daemon=True)
        self.thread.start()

    def _matches(self, condition, arguments, duration, exception):
        if not condition:
            return True
        source = condition.get("source")
        index = condition.get("arg_index")
        actual = duration if source == "duration_ms" else exception if source == "exception" else arguments[index] if type(index) is int and 0 <= index < len(arguments) else None
        expected = condition.get("bool") if source == "exception" else condition.get("number")
        if source == "exception":
            if type(actual) is not bool or type(expected) is not bool:
                return False
        elif type(actual) not in (int, float) or type(expected) not in (int, float) or not math.isfinite(actual) or not math.isfinite(expected):
            return False
        return {"gt": actual > expected, "gte": actual >= expected, "lt": actual < expected,
            "lte": actual <= expected, "eq": actual == expected, "ne": actual != expected}.get(condition.get("operator"), False)

    @staticmethod
    def _valid_policy(policy, line):
        if not isinstance(policy, dict) or set(policy) - {"action", "metric_name", "condition", "value_source", "value_arg_index"}:
            return False
        action = policy.get("action")
        if action not in ("snapshot", "count", "duration", "gauge"):
            return False
        if action != "snapshot" and not re.fullmatch(r"debug\.[a-z][a-z0-9_.]{0,100}", policy.get("metric_name") or ""):
            return False
        if action == "snapshot" and policy.get("metric_name") is not None:
            return False
        index = policy.get("value_arg_index")
        if action == "gauge":
            if policy.get("value_source") not in ("arg", "returned"):
                return False
            if policy["value_source"] == "arg" and (type(index) is not int or not 0 <= index <= 255):
                return False
            if policy["value_source"] == "returned" and index is not None:
                return False
        elif policy.get("value_source") is not None or index is not None:
            return False
        condition = policy.get("condition")
        if line and (action not in ("snapshot", "count") or condition is not None):
            return False
        if condition is None:
            return True
        if not isinstance(condition, dict) or set(condition) - {"source", "operator", "arg_index", "number", "bool"}:
            return False
        source, operator = condition.get("source"), condition.get("operator")
        if source not in ("arg", "duration_ms", "exception") or operator not in ("gt", "gte", "lt", "lte", "eq", "ne"):
            return False
        if source == "exception":
            return (operator in ("eq", "ne") and type(condition.get("bool")) is bool
                and condition.get("number") is None and condition.get("arg_index") is None)
        number, index = condition.get("number"), condition.get("arg_index")
        return (type(number) in (int, float) and math.isfinite(number) and condition.get("bool") is None
            and (type(index) is int and 0 <= index <= 255 if source == "arg" else index is None))

    def _snapshot(self, target, frame, phase, duration=None, error=None, returned=None):
        now = time.monotonic()
        if now - self.last_capture.get(target, -1) < 1:
            return
        if target not in self.last_capture and len(self.last_capture) >= 400:
            return
        self.last_capture[target] = now
        local = {key: scalar(key, value) for key, value in list(frame.f_locals.items())[:20]}
        stack, lines = stack_frames(frame, self.root)
        span = trace.get_current_span().get_span_context()
        snapshot = dict(method=target, phase=phase, captured_unix_ms=time.time_ns() // 1000000,
            payload=dict(locals=local, source_line=frame.f_lineno,
                stack=[f"{method}:{line}" for method, line in list(zip(stack.split(";"), lines))[-20:]]))
        if duration is not None:
            snapshot["duration_ms"] = duration
            snapshot["payload"]["returned"] = scalar("returned", returned)
        if error is not None:
            # Only exception class metadata is exported; no exception message or repr.
            snapshot.update(error=re.sub(r"[^A-Za-z0-9_.]", "_", type(error).__name__)[:128], error_id=uuid.uuid4().hex)
        if span.is_valid:
            snapshot.update(trace_id=f"{span.trace_id:032x}", span_id=f"{span.span_id:016x}")
        self.runtime.send("debug", {"snapshots": [snapshot]})

    def _observe(self, target, policy, frame, returned, duration, exception, arguments=()):
        if not self._matches(policy.get("condition"), arguments, duration, exception):
            return
        action = policy["action"]
        if action == "snapshot":
            self._snapshot(target, frame, "exit", duration, returned=returned)
            return
        key = (action, policy["metric_name"])
        instrument = self.instruments.get(key)
        if instrument is None:
            if len(self.instruments) >= 200:
                return
            instrument = (self.meter.create_counter(key[1]) if action == "count" else
                self.meter.create_histogram(key[1], unit="ms") if action == "duration" else self.meter.create_gauge(key[1]))
            self.instruments[key] = instrument
        if action == "count":
            instrument.add(1)
        elif action == "duration":
            instrument.record(duration)
        else:
            index = policy.get("value_arg_index", -1)
            value = returned if policy.get("value_source") == "returned" else arguments[index] if type(index) is int and 0 <= index < len(arguments) else None
            if type(value) in (int, float) and math.isfinite(value):
                instrument.set(value)

    def _trace(self, frame, event, arg):
        ident = id(frame)
        if self.closed or time.monotonic() - self.updated > 60:
            self.frames.pop(ident, None)
            return None
        try:
            file = source_file(frame.f_code.co_filename, self.root)
            name = getattr(frame.f_code, "co_qualname", frame.f_code.co_name)
            if not file or not re.fullmatch(r"[A-Za-z_][\w.]*", name, re.ASCII):
                return None
            target = file + "#" + name
            # Suspensions/resumptions are not complete calls: do not emit misleading durations or counts.
            if frame.f_code.co_flags & (inspect.CO_GENERATOR | inspect.CO_COROUTINE | inspect.CO_ASYNC_GENERATOR):
                return None
            policy = self.policies.get(target)
            error_scope = any(target.startswith(prefix) if "#" in prefix else target.startswith(prefix + "#") for prefix in self.errors)
            if event == "call":
                if policy:
                    self.observed[target] = min(1000000000000, self.observed.get(target, 0) + 1)
                    if len(self.frames) < 4096:
                        names = frame.f_code.co_varnames[:frame.f_code.co_argcount]
                        arguments = tuple(scalar(name, frame.f_locals.get(name)) for name in names[:256])
                        self.frames[ident] = (time.perf_counter_ns(), policy, False, arguments)
            elif event == "exception":
                state = self.frames.get(ident)
                if state:
                    self.frames[ident] = (state[0], state[1], True, state[3])
                if error_scope:
                    self._snapshot(target, frame, "exception", error=arg[1])
            elif event == "line":
                selected = target + "@" + str(frame.f_lineno)
                line_policy = self.policies.get(selected)
                if line_policy:
                    self.observed[selected] = min(1000000000000, self.observed.get(selected, 0) + 1)
                    if line_policy["action"] == "snapshot":
                        self._snapshot(selected, frame, "line")
                    else:
                        self._observe(selected, line_policy, frame, None, 0, False)
            elif event == "return":
                state = self.frames.pop(ident, None)
                if state and policy == state[1]:
                    self._observe(target, policy, frame, arg, (time.perf_counter_ns() - state[0]) / 1000000, state[2], state[3])
            return self._trace if policy or error_scope or any(key.startswith(target + "@") for key in self.policies) else None
        except Exception:
            self.frames.pop(ident, None)
            return None

    def _refresh(self):
        while not self.stop_event.is_set():
            try:
                config = self.runtime.transport.request("debug/config")
                rows = config.get("policies")
                version = config.get("config_version", "")
                if not isinstance(rows, list) or len(rows) > 200 or not re.fullmatch(r"[a-f0-9]{64}", version):
                    raise ValueError("Invalid debugger configuration")
                policies, rejected = {}, set()
                for row in rows:
                    target = row.get("target", "")
                    policy = row.get("policy") or {"action": "snapshot"}
                    valid = (re.fullmatch(r"(?:[\w.-]+/)*[\w.-]+\.py#[A-Za-z_][\w.]*(?:@[1-9][0-9]{0,5})?", target, re.ASCII)
                        and ".." not in target.split("#")[0].split("/")
                        and self._valid_policy(policy, "@" in target))
                    if valid:
                        policies[target] = policy
                    else:
                        rejected.add(target)
                self.policies = policies
                self.observed = {key: value for key, value in self.observed.items() if key in policies}
                self.last_capture = {key: value for key, value in self.last_capture.items() if key in policies}
                errors = config.get("exceptions", [])
                if not isinstance(errors, list) or len(errors) > 200:
                    raise ValueError("Invalid exception scopes")
                self.errors = [prefix for prefix in errors if isinstance(prefix, str)
                    and re.fullmatch(r"(?:[\w.-]+/)*[\w.-]+\.py(?:#[A-Za-z_][\w.]*)?", prefix, re.ASCII)
                    and ".." not in prefix.split("#")[0].split("/")]
                self.updated = time.monotonic()
                self.runtime.send("debug/config/applied", dict(config_version=version, session=self.session,
                    statuses=[dict(target=row["target"], status="error" if row["target"] in rejected else
                        "instrumented" if self.observed.get(row["target"]) else "unmatched",
                        instrumented_methods=1 if self.observed.get(row["target"]) else 0,
                        observed_calls=self.observed.get(row["target"], 0)) for row in rows]))
            except Exception:
                if time.monotonic() - self.updated > 60:
                    self.policies = {}
                    self.errors = []
                    self.frames = {}
                print("[Telvyn] Debugger configuration refresh failed.", file=sys.stderr)
            if self.stop_event.wait(15):
                return

    def after_fork(self):
        if self.enabled and not self.closed:
            self.policies, self.observed, self.last_capture = {}, {}, {}
            self.frames, self.errors = {}, []
            self.updated = 0
            self.session = uuid.uuid4().hex
            self._start()

    def stop(self):
        self.closed = True
        if self.enabled:
            self.policies = {}
            self.frames, self.errors = {}, []
            self.stop_event.set()
            self.thread.join(timeout=5)
            if sys.gettrace() == self._trace:
                sys.settrace(None)
            if threading.gettrace() == self._trace:
                threading.settrace(None)
