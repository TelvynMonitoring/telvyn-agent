import functools
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import tracemalloc
import uuid

from telvyn_context import requests


def int_conf(name, default, minimum, maximum):
    raw = os.environ.get(name, "").strip()
    if not re.fullmatch(r"[+-]?[0-9]{1,11}", raw):
        return default
    value = int(raw)
    return min(maximum, max(minimum, value)) if -(1 << 31) <= value < (1 << 31) else default


# Chamada a cada amostra para cada quadro da pilha: sem cache, Path.resolve() fazia chamadas ao sistema de arquivos
# por quadro dentro do gancho de CPU e a aplicação não terminava de subir. O resultado só depende do arquivo e da raiz.
@functools.lru_cache(maxsize=8192)
def source_file(filename, root):
    try:
        relative = Path(filename).resolve().relative_to(root).as_posix()
        return relative if re.fullmatch(r"(?:[\w.-]+/)*[\w.-]+\.py", relative, re.ASCII) else None
    except (ValueError, OSError):
        return None


def thread_cpu_ns(native_id):
    """Tempo de CPU da thread em ns (Linux), lido sem gancho nenhum na aplicação."""
    try:
        with open(f"/proc/self/task/{native_id}/schedstat", "rb") as stat:
            return int(stat.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def stack_frames(frame, root, lines=True):
    frames, numbers = [], []
    while frame is not None and len(frames) < 256:
        filename = source_file(frame.f_code.co_filename, root)
        if filename:
            name = re.sub(r"[^\w.]", "_", frame.f_code.co_name, flags=re.ASCII)
            frames.append(filename + "#" + name)
            numbers.append(frame.f_lineno if lines and frame.f_lineno > 0 else -1)
        frame = frame.f_back
    return ";".join(reversed(frames)), tuple(reversed(numbers))


class Profiler:
    def __init__(self, runtime):
        self.runtime = runtime
        self.enabled = os.environ.get("TELVYN_PROFILING_ENABLED") == "true"
        self.closed = False
        self.owns_heap = False
        self.allocations = None
        if not self.enabled:
            return
        root = os.environ.get("TELVYN_PROFILE_SOURCE_ROOT")
        if not root:
            raise ValueError("Profiling requires a source root")
        self.root = Path(root).resolve()
        self.period = int_conf("TELVYN_PROFILING_PERIOD_MS", 10, 1, 1000)
        self.flush = int_conf("TELVYN_PROFILING_FLUSH_SEC", 15, 2, 600)
        self.wall = os.environ.get("TELVYN_PROFILE_WALL_ENABLED") == "true"
        # Heap vivo rastreia toda alocação (tracemalloc não amostra): opt-in próprio, como alocação no Java/Node.
        self.heap = os.environ.get("TELVYN_PROFILE_HEAP_ENABLED") == "true"
        # CPU: a thread do profiler amostra as pilhas e conta só as threads que usaram CPU no período.
        # Um gancho por chamada (sys.setprofile) custava uma chamada de sistema por função e a aplicação não subia.
        self.cpu = thread_cpu_ns(threading.get_native_id()) is not None
        self._reset()
        if self.heap and not tracemalloc.is_tracing():
            tracemalloc.start(64)
            self.owns_heap = True
        if not self.cpu:
            print("[Telvyn] CPU profiler unavailable: per-thread CPU time requires Linux /proc.", file=sys.stderr)
        if os.environ.get("TELVYN_PROFILE_ALLOCATION_ENABLED") == "true":
            self._start_allocations()
        self._start()

    def _start_allocations(self):
        try:
            from telvyn_allocation import Allocations
            self.allocations = Allocations(self)
        except Exception:
            print("[Telvyn] Allocation profiler unavailable; install the compatible allocation extra.", file=sys.stderr)

    def _reset(self):
        self.lock = threading.RLock()
        self.samples = {"cpu": {}, "wall": {}}
        self.cpu_seen = {}
        # Depois de fork o Python mantém na thread que forkou o id nativo do processo pai; o filho registra o real.
        self.native_ids = {}
        self.instance = uuid.uuid4().hex
        self.from_ms = time.time_ns() // 1000000

    def _start(self):
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="telvyn-profiler", daemon=True)
        self.thread.start()

    def _add(self, kind, stack, lines, weight, context=None):
        if not stack or len(stack) > 16000:
            return
        key = (stack, lines, context)
        with self.lock:
            samples = self.samples[kind]
            if key in samples or len(samples) < 4096:
                samples[key] = samples.get(key, 0) + weight

    def _cpu_tick(self, frames, own):
        seen = {}
        for thread in threading.enumerate():
            native_id = self.native_ids.get(thread.ident, thread.native_id)
            if thread.ident == own or native_id is None or thread.name.startswith("telvyn-"):
                continue
            used = thread_cpu_ns(native_id)
            if used is None:
                continue
            seen[thread.ident] = used
            previous = self.cpu_seen.get(thread.ident)
            frame = frames.get(thread.ident)
            # Uma amostra por período em que a thread esteve na CPU; nunca transforma intervalos perdidos em amostras.
            if previous is None or frame is None or used - previous < self.period * 500000:
                continue
            stack, lines = stack_frames(frame, self.root, lines=False)
            self._add("cpu", stack, lines, 1, requests.thread_context(thread.ident))
        self.cpu_seen = seen

    def _run(self):
        deadline = time.monotonic() + self.flush
        while not self.stop_event.wait(self.period / 1000):
            try:
                own = threading.get_ident()
                if self.cpu:
                    self._cpu_tick(sys._current_frames(), own)
                if self.wall:
                    for ident, frame in sys._current_frames().items():
                        if ident != own:
                            stack, lines = stack_frames(frame, self.root)
                            self._add("wall", stack, lines, self.period * 1000000)
                if time.monotonic() >= deadline:
                    self._flush()
                    deadline = time.monotonic() + self.flush
            except Exception:
                print("[Telvyn] Profile window omitted after collection failure.", file=sys.stderr)

    def _emit(self, kind, samples, from_ms, seconds):
        folded, origins, links = {}, [], {}
        size = 0
        for (stack, lines, context), weight in samples.items():
            if weight <= 0:
                continue
            origin = dict(folded=stack, weight=weight, lines=list(lines))
            cost = len(json.dumps(origin))
            if size + cost > 250000 or len(origins) >= 4096:
                continue
            size += cost
            folded[stack] = folded.get(stack, 0) + weight
            origins.append(origin)
            if context:
                links.setdefault(context, {})[stack] = links.setdefault(context, {}).get(stack, 0) + weight
        if not folded:
            return
        identity = self.runtime.transport.identity
        report = dict(service=identity["service"], host=identity["host"], env=identity["environment"],
            version=identity["service_version"], runtime="python", source="python", profile_instance=self.instance,
            profile_type=kind, period_ms=self.period if kind == "cpu" else 0,
            window_start_unix_ms=from_ms, window_seconds=seconds,
            folded="\n".join(f"{stack} {weight}" for stack, weight in folded.items()),
            details={"line_stacks": origins})
        sample_links, link_chars = [], 0
        for (trace_id, span_id, endpoint), stacks in links.items():
            text = "\n".join(f"{stack} {weight}" for stack, weight in stacks.items())
            if len(sample_links) >= 128 or link_chars + len(text) > 200000:
                break
            row = dict(trace_id=trace_id, span_id=span_id, folded=text)
            if isinstance(endpoint, str) and endpoint and len(endpoint) <= 1024:
                row["endpoint"] = endpoint
            sample_links.append(row)
            link_chars += len(text)
        if sample_links:
            report["sample_links"] = sample_links
        self.runtime.send("profile", report)

    def _flush(self):
        now = time.time_ns() // 1000000
        with self.lock:
            samples, self.samples = self.samples, {"cpu": {}, "wall": {}}
            from_ms, self.from_ms = self.from_ms, now
        seconds = max(1, (now - from_ms) // 1000)
        for kind, values in samples.items():
            self._emit(kind, values, from_ms, seconds)
        if self.heap and tracemalloc.is_tracing():
            live = {}
            for statistic in tracemalloc.take_snapshot().statistics("traceback")[:4096]:
                frames, lines = [], []
                for frame in statistic.traceback:
                    filename = source_file(frame.filename, self.root)
                    if filename:
                        frames.append(filename)
                        lines.append(frame.lineno if frame.lineno > 0 else -1)
                if frames:
                    key = (";".join(frames), tuple(lines), None)
                    live[key] = live.get(key, 0) + statistic.size
            self._emit("heap", live, from_ms, seconds)

    def after_fork(self):
        if self.enabled and not self.closed:
            self._reset()
            self.native_ids[threading.get_ident()] = threading.get_native_id()
            self._start()
            # Native allocator hooks are not resumed in a forked child from an active capture.
            if self.allocations:
                self.allocations = None
                print("[Telvyn] Allocation profiler disabled after fork; initialize SDK in the worker.", file=sys.stderr)

    def stop(self):
        self.closed = True
        if not self.enabled:
            return
        self.stop_event.set()
        if self.allocations:
            self.allocations.stop()
        self.thread.join(timeout=5)
        if self.owns_heap:
            tracemalloc.stop()
