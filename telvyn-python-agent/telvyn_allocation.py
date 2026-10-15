import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time


class Allocations:
    """Bounded capture windows; weights are observed allocation bytes, including freed blocks."""

    def __init__(self, profiler):
        if sys.getprofile() is not None or threading.getprofile() is not None:
            raise ValueError("Allocation profiler requires an exclusive profile hook")
        import memray
        self.memray = memray
        self.profiler = profiler
        self.pid = os.getpid()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="telvyn-allocations", daemon=True)
        self.thread.start()

    def _run(self):
        from telvyn_profiler import source_file
        try:
            while not self.stop_event.is_set():
                # Private directory: capture metadata includes local paths and command-line arguments.
                with tempfile.TemporaryDirectory(prefix="telvyn-allocation-") as directory:
                    path = Path(directory) / "capture.bin"
                    destination = self.memray.FileDestination(path, compress_on_exit=False)
                    start = time.time_ns() // 1000000
                    deadline = time.monotonic() + self.profiler.flush
                    overflow = False
                    with self.memray.Tracker(destination=destination, native_traces=False,
                            trace_python_allocators=True, follow_fork=False):
                        while not self.stop_event.wait(0.1) and time.monotonic() < deadline:
                            if path.stat().st_size > 16 * 1024 * 1024:
                                overflow = True
                                break
                    end = time.time_ns() // 1000000
                    if self.stop_event.is_set():
                        return
                    if overflow or path.stat().st_size > 16 * 1024 * 1024:
                        # Do not publish a truncated capture as a complete window.
                        raise ValueError("Allocation capture exceeded limit")
                    samples = {}
                    with self.memray.FileReader(path, max_memory_records=1000) as reader:
                        for count, record in enumerate(reader.get_allocation_records()):
                            if count >= 1000000:
                                raise ValueError("Allocation record limit exceeded")
                            if record.allocator in (self.memray.AllocatorType.FREE,
                                    self.memray.AllocatorType.PYMALLOC_FREE, self.memray.AllocatorType.MUNMAP) or record.size <= 0:
                                continue
                            frames, lines = [], []
                            for function, filename, line in reversed(record.stack_trace(max_stacks=256)):
                                file = source_file(filename, self.profiler.root)
                                if file:
                                    frames.append(file + "#" + re.sub(r"[^\w.]", "_", function, flags=re.ASCII))
                                    lines.append(line if line > 0 else -1)
                            if not frames:
                                continue
                            stack = ";".join(frames)
                            key = (stack, tuple(lines), None)
                            if len(stack) <= 16000 and (key in samples or len(samples) < 4096):
                                samples[key] = samples.get(key, 0) + record.size
                    self.profiler._emit("alloc", samples, start, max(1, (end - start + 999) // 1000))
                # Parsing and this wait are gaps, never extrapolated into allocation totals.
                self.stop_event.wait(0.1)
        except Exception:
            print("[Telvyn] Allocation profiler unavailable or capture omitted; collection stopped.", file=sys.stderr)

    def stop(self):
        self.stop_event.set()
        if os.getpid() == self.pid:
            self.thread.join(timeout=5)
