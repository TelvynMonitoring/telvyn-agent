"""Initialize the same Telvyn distro when mounted by the admission controller."""
import importlib.machinery
import importlib.util
import os
import sys

# Preserve an application's own sitecustomize after this bootstrap directory.
paths = [path for path in sys.path if os.path.realpath(path) != os.path.dirname(__file__)]
original = importlib.machinery.PathFinder.find_spec("sitecustomize", paths)
if original is not None and original.loader is not None:
    original.loader.exec_module(importlib.util.module_from_spec(original))

if os.environ.get("OTEL_SDK_DISABLED", "").lower() != "true":
    try:
        if sys.version_info < (3, 10):
            raise RuntimeError("unsupported Python version")
        from opentelemetry.instrumentation.auto_instrumentation import initialize
        initialize()
    except Exception:
        print("[Telvyn] Instrumentation could not start; application startup continues.", file=sys.stderr)
