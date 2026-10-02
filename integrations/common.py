"""Protocol v1 helpers shared by the external checks."""

import math
from datetime import datetime, timezone


def timestamp(value=None):
    if value is None:
        value = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def metric(name, value, unit, resource_id, tags, observed_at, kind="gauge"):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return {
        "name": name, "value": value, "type": kind, "unit": unit,
        "timestamp": observed_at, "resource_id": resource_id, "tags": tags,
    }


def result(metrics=None, inventory=None, status="ok", coverage=None, error=None):
    return {
        "protocol_version": 1, "metrics": metrics or [], "inventory": inventory or [],
        "status": status, "coverage": coverage or {}, "error": error,
    }
