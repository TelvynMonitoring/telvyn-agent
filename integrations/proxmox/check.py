"""Read-only Proxmox VE cluster snapshot through its HTTPS JSON API."""

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from common import metric, result, timestamp


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(request.full_url, code, "redirect_rejected", headers, fp)


class ProxmoxClient:
    def __init__(self, params):
        url = urllib.parse.urlsplit(params["endpoint"].rstrip("/"))
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("invalid endpoint")
        path = url.path.rstrip("/")
        if path not in ("", "/api2/json"):
            raise ValueError("invalid endpoint path")
        self.base = urllib.parse.urlunsplit(("https", url.netloc, "/api2/json", "", ""))
        self.authorization = "PVEAPIToken=%s=%s" % (params["token_id"], params["token_secret"])
        context = ssl.create_default_context(cafile=params.get("ca_file") or None)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), _NoRedirect()
        )
        self.timeout = min(max(float(params.get("timeout_seconds", 10)), 1), 30)

    def get(self, path):
        request = urllib.request.Request(
            self.base + path,
            headers={"Authorization": self.authorization, "Accept": "application/json"},
            method="GET",
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            payload = response.read(8_388_609)
        if len(payload) > 8_388_608:
            raise ValueError("response too large")
        data = json.loads(payload)
        if not isinstance(data, dict) or "data" not in data:
            raise ValueError("invalid response")
        return data["data"]


def collect(instance_id, params, static_tags, client=None):
    try:
        client = client or ProxmoxClient(params)
        rows = client.get("/cluster/resources")
        if not isinstance(rows, list):
            raise ValueError("invalid resources")
    except (KeyError, ValueError, TypeError):
        return result(status="error", error="invalid_configuration_or_response")
    except Exception:
        return result(status="error", error="proxmox_api_unavailable")

    metrics, inventory = [], []
    counts = {"node": 0, "qemu": 0, "lxc": 0, "storage": 0}
    observed = timestamp()  # /cluster/resources does not provide a per-value timestamp.
    mapping = {
        "cpu": ("cpu.usage", "fraction", "gauge"),
        "mem": ("memory.used", "byte", "gauge"),
        "maxmem": ("memory.capacity", "byte", "gauge"),
        "disk": ("disk.used", "byte", "gauge"),
        "maxdisk": ("disk.capacity", "byte", "gauge"),
        "diskread": ("disk.read", "byte", "count"),
        "diskwrite": ("disk.write", "byte", "count"),
        "netin": ("network.received", "byte", "count"),
        "netout": ("network.sent", "byte", "count"),
        "uptime": ("uptime", "second", "gauge"),
    }
    for row in rows:
        if not isinstance(row, dict) or row.get("type") not in counts:
            continue
        kind = row["type"]
        resource_id = row.get("id")
        if not isinstance(resource_id, str) or not resource_id:
            continue
        counts[kind] += 1
        tags = {**static_tags, "provider": "proxmox", "resource_type": kind, "instance_id": instance_id}
        inventory.append({
            "resource_id": resource_id, "type": kind, "name": str(row.get("name") or resource_id),
            "state": str(row.get("status") or "unknown"),
            "parent_id": "node/" + row["node"] if kind != "node" and isinstance(row.get("node"), str) else None,
            "observed_at": observed,
        })
        up = row.get("status") in ("online", "running", "available")
        metrics.append(metric("telvyn.proxmox.up", int(up), "boolean", resource_id, tags, observed))
        # Powered-off VMs remain in inventory; their missing runtime counters are not fabricated.
        for key, (suffix, unit, value_type) in mapping.items():
            if kind in ("qemu", "lxc") and not up:
                break
            if key in row:
                item = metric("telvyn.proxmox." + suffix, row[key], unit, resource_id, tags, observed, value_type)
                if item is not None:
                    metrics.append(item)
    coverage = {
        "resources": counts, "timestamp_source": "collector_after_api_response",
        "version_endpoint": "not_requested", "metric_scope": "cluster_resources_snapshot",
    }
    status, error = "ok", None
    if str(params.get("include_version", "false")).lower() == "true":
        try:
            version = client.get("/version")
            coverage["version_endpoint"] = "available" if isinstance(version, dict) else "invalid"
        except Exception:
            coverage["version_endpoint"] = "unavailable"
            status, error = "partial", "optional_version_unavailable"
    return result(metrics, inventory, status, coverage, error)
