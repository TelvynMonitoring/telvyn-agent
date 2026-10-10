"""Read-only Proxmox VE cluster snapshot through its HTTPS JSON API."""

import json
import math
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from common import metric, result, timestamp


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        value = float(value)
        return value if math.isfinite(value) and value >= 0 else None
    except (ValueError, OverflowError):
        return None


def _fields(data, keys):
    """Allowlist API metadata, never forward raw config, comments or errors."""
    if not isinstance(data, dict):
        return {}
    return {key: data[key] for key in keys if key in data and (
        isinstance(data[key], str) and len(data[key]) <= 256 and not any(c in data[key] for c in "\r\n\0")
        or isinstance(data[key], (int, float, bool)) and math.isfinite(data[key]))}


def _node_details(client, node, resource_id, tags, observed, metrics, inventory):
    # Official schemas: pve-manager/PVE/API2/{Nodes,Network,NodeConfig}.pm;
    # pve-storage/src/PVE/API2/Disks.pm. All calls are read-only GETs.
    base = "/nodes/" + urllib.parse.quote(node, safe="")
    details = {"observed_at": observed, "endpoints": {}}
    endpoints = {"status": dict, "rrddata?timeframe=hour&cf=AVERAGE": list,
                 "network": list, "disks/list": list, "config": dict}

    def emit(suffix, value, unit, rid=resource_id, at=observed, metric_tags=tags):
        value = _number(value)
        if value is not None:
            metrics.append(metric("telvyn.proxmox." + suffix, value, unit, rid, metric_tags, at))

    for endpoint, expected in endpoints.items():
        key = endpoint.split("?")[0]
        try:
            data = client.get(base + "/" + endpoint)
            if not isinstance(data, expected):
                raise ValueError("invalid response")
            details["endpoints"][key] = "available"
            if key == "status":
                info = _fields(data, ("pveversion", "kversion"))
                for field, keys in {
                    "cpuinfo": ("model", "cores", "cpus", "sockets", "mhz"),
                    "current-kernel": ("sysname", "release", "version", "machine"),
                    "boot-info": ("mode", "secureboot"),
                }.items():
                    info[field] = _fields(data.get(field), keys)
                details["information"] = info
                emit("cpu.logical", info["cpuinfo"].get("cpus"), "count")
                for field, prefix, keys in (
                    ("memory", "memory", ("free", "available")),
                    ("swap", "swap", ("used", "total", "free")),
                    ("rootfs", "rootfs", ("used", "total", "free", "avail")),
                ):
                    values = data.get(field)
                    if isinstance(values, dict):
                        for name in keys:
                            emit(prefix + "." + name, values.get(name), "byte")
                load = data.get("loadavg")
                if isinstance(load, list):
                    for minutes, value in zip((1, 5, 15), load):
                        emit("cpu.load" + str(minutes), value, "count")
            elif key == "rrddata":
                # netin/netout are RRD DERIVE values, already bytes/s, aggregated
                # over physical NICs by pvestatd. Never reuse byte/count names.
                now = datetime.fromisoformat(observed.replace("Z", "+00:00")).timestamp()
                samples = [row for row in data if isinstance(row, dict)
                           and _number(row.get("time")) is not None
                           and now - 300 <= float(row["time"]) <= now]
                samples.sort(key=lambda row: float(row["time"]), reverse=True)
                found = 0
                for field, suffix in (("netin", "received"), ("netout", "sent")):
                    row = next((row for row in samples if _number(row.get(field)) is not None), None)
                    if row is not None:
                        at = timestamp(datetime.fromtimestamp(float(row["time"]), timezone.utc))
                        emit("network." + suffix + ".rate", row[field], "byte_per_second", at=at)
                        found += 1
                if found != 2:
                    details["endpoints"][key] = "missing_fresh_samples"
            elif key in ("network", "disks/list"):
                is_network = key == "network"
                kind = "network_interface" if is_network else "physical_disk"
                items = []
                for row in data:
                    if not isinstance(row, dict):
                        details["endpoints"][key] = "invalid"
                        continue
                    name = row.get("iface" if is_network else "devpath")
                    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._:/-]{1,80}", name):
                        details["endpoints"][key] = "invalid"
                        continue
                    rid = resource_id + "/" + kind + "/" + name.lstrip("/")
                    if len(rid) > 128:
                        details["endpoints"][key] = "invalid"
                        continue
                    keys = ("iface", "type", "active", "autostart", "address", "netmask", "cidr",
                            "gateway", "address6", "netmask6", "cidr6", "gateway6", "method", "method6",
                            "mtu", "bridge_ports", "bridge_vlan_aware", "bridge_vids", "bond_slaves",
                            "bond_mode", "vlan-id", "vlan-raw-device") if is_network else (
                            "devpath", "size", "model", "vendor", "serial", "wwn", "health", "type",
                            "used", "gpt", "mounted")
                    info = _fields(row, keys)
                    info["resource_id"] = rid
                    items.append(info)
                    # Network 'active' is not a carrier/speed measurement.
                    state = ("active" if row.get("active") in (True, 1) else
                             "inactive" if row.get("active") in (False, 0) else "unknown") if is_network else "present"
                    inventory.append({"resource_id": rid, "type": kind, "name": name, "state": state,
                                      "parent_id": resource_id, "observed_at": observed})
                    child_tags = {**tags, "resource_type": kind}
                    if is_network and state != "unknown":
                        emit("network.interface.active", int(state == "active"), "boolean", rid, metric_tags=child_tags)
                    elif not is_network:
                        emit("physical_disk.capacity", row.get("size"), "byte", rid, metric_tags=child_tags)
                details["network" if is_network else "disks"] = items
            else:
                details["configuration"] = _fields(data, ("startall-onboot-delay", "wakeonlan"))
        except urllib.error.HTTPError as error:
            details["endpoints"][key] = "forbidden" if error.code in (401, 403) else "unavailable"
        except (ValueError, TypeError):
            details["endpoints"][key] = "invalid"
        except Exception:
            details["endpoints"][key] = "unavailable"
    return details


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
        tls_options = {"cafile": params.get("ca_file") or None}
        ca_pem = params.get("ca_pem")
        if ca_pem is not None:
            # Only certificate blocks, not paths, private keys or mixed content.
            # OpenSSL below validates the actual X.509 data, not just PEM markers.
            if not isinstance(ca_pem, str) or not re.fullmatch(
                    r"(?:\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+",
                    ca_pem):
                raise ValueError("invalid_ca_pem")
            tls_options["cadata"] = ca_pem
        try:
            # If both forms are supplied, both must load successfully. Never
            # fall back to system trust or disable verification on invalid CA.
            context = ssl.create_default_context(**tls_options)
        except ssl.SSLError:
            raise ValueError("invalid_ca_certificate") from None
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


def _inventory_text(value, limit):
    return (isinstance(value, str) and 0 < len(value.encode("utf-8")) <= limit
            and not any(c in value for c in "\r\n\0"))


def _performance(client, resources, observed, metrics):
    """PVE's export uses absolute DERIVE counters, not byte/s gauges."""
    if not resources:
        return "not_requested"
    mapping = {
        "cpu_avg1": ("cpu.load1", "count"), "cpu_avg5": ("cpu.load5", "count"),
        "cpu_avg15": ("cpu.load15", "count"), "cpu_max": ("cpu.logical", "count"),
        "cpu_current": ("cpu.usage", "fraction"), "cpu_iowait": ("cpu.iowait", "fraction"),
        "mem_total": ("memory.capacity", "byte"), "mem_used": ("memory.used", "byte"),
        "swap_total": ("swap.total", "byte"), "swap_used": ("swap.used", "byte"),
        "disk_total": ("disk.capacity", "byte"), "disk_used": ("disk.used", "byte"),
        "disk_read": ("disk.read.total", "byte"), "disk_write": ("disk.write.total", "byte"),
        "net_in": ("network.received.total", "byte"), "net_out": ("network.sent.total", "byte"),
        "uptime": ("uptime", "second"),
    }
    try:
        payload = client.get("/cluster/metrics/export")
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            return "invalid"
        now = datetime.fromisoformat(observed.replace("Z", "+00:00")).timestamp()
        def key(item):
            return item["resource_id"], item["name"], tuple(sorted(item["tags"].items()))
        merged = {key(m): m for m in metrics}
        for row in payload["data"]:
            if not isinstance(row, dict):
                continue
            tags = resources.get(row.get("id"))
            field = mapping.get(row.get("metric"))
            at, value = _number(row.get("timestamp")), _number(row.get("value"))
            if tags is None or field is None or at is None or value is None or not now - 300 <= at <= now:
                continue
            # Absolute counters stay cumulative; the metric's .total suffix allows
            # rate() without treating a counter as an instantaneous throughput.
            item = metric("telvyn.proxmox." + field[0], value, field[1], row["id"], tags,
                          timestamp(datetime.fromtimestamp(at, timezone.utc)))
            identity = key(item)
            # Prefer the timestamped export for load averages, like Datadog.
            # /nodes/status is only a fallback when export is unavailable.
            status_load = (field[0].startswith("cpu.load") and identity in merged
                           and merged[identity]["timestamp"] == observed)
            if identity not in merged or status_load or item["timestamp"] > merged[identity]["timestamp"]:
                merged[identity] = item
        metrics[:] = merged.values()
        return "available"
    except urllib.error.HTTPError as error:
        return "unsupported" if error.code in (404, 501) else "forbidden" if error.code in (401, 403) else "unavailable"
    except Exception:
        return "unavailable"


def _cluster_inventory(client, observed):
    """Only /cluster/status proves cluster membership; standalone has no cluster row."""
    try:
        rows = client.get("/cluster/status")
        if not isinstance(rows, list):
            raise ValueError("invalid cluster status")
        inventory, seen = [], set()
        for row in rows:
            if not isinstance(row, dict) or row.get("type") not in ("cluster", "node"):
                raise ValueError("invalid cluster status row")
            kind, rid, name = row["type"], row.get("id"), row.get("name")
            if (not isinstance(rid, str) or rid in seen or not _inventory_text(name, 256)
                    or not re.fullmatch("cluster" if kind == "cluster" else r"node/[A-Za-z0-9._-]{1,64}", rid)):
                raise ValueError("invalid cluster identity")
            seen.add(rid)
            flag = row.get("quorate" if kind == "cluster" else "online")
            state = ("quorate" if flag == 1 else "not_quorate" if flag == 0 else "unknown") if kind == "cluster" else (
                "online" if flag == 1 else "offline" if flag == 0 else "unknown")
            inventory.append({"resource_id": rid, "type": kind, "name": name, "state": state,
                              "parent_id": None, "observed_at": observed})
        cluster = "cluster" if "cluster" in seen else None
        for item in inventory:
            if item["type"] == "node":
                item["parent_id"] = cluster
        return inventory, "clustered" if cluster else "standalone", "available"
    except urllib.error.HTTPError as error:
        return [], "unknown", "forbidden" if error.code in (401, 403) else "unavailable"
    except (TypeError, ValueError):
        return [], "unknown", "invalid"
    except Exception:
        return [], "unknown", "unavailable"


def collect(instance_id, params, static_tags, client=None):
    observed = timestamp()
    api_tags = {**static_tags, "provider": "proxmox", "resource_type": "api", "instance_id": instance_id}
    if client is None:
        try:
            client = ProxmoxClient(params)
        except (KeyError, ValueError, TypeError, OSError):
            return result(status="error", error="invalid_configuration_or_response")
    try:
        rows = client.get("/cluster/resources")
        if not isinstance(rows, list):
            raise ValueError("invalid resources")
    except (KeyError, ValueError, TypeError):
        return result(status="error", error="invalid_configuration_or_response")
    except Exception:
        return result([metric("telvyn.proxmox.api.up", 0, "boolean", "api/proxmox", api_tags, observed)],
                      status="partial", coverage={"inventory_complete": False}, error="proxmox_api_unavailable")

    metrics, inventory, nodes, performance_resources = [], [], [], {}
    counts = {"node": 0, "qemu": 0, "lxc": 0, "storage": 0, "network": 0}
    observed = timestamp()  # /cluster/resources does not provide a per-value timestamp.
    metrics.append(metric("telvyn.proxmox.api.up", 1, "boolean", "api/proxmox", api_tags, observed))
    cluster_inventory, cluster_mode, cluster_status = _cluster_inventory(client, observed)
    inventory_complete = cluster_status == "available"
    seen = set()
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
        if not isinstance(row, dict):
            inventory_complete = False
            continue
        if row.get("type") not in counts:
            continue
        kind = row["type"]
        resource_id = row.get("id")
        name = row.get("name") or row.get("storage") or (row.get("node") if kind == "node" else None) or resource_id
        state = row.get("status") or "unknown"
        if (not isinstance(resource_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", resource_id)
                or not resource_id.startswith(kind + "/") or resource_id in seen
                or not _inventory_text(name, 256) or not _inventory_text(state, 64)):
            inventory_complete = False
            continue
        seen.add(resource_id)
        counts[kind] += 1
        tags = {**static_tags, "provider": "proxmox", "resource_type": kind, "instance_id": instance_id}
        inventory.append({
            "resource_id": resource_id, "type": kind, "name": name,
            "state": state,
            "parent_id": "node/" + row["node"] if kind != "node" and isinstance(row.get("node"), str) else None,
            "observed_at": observed,
        })
        up = row.get("status") in ("online", "running", "available", "ok")
        if up:
            performance_resources[resource_id] = tags
        if kind in ("node", "qemu") and _number(row.get("maxcpu")) is not None:
            metrics.append(metric("telvyn.proxmox.cpu.logical", _number(row["maxcpu"]), "count", resource_id, tags, observed))
        if kind == "node" and up:
            node = row.get("node") or resource_id.removeprefix("node/")
            if isinstance(node, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", node):
                nodes.append((node, resource_id, tags))
        metrics.append(metric("telvyn.proxmox.up", int(up), "boolean", resource_id, tags, observed))
        # Powered-off VMs remain in inventory; their missing runtime counters are not fabricated.
        for key, (suffix, unit, value_type) in mapping.items():
            if kind in ("qemu", "lxc") and not up:
                break
            if key in row:
                item = metric("telvyn.proxmox." + suffix, row[key], unit, resource_id, tags, observed, value_type)
                if item is not None:
                    metrics.append(item)
    # Merge observed membership nodes, including offline nodes missing runtime data.
    members = {item["resource_id"]: item for item in cluster_inventory}
    for item in inventory:
        if item["type"] == "node" and item["resource_id"] in members:
            item.update(members[item["resource_id"]])
    for item in cluster_inventory:
        if item["resource_id"] not in seen:
            inventory.append(item)
            if item["type"] == "node":
                counts["node"] += 1
    # A dangling relation is observed, but cannot constitute a complete snapshot.
    ids = {item["resource_id"] for item in inventory}
    for item in inventory:
        if item["parent_id"] and item["parent_id"] not in ids:
            inventory_complete = False
        if item["type"] == "node" and item["state"] != "online":
            inventory_complete = False  # interface/disk inventory cannot be refreshed offline
    coverage = {
        "resources": counts, "timestamp_source": "collector_after_api_response",
        "version_endpoint": "not_requested", "metric_scope": "cluster_resources_snapshot",
        "cluster_mode": cluster_mode, "cluster_status_endpoint": cluster_status,
        "inventory_complete": inventory_complete, "inventory_scope": "credential_visible_resources",
    }
    status, error = ("ok", None) if inventory_complete else ("partial", "inventory_incomplete")
    for kind, count in counts.items():
        tags = {**api_tags, "resource_type": kind}
        metrics.append(metric("telvyn.proxmox.resource.count", count, "count", "api/proxmox", tags, observed))
    try:
        ha = client.get("/cluster/ha/status/current")
        if not isinstance(ha, list):
            raise ValueError("invalid HA status")
        coverage["ha_status_endpoint"] = "available"
        for row in ha:
            if not isinstance(row, dict) or row.get("type") != "quorum":
                continue
            rid = "node/" + str(row.get("node", ""))
            if rid not in ids:
                continue
            if isinstance(row.get("status"), str):
                metrics.append(metric("telvyn.proxmox.ha.quorum", int(row["status"] == "OK"), "boolean", rid, api_tags, observed))
            if row.get("quorate") in (0, 1):
                metrics.append(metric("telvyn.proxmox.ha.quorate", int(row["quorate"]), "boolean", rid, api_tags, observed))
    except Exception:
        coverage["ha_status_endpoint"] = "unavailable"
        status, error = "partial", "ha_metrics_incomplete"
    coverage["node_details"] = {}
    coverage["node_network_scope"] = "physical_nics_aggregate_rrd_average"
    coverage["node_network_timestamp_source"] = "rrd_sample_time_max_age_300s"
    for node, resource_id, tags in nodes:
        details = _node_details(client, node, resource_id, tags, observed, metrics, inventory)
        coverage["node_details"][resource_id] = details
        if any(value != "available" for value in details["endpoints"].values()):
            status, error = "partial", "node_details_incomplete"
        if any(details["endpoints"].get(key) != "available" for key in ("network", "disks/list")):
            coverage["inventory_complete"] = False
    coverage["performance_endpoint"] = _performance(client, performance_resources, observed, metrics)
    coverage["performance_counter_semantics"] = "absolute_total_use_rate"
    if coverage["performance_endpoint"] not in ("available", "unsupported", "not_requested"):
        status, error = "partial", "performance_metrics_incomplete"
    if str(params.get("include_version", "false")).lower() == "true":
        try:
            version = client.get("/version")
            coverage["version_endpoint"] = "available" if isinstance(version, dict) else "invalid"
            if not isinstance(version, dict):
                status, error = "partial", "optional_version_unavailable"
        except Exception:
            coverage["version_endpoint"] = "unavailable"
            status, error = "partial", "optional_version_unavailable"
    # Protocol v1 rejects unknown inventory fields and caps coverage at 8 KiB.
    # Metadata stays in coverage, not extra inventory keys. Reserve room for the
    # runner's unsupported_count_metrics annotation; never invalidate base data.
    while len(json.dumps(coverage).encode("utf-8")) > 7600 and coverage["node_details"]:
        coverage["node_details"].popitem()
        coverage["node_details_truncated"] = True
        status, error = "partial", "result_limit_reached"
    if len(metrics) > 500 or len(inventory) > 1000:
        status, error = "partial", "result_limit_reached"
        coverage["result_truncated"] = True
        coverage["inventory_complete"] = False
    return result(metrics[:500], inventory[:1000], status, coverage, error)

