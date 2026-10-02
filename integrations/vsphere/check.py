"""vCenter read-only inventory and sampled performance via optional pyVmomi."""

import ssl
from urllib.parse import urlsplit

from common import metric, result, timestamp


# Exact provider counter names and units; do not interpret an unknown counter as a rate.
COUNTERS = {
    ("cpu", "usage", "average", "percent"): ("cpu.usage", "percent", 0.01),
    ("mem", "usage", "average", "percent"): ("memory.usage", "percent", 0.01),
    ("mem", "consumed", "average", "kiloBytes"): ("memory.consumed", "byte", 1024),
    ("net", "received", "average", "kiloBytesPerSecond"): ("network.received", "byte_per_second", 1024),
    ("net", "transmitted", "average", "kiloBytesPerSecond"): ("network.sent", "byte_per_second", 1024),
    ("disk", "read", "average", "kiloBytesPerSecond"): ("disk.read", "byte_per_second", 1024),
    ("disk", "write", "average", "kiloBytesPerSecond"): ("disk.write", "byte_per_second", 1024),
}


def _property(obj, *path):
    for name in path:
        obj = getattr(obj, name, None)
        if obj is None:
            break
    return obj


class PyVmomiClient:
    def __init__(self, params):
        if params.get("endpoint_kind") != "vcenter":
            raise ValueError("vcenter_required")
        endpoint = urlsplit(params["endpoint"])
        if (endpoint.scheme != "https" or not endpoint.hostname or endpoint.path not in ("", "/")
                or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment):
            raise ValueError("invalid_endpoint")
        try:
            from pyVim.connect import SmartConnect, Disconnect
            from pyVmomi import vim
        except ImportError as exc:
            raise RuntimeError("pyvmomi_missing") from exc
        self.vim = vim
        self.disconnect = Disconnect
        context = ssl.create_default_context(cafile=params.get("ca_file") or None)
        self.service = SmartConnect(
            host=endpoint.hostname, port=endpoint.port or 443,
            user=params["username"], pwd=params["password"], sslContext=context,
        )
        self.content = self.service.RetrieveContent()
        self.perf = self.content.perfManager

    def close(self):
        self.disconnect(self.service)

    def entities(self):
        view = self.content.viewManager.CreateContainerView(
            self.content.rootFolder,
            [self.vim.HostSystem, self.vim.VirtualMachine, self.vim.Datastore], True,
        )
        try:
            # Copy before destroying server-side view.
            return list(view.view)
        finally:
            view.Destroy()

    def samples(self, entities):
        counters = {}
        for counter in self.perf.perfCounter:
            key = (
                counter.groupInfo.key, counter.nameInfo.key,
                counter.rollupType, counter.unitInfo.key,
            )
            if key in COUNTERS:
                counters[counter.key] = COUNTERS[key]
        output, failures = [], 0
        for entity in entities:
            if isinstance(entity, self.vim.Datastore) or (
                isinstance(entity, self.vim.VirtualMachine)
                and str(_property(entity, "runtime", "powerState")) != "poweredOn"
            ):
                continue
            try:
                available = self.perf.QueryAvailablePerfMetric(entity=entity, intervalId=20) or []
                ids = [item for item in available if item.counterId in counters and not item.instance]
                if not ids:
                    continue
                query = self.vim.PerformanceManager.QuerySpec(
                    entity=entity, metricId=ids, intervalId=20, maxSample=1,
                )
                for series in self.perf.QueryPerf(querySpec=[query]) or []:
                    if not series.sampleInfo:
                        continue
                    observed = timestamp(series.sampleInfo[-1].timestamp)
                    for value in series.value or []:
                        if value.id.counterId in counters and not value.id.instance and value.value:
                            output.append((entity, counters[value.id.counterId], value.value[-1], observed))
            except Exception:
                failures += 1
        return output, failures


def collect(instance_id, params, static_tags, client=None):
    owned = client is None
    try:
        client = client or PyVmomiClient(params)
    except RuntimeError as exc:
        if str(exc) == "pyvmomi_missing":
            return result(status="error", error="pyvmomi_missing: install pinned wheel in offline runtime bundle")
        return result(status="error", error="vsphere_connection_failed")
    except (ValueError, KeyError, TypeError):
        return result(status="error", error="invalid_configuration")
    except Exception:
        return result(status="error", error="vsphere_connection_failed")

    metrics, inventory = [], []
    counts = {"esxi_host": 0, "vm": 0, "datastore": 0}
    coverage = {"resources": counts, "performance": "not_collected", "timestamp_source": "provider_for_performance_collector_for_inventory"}
    status, error = "ok", None
    try:
        entities = client.entities()
        observed = timestamp()
        for entity in entities:
            kind = _kind(entity)
            if kind is None:
                continue
            resource_id = getattr(entity, "_moId", None)
            if not isinstance(resource_id, str) or not resource_id:
                continue
            counts[kind] += 1
            state = _state(entity, kind)
            inventory.append({
                "resource_id": kind + "/" + resource_id, "type": kind,
                "name": str(getattr(entity, "name", resource_id)), "state": state,
                "parent_id": _parent_id(entity, kind),
                "observed_at": observed,
            })
            tags = {**static_tags, "provider": "vsphere", "resource_type": kind, "instance_id": instance_id}
            if kind == "datastore":
                capacity = _property(entity, "summary", "capacity")
                free = _property(entity, "summary", "freeSpace")
                for suffix, value in (("datastore.capacity", capacity), ("datastore.free", free)):
                    item = metric("telvyn.vsphere." + suffix, value, "byte", kind + "/" + resource_id, tags, observed)
                    if item is not None:
                        metrics.append(item)
        try:
            samples, failures = client.samples(entities)
            for entity, (suffix, unit, factor), raw, sample_time in samples:
                kind = _kind(entity)
                resource_id = getattr(entity, "_moId", None)
                if kind not in ("esxi_host", "vm") or not isinstance(resource_id, str) or raw < 0:
                    continue
                tags = {**static_tags, "provider": "vsphere", "resource_type": kind, "instance_id": instance_id}
                item = metric("telvyn.vsphere." + suffix, raw * factor, unit, kind + "/" + resource_id, tags, sample_time)
                if item is not None:
                    metrics.append(item)
            coverage["performance"] = "sampled_realtime_available_counters" if samples else "no_available_samples"
            coverage["performance_entity_failures"] = failures
            if failures:
                status, error = "partial", "some_performance_entities_unavailable"
        except Exception:
            status, error = "partial", "performance_unavailable"
            coverage["performance"] = "unavailable"
    except Exception:
        return result(status="error", error="inventory_unavailable", coverage=coverage)
    finally:
        if owned:
            try:
                client.close()
            except Exception:
                pass
    return result(metrics, inventory, status, coverage, error)


def _kind(entity):
    # pyVmomi may prefix WSDL names with "vim."; fakes can mirror either form.
    return {"HostSystem": "esxi_host", "VirtualMachine": "vm", "Datastore": "datastore"}.get(type(entity).__name__.rsplit(".", 1)[-1])


def _parent_id(entity, kind):
    if kind != "vm":
        return None
    host_id = _property(entity, "runtime", "host", "_moId")
    return "esxi_host/" + host_id if isinstance(host_id, str) and host_id else None


def _state(entity, kind):
    if kind == "vm":
        return str(_property(entity, "runtime", "powerState") or "unknown")
    if kind == "esxi_host":
        return str(_property(entity, "runtime", "connectionState") or "unknown")
    return "accessible" if _property(entity, "summary", "accessible") else "unavailable"
