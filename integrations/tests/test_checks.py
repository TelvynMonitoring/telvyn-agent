import json
import math
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from proxmox.check import ProxmoxClient, collect as collect_proxmox  # noqa: E402
from vsphere.check import COUNTERS, _kind, collect as collect_vsphere  # noqa: E402
from runner import run  # noqa: E402


class FakeProxmox:
    def __init__(self, rows, fail_version=False):
        self.rows = rows
        self.fail_version = fail_version
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        if path == "/version":
            if self.fail_version:
                raise OSError("secret should not leak")
            return {"version": "8.4"}
        return self.rows


class HostSystem:
    def __init__(self, ident):
        self._moId = ident
        self.name = "esxi-1"
        self.runtime = SimpleNamespace(connectionState="connected")


class VirtualMachine:
    def __init__(self, ident, state, host):
        self._moId = ident
        self.name = "vm-" + ident
        self.runtime = SimpleNamespace(powerState=state, host=host)


class Datastore:
    def __init__(self, ident):
        self._moId = ident
        self.name = "store-1"
        self.summary = SimpleNamespace(capacity=4096, freeSpace=1024, accessible=True)


class FakeVSphere:
    def __init__(self, entities, samples, failures=0):
        self._entities = entities
        self._samples = samples
        self.failures = failures

    def entities(self):
        return self._entities

    def samples(self, entities):
        return self._samples, self.failures


class ChecksTest(unittest.TestCase):
    def test_proxmox_inventory_includes_powered_off_without_stale_runtime_counters(self):
        rows = json.loads((ROOT / "tests/fixtures/proxmox_resources.json").read_text())["data"]
        fake = FakeProxmox(rows)
        output = collect_proxmox("one", {"include_version": "false"}, {"site": "lab"}, fake)
        self.assertEqual(output["status"], "ok")
        self.assertEqual(fake.paths, ["/cluster/resources"])
        cold = next(row for row in output["inventory"] if row["resource_id"] == "qemu/101")
        self.assertEqual(cold["state"], "stopped")
        self.assertEqual(cold["parent_id"], "node/pve1")
        self.assertFalse(any(m["resource_id"] == "qemu/101" and m["name"].endswith("cpu.usage") for m in output["metrics"]))
        self.assertEqual(output["coverage"]["timestamp_source"], "collector_after_api_response")

    def test_proxmox_optional_version_partial_sanitized(self):
        output = collect_proxmox("one", {"include_version": "true"}, {}, FakeProxmox([], True))
        self.assertEqual(output["status"], "partial")
        self.assertEqual(output["error"], "optional_version_unavailable")
        self.assertNotIn("secret", json.dumps(output))

    def test_proxmox_https_required_and_nonfinite_omitted(self):
        with self.assertRaises(ValueError):
            ProxmoxClient({"endpoint": "http://pve:8006", "token_id": "a", "token_secret": "b"})
        row = {"type": "node", "id": "node/pve1", "status": "online", "cpu": math.inf}
        output = collect_proxmox("one", {}, {}, FakeProxmox([row]))
        self.assertFalse(any(m["name"].endswith("cpu.usage") for m in output["metrics"]))

    def test_vsphere_inventory_performance_units_and_partial(self):
        host = HostSystem("host-1")
        running = VirtualMachine("vm-1", "poweredOn", host)
        off = VirtualMachine("vm-2", "poweredOff", host)
        store = Datastore("datastore-1")
        samples = [
            (running, COUNTERS[("cpu", "usage", "average", "percent")], 2067, "2026-01-01T00:00:00Z"),
            (host, COUNTERS[("net", "received", "average", "kiloBytesPerSecond")], 4, "2026-01-01T00:00:00Z"),
            (running, COUNTERS[("disk", "read", "average", "kiloBytesPerSecond")], 3, "2026-01-01T00:00:00Z"),
        ]
        output = collect_vsphere("one", {}, {"site": "lab"}, FakeVSphere([host, running, off, store], samples, 1))
        self.assertEqual(output["status"], "partial")
        self.assertEqual(output["coverage"]["performance_entity_failures"], 1)
        self.assertEqual(output["coverage"]["resources"], {"esxi_host": 1, "vm": 2, "datastore": 1})
        self.assertEqual(next(i for i in output["inventory"] if i["resource_id"] == "vm/vm-1")["parent_id"], "esxi_host/host-1")
        values = {m["name"]: m["value"] for m in output["metrics"]}
        self.assertEqual(values["telvyn.vsphere.cpu.usage"], 20.67)
        self.assertEqual(values["telvyn.vsphere.network.received"], 4096)
        self.assertEqual(values["telvyn.vsphere.disk.read"], 3072)
        self.assertEqual(values["telvyn.vsphere.datastore.free"], 1024)

    def test_namespaced_pyvmomi_class_name(self):
        item = type("vim.HostSystem", (), {})()
        self.assertEqual(_kind(item), "esxi_host")

    def test_vsphere_missing_dependency_is_actionable_without_secret(self):
        with patch("vsphere.check.PyVmomiClient", side_effect=RuntimeError("pyvmomi_missing")):
            output = collect_vsphere("one", {"password": "do-not-echo"}, {}, None)
        self.assertEqual(output["status"], "error")
        self.assertIn("offline runtime bundle", output["error"])
        self.assertNotIn("do-not-echo", json.dumps(output))

    def test_isolated_runner_real_process(self):
        request = {"protocol_version": 1, "instance_id": "one", "params": {}, "static_tags": {}}
        proc = subprocess.run(
            [sys.executable, "-I", "-B", str(ROOT / "runner.py"), "--check", "proxmox"],
            input=json.dumps(request), text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        output = json.loads(proc.stdout)
        self.assertEqual(output["protocol_version"], 1)
        self.assertEqual(output["status"], "error")
        self.assertNotIn("Traceback", proc.stderr)

    def test_runner_rejects_secret_static_tag(self):
        output = run("proxmox", {
            "protocol_version": 1, "instance_id": "one", "params": {},
            "static_tags": {"api_token": "do-not-echo"},
        })
        self.assertEqual(output["error"], "secret_tag_rejected")
        self.assertNotIn("do-not-echo", json.dumps(output))


if __name__ == "__main__":
    unittest.main()
