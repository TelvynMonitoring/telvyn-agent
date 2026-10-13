import json
import math
import ssl
import subprocess
import sys
import time
import urllib.error
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from proxmox.check import ProxmoxClient, _NoRedirect, collect as collect_proxmox  # noqa: E402
from vsphere.check import COUNTERS, _kind, collect as collect_vsphere  # noqa: E402
from runner import run  # noqa: E402


class FakeProxmox:
    def __init__(self, rows, fail_version=False, responses=None):
        self.rows = rows
        self.fail_version = fail_version
        self.paths = []
        self.responses = responses or {}

    def get(self, path):
        self.paths.append(path)
        if path in self.responses:
            value = self.responses[path]
            if isinstance(value, Exception):
                raise value
            return value
        if path == "/version":
            if self.fail_version:
                raise OSError("secret should not leak")
            return {"version": "8.4"}
        if path == "/cluster/resources":
            return self.rows
        if path == "/cluster/status":
            return []
        if path == "/cluster/ha/status/current":
            return []
        if path == "/cluster/metrics/export":
            return {"data": []}
        if "/rrddata?" in path:
            return [{"time": time.time() - 120, "netin": 0, "netout": 0}]
        return [] if path.endswith(("/network", "/disks/list")) else {}


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
    def test_proxmox_api_network_counts_and_quorum_are_observed(self):
        fake = FakeProxmox([
            {"type":"node","id":"node/pve1","node":"pve1","status":"online"},
            {"type":"network","id":"network/pve1/zone/local","node":"pve1","status":"ok"},
        ], responses={"/cluster/ha/status/current":[{"type":"quorum","node":"pve1","status":"OK","quorate":1}]})
        output = collect_proxmox("one", {}, {}, fake)
        values = {(m["name"],m["resource_id"],m["tags"]["resource_type"]):m["value"] for m in output["metrics"]}
        self.assertEqual(values["telvyn.proxmox.api.up","api/proxmox","api"],1)
        self.assertEqual(values["telvyn.proxmox.resource.count","api/proxmox","network"],1)
        self.assertEqual(len([m for m in output["metrics"] if m["name"]=="telvyn.proxmox.resource.count"]),5)
        self.assertEqual(values["telvyn.proxmox.up","network/pve1/zone/local","network"],1)
        self.assertEqual(values["telvyn.proxmox.ha.quorum","node/pve1","api"],1)
        self.assertEqual(values["telvyn.proxmox.ha.quorate","node/pve1","api"],1)
        failed = collect_proxmox("one", {}, {}, FakeProxmox([],responses={"/cluster/resources":OSError("do-not-leak")}))
        self.assertEqual(failed["metrics"][0]["value"],0)
        self.assertFalse(failed["coverage"]["inventory_complete"])
        self.assertNotIn("do-not-leak",json.dumps(failed))

    def test_proxmox_cluster_discovery_relations_and_stopped_guests(self):
        fake = FakeProxmox([
            {"type": "node", "id": "node/pve1", "node": "pve1", "status": "online"},
            {"type": "qemu", "id": "qemu/101", "name": "cold-vm", "node": "pve1", "status": "stopped", "cpu": 0.9},
            {"type": "lxc", "id": "lxc/102", "name": "cold-ct", "node": "pve1", "status": "stopped", "cpu": 0.9},
            {"type": "storage", "id": "storage/pve1/local", "storage": "local", "node": "pve1", "status": "available"},
        ], responses={"/cluster/status": [
            {"type": "cluster", "id": "cluster", "name": "real-cluster", "quorate": 1, "ip": "not-exported"},
            {"type": "node", "id": "node/pve1", "name": "pve1", "online": 1},
            {"type": "node", "id": "node/pve2", "name": "pve2", "online": 0},
        ]})
        output = collect_proxmox("one", {}, {}, fake)
        items = {item["resource_id"]: item for item in output["inventory"]}
        self.assertEqual(items["cluster"]["name"], "real-cluster")
        self.assertEqual(items["cluster"]["state"], "quorate")
        self.assertEqual(items["node/pve1"]["parent_id"], "cluster")
        self.assertEqual(items["node/pve2"]["state"], "offline")
        for rid in ("qemu/101", "lxc/102"):
            self.assertEqual(items[rid]["state"], "stopped")
            self.assertEqual(items[rid]["parent_id"], "node/pve1")
            self.assertFalse(any(m["resource_id"] == rid and m["name"].endswith("cpu.usage") for m in output["metrics"]))
        self.assertEqual(items["storage/pve1/local"]["name"], "local")
        self.assertEqual(items["storage/pve1/local"]["parent_id"], "node/pve1")
        self.assertEqual(output["coverage"]["cluster_mode"], "clustered")
        self.assertFalse(output["coverage"]["inventory_complete"])  # offline-node children unknown
        self.assertNotIn("not-exported", json.dumps(output))

    def test_proxmox_standalone_and_valid_empty_inventory_are_not_cluster_or_failure(self):
        node = {"type": "node", "id": "node/pve1", "node": "pve1", "status": "online"}
        output = collect_proxmox("one", {}, {}, FakeProxmox([node], responses={"/cluster/status": [
            {"type": "node", "id": "node/pve1", "name": "pve1", "online": 1}]}))
        self.assertEqual(output["coverage"]["cluster_mode"], "standalone")
        self.assertTrue(output["coverage"]["inventory_complete"])
        self.assertFalse(any(item["type"] == "cluster" for item in output["inventory"]))
        self.assertIsNone(output["inventory"][0]["parent_id"])
        empty = collect_proxmox("one", {}, {}, FakeProxmox([]))
        self.assertEqual(empty["status"], "ok")
        self.assertEqual(empty["inventory"], [])
        self.assertEqual(empty["coverage"]["resources"]["qemu"], 0)
        self.assertEqual(empty["coverage"]["resources"]["lxc"], 0)
        self.assertTrue(empty["coverage"]["inventory_complete"])

    def test_proxmox_cluster_failure_and_malformed_rows_never_mean_complete_empty(self):
        for response in (OSError("do-not-export"), {"bad": "shape"},
                         [{"type": "cluster", "id": "cluster", "name": "bad\nname"}],
                         urllib.error.HTTPError("https://unused", 403, "do-not-export", {}, None)):
            with self.subTest(kind=type(response).__name__):
                output = collect_proxmox("one", {}, {}, FakeProxmox([], responses={"/cluster/status": response}))
                self.assertEqual(output["status"], "partial")
                self.assertEqual(output["coverage"]["cluster_mode"], "unknown")
                self.assertFalse(output["coverage"]["inventory_complete"])
                self.assertNotIn("do-not-export", json.dumps(output))
        output = collect_proxmox("one", {}, {}, FakeProxmox([None, {"type": "qemu", "id": "bad id"}]))
        self.assertFalse(output["coverage"]["inventory_complete"])
        self.assertEqual(output["inventory"], [])

    def test_proxmox_inventory_truncation_is_explicit(self):
        rows = [{"type": "qemu", "id": "qemu/" + str(i), "name": "vm", "status": "stopped"} for i in range(1001)]
        output = collect_proxmox("one", {}, {}, FakeProxmox(rows))
        self.assertEqual(len(output["inventory"]), 1000)
        self.assertFalse(output["coverage"]["inventory_complete"])
        self.assertTrue(output["coverage"]["result_truncated"])
        self.assertEqual(output["status"], "partial")

    def test_proxmox_inventory_includes_powered_off_without_stale_runtime_counters(self):
        rows = json.loads((ROOT / "tests/fixtures/proxmox_resources.json").read_text())["data"]
        fake = FakeProxmox(rows)
        output = collect_proxmox("one", {"include_version": "false"}, {"site": "lab"}, fake)
        self.assertEqual(output["status"], "ok")
        self.assertEqual(fake.paths, ["/cluster/resources", "/cluster/status", "/cluster/ha/status/current", "/nodes/pve1/status",
                                     "/nodes/pve1/rrddata?timeframe=hour&cf=AVERAGE",
                                     "/nodes/pve1/network", "/nodes/pve1/disks/list", "/nodes/pve1/config",
                                     "/cluster/metrics/export"])
        cold = next(row for row in output["inventory"] if row["resource_id"] == "qemu/101")
        self.assertEqual(cold["state"], "stopped")
        self.assertEqual(cold["parent_id"], "node/pve1")
        self.assertFalse(any(m["resource_id"] == "qemu/101" and m["name"].endswith("cpu.usage") for m in output["metrics"]))
        self.assertEqual(output["coverage"]["timestamp_source"], "collector_after_api_response")

    def test_proxmox_export_preserves_counter_units_scope_and_freshness(self):
        at = int(time.time()) - 10
        fake = FakeProxmox([{"type": "qemu", "id": "qemu/101", "name": "vm", "status": "running", "maxcpu": 2}],
            responses={"/cluster/metrics/export": {"data": [
                {"id": "qemu/101", "metric": "net_in", "type": "derive", "value": 4096, "timestamp": at},
                {"id": "qemu/101", "metric": "cpu_iowait", "type": "gauge", "value": .1, "timestamp": at},
                {"id": "qemu/101", "metric": "disk_read", "value": 2, "timestamp": at - 1000},
                {"id": "qemu/not-visible", "metric": "net_out", "value": 3, "timestamp": at},
            ]}})
        output = collect_proxmox("one", {}, {}, fake)
        values = {m["name"]: m for m in output["metrics"]}
        self.assertEqual(values["telvyn.proxmox.cpu.logical"]["value"], 2)
        counter = values["telvyn.proxmox.network.received.total"]
        self.assertEqual((counter["value"], counter["unit"], counter["type"]), (4096, "byte", "gauge"))
        self.assertEqual(counter["resource_id"], "qemu/101")
        self.assertNotIn("telvyn.proxmox.disk.read.total", values)
        self.assertNotIn("telvyn.proxmox.network.sent.total", values)
        self.assertEqual(output["coverage"]["performance_endpoint"], "available")

    def test_proxmox_load_prefers_timestamped_export_with_status_fallback(self):
        from datetime import datetime
        at = int(time.time()) - 10
        node = {"type": "node", "id": "node/pve1", "node": "pve1", "status": "online"}
        responses = {"/nodes/pve1/status": {"loadavg": [1.2, 2.3, 3.4]},
                     "/cluster/metrics/export": {"data": [
                         {"id": "node/pve1", "metric": "cpu_avg1", "value": .5, "timestamp": at},
                         {"id": "node/pve1", "metric": "cpu_avg1", "value": .4, "timestamp": at - 5},
                     ]}}
        output = collect_proxmox("one", {}, {}, FakeProxmox([node], responses=responses))
        values = {m["name"]: m for m in output["metrics"]}
        load = values["telvyn.proxmox.cpu.load1"]
        self.assertEqual((load["value"], load["unit"]), (.5, "count"))
        self.assertEqual(datetime.fromisoformat(load["timestamp"].replace("Z", "+00:00")).timestamp(), at)
        self.assertEqual(values["telvyn.proxmox.cpu.load5"]["value"], 2.3)

    def test_proxmox_optional_version_partial_sanitized(self):
        output = collect_proxmox("one", {"include_version": "true"}, {}, FakeProxmox([], True))
        self.assertEqual(output["status"], "partial")
        self.assertEqual(output["error"], "optional_version_unavailable")
        self.assertNotIn("secret", json.dumps(output))
        malformed = collect_proxmox("one", {"include_version": "true"}, {},
                                    FakeProxmox([], responses={"/version": []}))
        self.assertEqual(malformed["status"], "partial")
        self.assertEqual(malformed["coverage"]["version_endpoint"], "invalid")

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

    def test_proxmox_node_without_vms_has_details_and_timestamped_network_rates(self):
        at = int(time.time()) - 120
        node = {"type": "node", "id": "node/pve1", "node": "pve1", "status": "online", "cpu": 0.25}
        fake = FakeProxmox([node], responses={
            "/nodes/pve1/status": {
                "pveversion": "pve-manager/8.4", "kversion": "Linux test",
                "cpuinfo": {"cpus": 4, "cores": 2, "model": "Test CPU", "flags": "not-exported"},
                "memory": {"available": 1024, "free": 512}, "loadavg": ["0.1", "0.2", "0.3"],
                "rootfs": {"total": 4096, "used": 1024, "avail": 3000},
                "swap": {"total": 2048, "used": 0},
            },
            "/nodes/pve1/rrddata?timeframe=hour&cf=AVERAGE": [
                {"time": at, "netin": 200.5, "netout": 50}, {"time": at + 60},
                {"time": at - 60, "netin": 999}, {"time": at + 900, "netin": 999},
            ],
            "/nodes/pve1/network": [{"iface": "vmbr0", "type": "bridge", "active": 1,
                                      "cidr": "192.168.1.6/24", "bridge_ports": "eno1",
                                      "comments": "do-not-export", "options": ["do-not-export"]}],
            "/nodes/pve1/disks/list": [{"devpath": "/dev/sda", "size": 4096, "model": "Test Disk",
                                         "health": "PASSED", "used": "LVM"}],
            "/nodes/pve1/config": {"startall-onboot-delay": 10, "acme": "do-not-export"},
        })
        output = collect_proxmox("one", {}, {"site": "lab"}, fake)
        self.assertEqual(output["status"], "ok")
        self.assertEqual(output["protocol_version"], 1)
        values = {m["name"].removeprefix("telvyn.proxmox."): m for m in output["metrics"]}
        self.assertEqual(values["cpu.usage"]["value"], 0.25)
        self.assertEqual(values["cpu.load5"]["value"], 0.2)
        self.assertEqual(values["rootfs.total"]["value"], 4096)
        rate = values["network.received.rate"]
        self.assertEqual((rate["value"], rate["type"], rate["unit"]), (200.5, "gauge", "byte_per_second"))
        from datetime import datetime
        self.assertEqual(datetime.fromisoformat(rate["timestamp"].replace("Z", "+00:00")).timestamp(), at)
        self.assertNotIn("network.received", values)
        self.assertEqual(values["physical_disk.capacity"]["resource_id"], "node/pve1/physical_disk/dev/sda")
        details = output["coverage"]["node_details"]["node/pve1"]
        self.assertEqual(details["network"][0]["bridge_ports"], "eno1")
        self.assertEqual(details["disks"][0]["health"], "PASSED")
        self.assertEqual(details["configuration"], {"startall-onboot-delay": 10})
        for item in output["inventory"]:
            self.assertEqual(set(item), {"resource_id", "type", "name", "state", "parent_id", "observed_at"})
        self.assertNotIn("do-not-export", json.dumps(output, allow_nan=False))

    def test_proxmox_partial_endpoints_do_not_lose_base_or_other_nodes(self):
        rows = [{"type": "node", "id": "node/" + node, "node": node, "status": "online", "cpu": 0.5}
                for node in ("pve1", "pve2")]
        fake = FakeProxmox(rows, responses={
            "/nodes/pve1/status": urllib.error.HTTPError("https://unused", 403, "do-not-export", {}, None),
            "/nodes/pve1/network": {"invalid": "do-not-export"},
            "/nodes/pve1/disks/list": OSError("do-not-export"),
        })
        output = collect_proxmox("one", {}, {}, fake)
        self.assertEqual(output["status"], "partial")
        endpoints = output["coverage"]["node_details"]["node/pve1"]["endpoints"]
        self.assertEqual((endpoints["status"], endpoints["network"], endpoints["disks/list"]),
                         ("forbidden", "invalid", "unavailable"))
        self.assertEqual(len([m for m in output["metrics"] if m["name"].endswith("cpu.usage")]), 2)
        self.assertIn("node/pve2", output["coverage"]["node_details"])
        self.assertNotIn("do-not-export", json.dumps(output))

    def test_proxmox_rrd_missing_stale_nonfinite_never_fabricates_rates(self):
        rows = [{"type": "node", "id": "node/pve1", "status": "online"}]
        for samples in ([], [{"time": time.time() - 600, "netin": 10, "netout": 20}],
                        [{"time": time.time() - 60, "netin": math.inf, "netout": -1}],
                        [{"time": True, "netin": 1}], [None, {"time": "bad"}]):
            with self.subTest(samples=samples):
                fake = FakeProxmox(rows, responses={"/nodes/pve1/rrddata?timeframe=hour&cf=AVERAGE": samples})
                output = collect_proxmox("one", {}, {}, fake)
                self.assertEqual(output["status"], "partial")
                self.assertFalse(any(m["name"].endswith(".rate") for m in output["metrics"]))
                json.dumps(output, allow_nan=False)

    def test_proxmox_offline_node_does_not_request_details(self):
        fake = FakeProxmox([{"type": "node", "id": "node/pve1", "status": "offline"}])
        output = collect_proxmox("one", {}, {}, fake)
        self.assertEqual(fake.paths, ["/cluster/resources", "/cluster/status", "/cluster/ha/status/current"])
        self.assertEqual(output["inventory"][0]["state"], "offline")

    def test_proxmox_missing_direction_does_not_turn_into_zero(self):
        fake = FakeProxmox([{"type": "node", "id": "node/pve1", "status": "online"}], responses={
            "/nodes/pve1/rrddata?timeframe=hour&cf=AVERAGE": [{"time": time.time() - 60, "netin": 0}],
        })
        output = collect_proxmox("one", {}, {}, fake)
        rates = [m for m in output["metrics"] if m["name"].endswith(".rate")]
        self.assertEqual(output["status"], "partial")
        self.assertEqual([(m["name"], m["value"]) for m in rates], [("telvyn.proxmox.network.received.rate", 0)])

    def test_proxmox_details_respect_runner_limits_and_filter_malformed_children(self):
        fake = FakeProxmox([{"type": "node", "id": "node/pve1", "status": "online"}], responses={
            "/nodes/pve1/network": [None, {"iface": "bad?token=hidden"}] + [
                {"iface": "eth" + str(i), "active": 1, "bridge_ports": "x" * 256} for i in range(1100)],
        })
        output = collect_proxmox("one", {}, {}, fake)
        self.assertEqual(output["status"], "partial")
        self.assertLessEqual(len(output["metrics"]), 500)
        self.assertLessEqual(len(output["inventory"]), 1000)
        self.assertLess(len(json.dumps(output["coverage"]).encode()), 8192)
        self.assertTrue(output["coverage"]["node_details_truncated"])
        self.assertTrue(output["coverage"]["result_truncated"])
        self.assertNotIn("hidden", json.dumps(output))

    def test_proxmox_client_preserves_verified_tls_get_and_no_redirect(self):
        from unittest.mock import MagicMock
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = b'{"data":[]}'
        with patch("proxmox.check.ssl.create_default_context") as tls, \
                patch("proxmox.check.urllib.request.build_opener", return_value=opener):
            client = ProxmoxClient({"endpoint": "https://example.test:8006", "token_id": "synthetic",
                                    "token_secret": "synthetic", "ca_file": "test-ca.pem"})
            self.assertEqual(client.get("/nodes/pve1/network"), [])
            tls.assert_called_once_with(cafile="test-ca.pem")
            request = opener.open.call_args.args[0]
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.full_url, "https://example.test:8006/api2/json/nodes/pve1/network")
            with self.assertRaises(urllib.error.HTTPError):
                _NoRedirect().redirect_request(request, None, 302, "redirect", {}, "https://other.test")

    def test_proxmox_inline_ca_loads_with_real_ssl_and_keeps_verification(self):
        # Public trust anchor only; no private key or deployed credentials.
        ca = ssl.DER_cert_to_PEM_cert(ssl.create_default_context().get_ca_certs(binary_form=True)[0])
        params = {"endpoint": "https://example.test:8006", "token_id": "synthetic",
                  "token_secret": "synthetic", "ca_pem": ca}
        with patch("proxmox.check.urllib.request.build_opener") as opener:
            ProxmoxClient(params)
            context = opener.call_args.args[1]._context
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            self.assertGreater(context.cert_store_stats()["x509"], 0)
        with patch("proxmox.check.ssl.create_default_context", wraps=ssl.create_default_context) as tls:
            ProxmoxClient({**params, "ca_pem": ca + ca})
            tls.assert_called_once_with(cafile=None, cadata=ca + ca)

    def test_proxmox_invalid_ca_fails_closed_before_any_request(self):
        params = {"endpoint": "https://example.test:8006", "token_id": "synthetic",
                  "token_secret": "do-not-export"}
        for ca in ("", "not-a-certificate", "/local/ca.pem", 7, b"DER-not-PEM",
                   "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
                   "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"):
            with self.subTest(kind=type(ca).__name__), patch("proxmox.check.urllib.request.build_opener") as opener:
                output = collect_proxmox("one", {**params, "ca_pem": ca}, {})
                self.assertEqual(output["status"], "error")
                self.assertEqual(output["error"], "invalid_configuration_or_response")
                self.assertEqual(output["metrics"], [])
                opener.assert_not_called()
                self.assertNotIn("do-not-export", json.dumps(output))

    def test_proxmox_inline_ca_does_not_ignore_legacy_ca_file(self):
        ca = ssl.DER_cert_to_PEM_cert(ssl.create_default_context().get_ca_certs(binary_form=True)[0])
        with patch("proxmox.check.ssl.create_default_context", side_effect=FileNotFoundError), \
                patch("proxmox.check.urllib.request.build_opener") as opener:
            output = collect_proxmox("one", {"endpoint": "https://example.test:8006",
                                             "token_id": "synthetic", "token_secret": "synthetic",
                                             "ca_pem": ca, "ca_file": "missing-ca.pem"}, {})
            self.assertEqual(output["status"], "error")
            opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
