# Telvyn virtualization checks (protocol v1)

Status: prototype, not Datadog Python-check parity. Persistent CPython/SDK lifecycle, typed aggregation and real-hypervisor validation remain pending; see [parity matrix](../docs/DATADOG-PYTHON-CHECKS-PARITY.md). No automatic remote installer or updater is included.

Independent Python 3 checks; no Datadog code is reused. The Datadog [Proxmox](https://docs.datadoghq.com/integrations/proxmox/) and [vSphere](https://docs.datadoghq.com/integrations/vsphere/) catalogs and the official vSphere implementation reference [`vsphere/vsphere.py`](https://github.com/DataDog/integrations-core/blob/master/vsphere/datadog_checks/vsphere/vsphere.py) (not `check.py`) were used only to compare scope. These checks poll inventory and performance; they do **not** replace SDK/OTLP application tracing or streamed logs.

## Runner / package handoff to Edward

Edward's `internal/checkpackages/verify.go` verifies a locally administrator-provisioned package rooted at `<package-root>/<NAME>/<VERSION>/`. Copy **the contents** of `integrations/` into that version directory, not the enclosing `integrations` directory; the runner path is `<package-root>/<NAME>/<VERSION>/runner.py`. Execute exactly `python3 -I -B <verified-runner-path> --check proxmox|vsphere` with one UTF-8 JSON object on stdin, max 1 MiB. `-I` removes scriptdir from `sys.path`; runner adds only its own resolved directory, verified before execution. `-B` prevents `__pycache__` from changing the signed file set. No shell, cwd imports, runtime pip, agent token, or raw exception text. One compact JSON object on stdout. The Go executor must set process timeout/output limits and validate the response. Current `approved-unisolated` mode is **not** a sandbox and does not constrain Python filesystem/network access; deployment requires explicit administrator trust and risk acceptance.

Input: `{ "protocol_version":1, "instance_id":"...", "params":{"...":"..."}, "static_tags":{"site":"..."} }`. Config values are strings, including `include_version: "true"`. The Go side must not put secrets in `static_tags`; runner also rejects credential-like tag keys. Reserve secrets for `params`, delivered by a protected channel. Output: `{ "protocol_version":1, "metrics":[{"name":"...","value":1.0,"type":"gauge|count","unit":"...","timestamp":"UTC ISO-8601","resource_id":"...","tags":{}}], "inventory":[{"resource_id":"...","type":"...","name":"...","state":"...","parent_id":null,"observed_at":"UTC ISO-8601"}], "status":"ok|partial|error", "coverage":{}, "error":null }`. Error values are fixed codes, never exception strings. `count` means provider cumulative counter, **not** a derived rate.

Edward's verifier accepts an exact-byte Ed25519-signed `manifest.json` plus base64 `manifest.sig`; trusted public keys are local **outside** the package. Manifest fields: `name`, `version`, `key_id`, `protocol_version: 1`, `runtime: "python3"`, host `goos`/`goarch`, `isolation_mode: "approved-unisolated"`, `checks: ["proxmox","vsphere"]`, and SHA-256 `files` map. The package may contain only declared `.py`/`.txt` files (at most 32, each at most 512 KiB); package `runner.py`, `common.py`, `proxmox/*.py`, `vsphere/*.py` and optionally `requirements-vsphere.txt`. **Exclude** this README, tests, fixtures and any `__pycache__`/`.pyc` from that package. Do not create a signature until final contents are frozen. There is no installer, automatic update, wheelhouse or atomic rollback in this stage; local administrator provisioning and prior runtime dependency installation are prerequisites. No private signing key belongs in this tree. `requirements-vsphere.txt` is a **candidate** pyVmomi pin, not a verified compatibility or hash lock; the local administrator must approve vCenter/Python compatibility and install a fully hashed, versioned offline dependency bundle before execution. This directory does not contain a signed manifest and is not deployable as-is.

## Configuration / scope

### Go agent activation

The initial Go agent binary must be updated once to include `external.python`. After that, compatible signed Python package versions can change without rebuilding Go. This is not an automatic package updater.

Local administrator configuration (not remote check parameters):

| Environment variable | Purpose |
|---|---|
| `TELVYN_EXTERNAL_PACKAGE_DIR` | Absolute root of locally provisioned signed packages |
| `TELVYN_EXTERNAL_TRUST_DIR` | Absolute directory of trusted base64 Ed25519 `<key_id>.pub` files, outside the package tree |
| `TELVYN_EXTERNAL_PYTHON` | Absolute path of the administrator-managed Python executable |
| `TELVYN_EXTERNAL_EXECUTION_MODE` | Explicit `approved-unisolated` opt-in; otherwise execution is refused |
| `TELVYN_EXTERNAL_APPROVED_ENDPOINTS` | Comma-separated exact endpoint allowlist approved on the collector |

CheckConfig uses `check_type: "external.python"`, a UUID `check_id`, the authorized `host_id`, and string params `package`, `version`, `check` (`proxmox` or `vsphere`) plus the integration settings below. The registry uses the existing scheduler; no new scheduler or ingestion token is configured in Python. Package/trust/runtime directories must be writable only by the provisioning administrator, not remotely controlled users or the check process. A verified package is trusted executable code, not a sandbox.

Inventory snapshots are currently retained locally; backend host discovery and portal configuration have not been wired. The current metric ingestion encodes gauges: cumulative `count` output is omitted and recorded in coverage rather than mislabeled as a gauge. Do not infer full Datadog parity or production rollout from the local tests.

Proxmox: `endpoint` = `https://host:8006` or `https://host:8006/api2/json`, `token_id`, `token_secret`, optional `ca_file`, `timeout_seconds` (1–30), `include_version` (`"true"`/`"false"`). HTTPS certificate verification is mandatory; redirects and ambient proxies are rejected. Only GET `/cluster/resources` and optional GET `/version`. Proxmox recommends read-only `PVEAuditor` tokens. VM/CT stopped entries remain in inventory; runtime counters for them are omitted. Source endpoint does not expose a sample timestamp in this response: `timestamp` and `observed_at` are collector receipt time, **not** proof of provider freshness. No per-disk/per-NIC or historical series. Optional `/version` failure yields `partial`; version is coverage only, not a metric.

vSphere: `endpoint` = `https://vcenter-host`, `endpoint_kind` = `vcenter`, `username`, `password`, optional `ca_file`. Requires preinstalled `pyVmomi` from the verified offline runtime bundle; absent dependency returns `pyvmomi_missing` without pip/network installation. Direct ESXi is not a supported target. Uses read-only ContainerView for ESXi hosts, VMs (including powered-off), datastores; QueryAvailablePerfMetric/QueryPerf for available aggregate real-time host and powered-on VM counters, latest sample only. A per-entity performance failure is `partial` with successful samples retained. Inventory timestamps are collector time; performance timestamps are the provider `sampleInfo.timestamp`. Datastore capacity/free are inventory properties. Relations: VM → runtime.host when present. No cluster/resource-pool/per-datastore performance or per-device instance metrics in this first scope. vCenter permissions and statistics collection level can reduce coverage; `coverage` reports that but does not fabricate zeroes.

## Metric de/para and units

| Provider field/counter | Telvyn name | unit / conversion | Related Datadog catalog |
|---|---|---|---|
| Proxmox `status` | `telvyn.proxmox.up` | boolean 0/1, status snapshot | `proxmox.node.up`, `proxmox.vm.up`, `proxmox.storage.up` |
| Proxmox `cpu` | `telvyn.proxmox.cpu.usage` | fraction | `proxmox.cpu` |
| Proxmox `mem`,`maxmem` | `telvyn.proxmox.memory.used`, `.capacity` | byte | `proxmox.mem.used`, `.max` |
| Proxmox `disk`,`maxdisk` | `telvyn.proxmox.disk.used`, `.capacity` | byte | `proxmox.disk.used`, `.max` |
| Proxmox `diskread`,`diskwrite`,`netin`,`netout` **when present** | `telvyn.proxmox.disk.read`, `.write`, `.network.received`, `.sent` | byte cumulative | `proxmox.disk.read`, `.write`, `.net.in`, `.out` |
| vSphere `cpu.usage.average` | `telvyn.vsphere.cpu.usage` | provider percent fixed point / 100; 2067 → 20.67 percent | `vsphere.cpu.usage.avg` |
| vSphere `mem.usage.average` | `telvyn.vsphere.memory.usage` | provider percent fixed point / 100 | `vsphere.mem.usage.avg` |
| vSphere `mem.consumed.average` | `telvyn.vsphere.memory.consumed` | kiloBytes × 1024 → byte | `vsphere.mem.consumed.avg` |
| vSphere `net.received/transmitted.average` | `telvyn.vsphere.network.received/sent` | kiloBytesPerSecond × 1024 → byte_per_second | `vsphere.net.received/transmitted.avg` |
| vSphere `disk.read/write.average` | `telvyn.vsphere.disk.read/write` | kiloBytesPerSecond × 1024 → byte_per_second | `vsphere.disk.read/write.avg` |
| vSphere datastore `capacity`,`freeSpace` | `telvyn.vsphere.datastore.capacity/free` | byte, inventory property | datastore capacity catalog |

Mappings follow provider units/counter metadata in Broadcom's [PerformanceManager](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.PerformanceManager.html), [CPU](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/cpu_counters.html), [memory](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/memory_counters.html), [network](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/network_counters.html), and [disk](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/disk_counters.html) API docs, and Proxmox's [REST API guide](https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf). Only provider fields actually present are emitted. No logs or credential parameters are output.

Light local tests: `python -I -B -m unittest discover -s integrations/tests -v` from stage root. These use fakes plus a real `-I -B` runner subprocess; **no hypervisor integration has been validated**. Linux transfer, package-signature verification, vCenter/Proxmox API compatibility and real-device acceptance remain for the principal after review.
