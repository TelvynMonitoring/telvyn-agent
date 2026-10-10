# Proxmox integration

The official image and Linux archive include the reviewed Proxmox collector.
It reads inventory, CPU, memory, disks and network through the HTTPS Proxmox API.
It does not install anything in the hypervisor or replace existing collectors.

## Kubernetes collector

Enable `proxmox.enabled=true` and set `proxmox.allowedEndpoints` to the exact HTTPS
endpoint(s), comma-separated. Keep the same spelling in the portal. Configure
**Servers → Add server → Proxmox**, choose this collector, enter a read-only
Proxmox API token, and provide the CA certificate for a private certificate.
TLS validation remains mandatory; redirects and ambient proxies are rejected.

## Linux collector

Python 3 must be installed through the OS package manager. Set the following
local environment before using the normal installer (or in the existing
agent's environment file, followed by its controlled restart):

```
TELVYN_EXTERNAL_EXECUTION_MODE=approved-unisolated
TELVYN_EXTERNAL_APPROVED_ENDPOINTS=https://your-proxmox:8006
```

The release installs packages and trust metadata under `/opt/telvyn/integrations`.
These files must remain administrator-owned and not writable by the collector.
The Python subprocess is trusted release code, not an OS sandbox. It runs under
the collector's OS permissions, with bounded input, output and execution time.
Do not enable arbitrary third-party packages without reviewing their code.

Each release generates package hashes and an integrity signature with an
ephemeral build key. The private key is never distributed. Because the matching
public key ships in the same release, this signature checks local integrity;
it does **not** independently authenticate the publisher. Obtain the release
only from the official repository/registry over HTTPS and verify its checksum.

Package protocol versions 0.1.0 and 0.1.2 are included for deployed backend
compatibility. Unknown package versions fail closed. Partial API permissions
produce partial coverage; missing values are not replaced with zero. Resource
and response-size limits remain explicit. No claim of complete Datadog parity.
