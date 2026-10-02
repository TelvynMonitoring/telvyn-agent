"""One invocation, one JSON request on stdin, one JSON response on stdout."""

import argparse
import json
import sys
from pathlib import Path

# -I removes the script directory from sys.path. The Go installer must verify this
# directory's signed package before execution; never add cwd or user site-packages.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import result


def run(check, request):
    if not isinstance(request, dict) or request.get("protocol_version") != 1:
        return result(status="error", error="unsupported_protocol_version")
    if not isinstance(request.get("instance_id"), str) or not request["instance_id"]:
        return result(status="error", error="invalid_instance_id")
    if not isinstance(request.get("params"), dict) or not isinstance(request.get("static_tags"), dict):
        return result(status="error", error="invalid_params_or_tags")
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in request["static_tags"].items()):
        return result(status="error", error="invalid_static_tags")
    if any(any(word in key.lower() for word in ("password", "secret", "token", "credential", "authorization", "api_key"))
           for key in request["static_tags"]):
        return result(status="error", error="secret_tag_rejected")
    try:
        if check == "proxmox":
            from proxmox.check import collect
        elif check == "vsphere":
            from vsphere.check import collect
        else:
            return result(status="error", error="unknown_check")
        return collect(request["instance_id"], request["params"], request["static_tags"])
    except (ValueError, KeyError):
        return result(status="error", error="invalid_configuration")
    except Exception:
        # Never echo an exception: SDK/network errors can contain URLs or credentials.
        return result(status="error", error="collection_failed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", required=True, choices=("proxmox", "vsphere"))
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(1_048_577)
        if len(raw) > 1_048_576:
            output = result(status="error", error="request_too_large")
        else:
            output = run(args.check, json.loads(raw))
    except (ValueError, UnicodeError):
        output = result(status="error", error="invalid_json")
    sys.stdout.write(json.dumps(output, allow_nan=False, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
