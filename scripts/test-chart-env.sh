#!/bin/sh
set -eu
chart="${1:-charts/ispwatch-agent}"
for ebpf in false true; do
  helm template validation "$chart" --show-only templates/daemonset.yaml \
    --set ingest.url=https://example.com --set ingest.token=validation-only \
    --set ebpfTracing.enabled="$ebpf" |
    awk '
      /- name: ISPWATCH_/ { sub(/\r$/, ""); count[$3]++ }
      END {
        bad = 0
        for (name in count) if (count[name] != 1) { print "Duplicate: " name; bad = 1 }
        if (count["ISPWATCH_KUBELET_URL"] != 1 ||
            count["ISPWATCH_KUBELET_TOKEN_FILE"] != 1 ||
            count["ISPWATCH_KUBELET_INSECURE"] != 1) bad = 1
        exit bad
      }'
done
echo "PASS: unique kubelet environment with eBPF enabled and disabled"
