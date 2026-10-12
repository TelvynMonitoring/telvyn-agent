package checks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ispwatch/collector/internal/quarkus"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (h *httpKubeletFetcher) prometheusBody(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(h.url, "/stats/summary")+path, nil)
	if err != nil {
		return nil, err
	}
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (32<<20)+1))
	if len(body) > 32<<20 {
		return nil, fmt.Errorf("kubelet metrics response exceeds 32 MiB")
	}
	return body, err
}

// Use the same kubelet endpoints as DD's kubelet check. Durations remain in
// seconds and counters remain cumulative; the portal applies rate()/increase().
func (c *k8sKubeletCheck) parseOperational(body io.Reader, node string) ([]*collectorv1.Metric, error) {
	gauges := map[string]string{
		"go_threads": "go_threads", "go_goroutines": "go_goroutines",
		"rest_client_requests_total":              "rest_client_requests_total",
		"kubelet_pleg_last_seen_seconds":          "pleg_last_seen_seconds",
		"kubelet_runtime_operations_total":        "runtime_operations_total",
		"kubelet_runtime_operations_errors_total": "runtime_errors_total",
		"kubelet_evictions":                       "evictions_total", "kubelet_pleg_discard_events": "pleg_discard_events_total",
		"kubelet_cpu_manager_pinning_errors_total":    "cpu_manager_pinning_errors_total",
		"kubelet_cpu_manager_pinning_requests_total":  "cpu_manager_pinning_requests_total",
		"kubelet_container_log_filesystem_used_bytes": "container_log_filesystem_used_bytes",
		"kubelet_volume_stats_available_bytes":        "volume_stats_available_bytes",
		"kubelet_volume_stats_capacity_bytes":         "volume_stats_capacity_bytes",
		"kubelet_volume_stats_used_bytes":             "volume_stats_used_bytes",
		"kubelet_volume_stats_inodes":                 "volume_stats_inodes",
		"kubelet_volume_stats_inodes_free":            "volume_stats_inodes_free",
		"kubelet_volume_stats_inodes_used":            "volume_stats_inodes_used",
		"kubernetes_healthcheck":                      "healthcheck", "kubernetes_healthchecks_total": "healthchecks_total",
	}
	histograms := []string{
		"apiserver_client_certificate_expiration_seconds", "kubelet_pleg_relist_duration_seconds",
		"kubelet_pleg_relist_interval_seconds", "kubelet_containers_per_pod_count",
		"kubelet_network_plugin_operations_duration_seconds", "kubelet_pod_start_duration_seconds",
		"kubelet_pod_worker_duration_seconds", "kubelet_pod_worker_start_duration_seconds",
		"kubelet_runtime_operations_duration_seconds", "rest_client_request_duration_seconds",
	}
	for _, base := range histograms {
		for _, suffix := range []string{"_sum", "_count", "_bucket"} {
			gauges[base+suffix] = strings.TrimPrefix(base, "kubelet_") + suffix
		}
	}
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 65536), 4<<20)
	now := timestamppb.Now()
	var out []*collectorv1.Metric
	for scanner.Scan() {
		name, labels, value, valid := quarkus.ParseLine(scanner.Text())
		if !valid || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		suffix, supported := gauges[name]
		prefix := "k8s.kubelet."
		if name == "prober_probe_total" {
			probe := map[string]string{"Liveness": "liveness", "Readiness": "readiness", "Startup": "startup"}[labels["probe_type"]]
			result := map[string]string{"successful": "success", "failed": "failure", "unknown": "unknown"}[labels["result"]]
			if probe == "" || result == "" || labels["namespace"] == "" || labels["pod"] == "" || labels["container"] == "" {
				continue
			}
			suffix, supported, prefix = probe+"_probe_"+result+"_total", true, "k8s.container."
		}
		if !supported {
			continue
		}
		tags := map[string]string{"node": node}
		if strings.HasSuffix(name, "_bucket") {
			bound, err := strconv.ParseFloat(labels["le"], 64)
			if err != nil || math.IsNaN(bound) || bound < 0 {
				continue
			}
			tags["le"] = strconv.FormatFloat(bound, 'g', -1, 64)
		}
		for _, key := range []string{"namespace", "pod", "container", "operation_type", "method", "verb", "host", "code", "persistentvolumeclaim", "name", "status", "eviction_signal"} {
			if v := labels[key]; v != "" {
				if key == "name" {
					tags["sli_name"] = v
				} else {
					tags[key] = v
				}
			}
		}
		if strings.HasPrefix(name, "rest_client_request_duration_seconds_") {
			if parsed, err := url.Parse(labels["url"]); err == nil && parsed.Path != "" {
				// Match DD's REST dimension without retaining credentials or query parameters.
				tags["url"] = parsed.Path
			}
		}
		out = append(out, c.metric(now, prefix+suffix, value, tags))
	}
	return out, scanner.Err()
}
