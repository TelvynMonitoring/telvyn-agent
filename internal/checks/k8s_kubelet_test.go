package checks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type summaryFixture struct{ summary *kubeletSummary }

func TestContainerCPUUsesCounterRateAndDoesNotMixRestartedIdentities(t *testing.T) {
	at := time.Unix(1000, 0)
	previous := kubeletCPUSample{value: 1000000000, time: at}
	for _, row := range []struct {
		sample kubeletCPUSample
		want   float64
		valid  bool
	}{
		{kubeletCPUSample{value: 3500000000, time: at.Add(10 * time.Second)}, 250000000, true},
		{kubeletCPUSample{value: 1000000000, time: at.Add(10 * time.Second)}, 0, true},
		{kubeletCPUSample{value: 1, time: at.Add(10 * time.Second)}, 0, false},
		{kubeletCPUSample{value: 2000000000, time: at}, 0, false},
	} {
		value, valid := kubeletContainerCPURate(previous, row.sample)
		if value != row.want || valid != row.valid {
			t.Fatal(value, valid, row)
		}
	}
	var summary kubeletSummary
	if err := json.Unmarshal([]byte(`{"node":{"nodeName":"node"},"pods":[{"podRef":{"namespace":"ns","name":"pod","uid":"uid"},"containers":[{"name":"app","startTime":"start","cpu":{"usageNanoCores":999,"usageCoreNanoSeconds":3500000000}}]}]}`), &summary); err != nil {
		t.Fatal(err)
	}
	check := k8sKubeletCheck{fetcher: summaryFixture{&summary}, containerCPU: map[string]kubeletCPUSample{"node|ns|pod|uid|app|start": {value: 1000000000, time: time.Now().Add(-10 * time.Second)}, "removed": previous}}
	metrics, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, metric := range metrics {
		if metric.MetricName == "k8s.container.cpu_usage_nanocores" {
			found = true
			if metric.Value < 240000000 || metric.Value > 260000000 {
				t.Fatal(metric)
			}
		}
	}
	if !found || len(check.containerCPU) != 1 {
		t.Fatal(found, check.containerCPU)
	}
	for _, change := range []func(){
		func() { summary.Pods[0].PodRef.UID = "new-uid" },
		func() { summary.Pods[0].Containers[0].StartTime = "restart" },
	} {
		change()
		metrics, err = check.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, metric := range metrics {
			if metric.MetricName == "k8s.container.cpu_usage_nanocores" {
				t.Fatal("first sample must not fabricate a rate", metric)
			}
		}
	}
}

func TestPodSummaryNetworkKeepsDefaultInterfaceOnlyOnNetworkSamples(t *testing.T) {
	var summary kubeletSummary
	if err := json.Unmarshal([]byte(`{"pods":[{"podRef":{"namespace":"ns","name":"pod"},"cpu":{"usageNanoCores":1},"network":{"name":"eth0","rxBytes":0,"txBytes":2}}]}`), &summary); err != nil {
		t.Fatal(err)
	}
	check := k8sKubeletCheck{fetcher: summaryFixture{&summary}}
	metrics, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, metric := range metrics {
		if strings.HasPrefix(metric.MetricName, "k8s.pod.network_") {
			seen++
			if metric.Tags["interface"] != "eth0" || metric.Tags["pod"] != "pod" {
				t.Fatal(metric)
			}
		} else if metric.Tags["interface"] != "" {
			t.Fatal("network tag leaked into unrelated signal", metric)
		}
	}
	if seen != 2 {
		t.Fatal(metrics)
	}
}

func TestCadvisorPacketsOperationsAndInvalidStartKeepScope(t *testing.T) {
	metrics, err := (&k8sKubeletCheck{}).parseCadvisor(strings.NewReader(`container_network_receive_packets_total{namespace="ns",pod="pod",container="POD",interface="eth0"} 8
container_fs_reads_total{namespace="ns",pod="pod",container="app",device="/dev/vda"} 4
container_start_time_seconds{namespace="ns",pod="pod",container="app"} 0
container_start_time_seconds{namespace="ns",pod="pod",container="app"} 999999999999
`), "node")
	if err != nil || len(metrics) != 4 {
		t.Fatal(metrics, err)
	}
	if metrics[0].MetricName != "k8s.pod.network_rx_packets_total" || metrics[0].Tags["interface"] != "eth0" || metrics[1].MetricName != "k8s.container.fs_reads_total" || metrics[1].Tags["device"] != "/dev/vda" {
		t.Fatal(metrics)
	}
}

func TestCadvisorContainerDiagnosticsKeepCountersAndUnlimitedThreads(t *testing.T) {
	check := k8sKubeletCheck{}
	metrics, err := check.parseCadvisor(strings.NewReader(`container_memory_kernel_usage{namespace="ns",pod="pod",container="app"} 0
container_oom_events_total{namespace="ns",pod="pod",container="app"} 2
container_file_descriptors{namespace="ns",pod="pod",container="app"} 7
container_threads{namespace="ns",pod="pod",container="app"} 3
container_threads_max{namespace="ns",pod="pod",container="app"} 0
container_start_time_seconds{namespace="ns",pod="pod",container="app"} 1791300000
container_threads{namespace="ns",pod="pod",container="POD"} 99
container_oom_events_total{namespace="ns",pod="pod",container="app"} NaN
`), "node")
	if err != nil || len(metrics) != 6 {
		t.Fatalf("unexpected diagnostics: %v, %v", metrics, err)
	}
	want := map[string]float64{"memory_oom_events_total": 2, "open_file_descriptors": 7, "threads": 3, "threads_limit": 0, "start_time_seconds": 1791300000}
	for _, metric := range metrics {
		suffix := strings.TrimPrefix(metric.MetricName, "k8s.container.")
		if suffix == "uptime_seconds" {
			if metric.Value != float64(metric.Time.Seconds)+float64(metric.Time.Nanos)/1e9-1791300000 {
				t.Fatal(metric)
			}
			continue
		}
		value, exists := want[suffix]
		if !exists || metric.Value != value || metric.Source != "k8s.cadvisor" || metric.Tags["container"] != "app" {
			t.Fatalf("wrong unit, entity or value: %v", metric)
		}
		delete(want, suffix)
	}
	if len(want) != 0 {
		t.Fatal(want)
	}
}

func TestCadvisorMemoryRatiosUseSameContainerAndIgnoreMissingOrZeroLimits(t *testing.T) {
	check := k8sKubeletCheck{}
	metrics, err := check.parseCadvisor(strings.NewReader(`container_spec_memory_limit_bytes{namespace="ns",pod="pod",container="app"} 200
container_memory_usage_bytes{namespace="ns",pod="pod",container="app"} 50
container_memory_swap{namespace="ns",pod="pod",container="app"} 10
container_spec_memory_swap_limit_bytes{namespace="ns",pod="pod",container="app"} 40
container_cpu_load_average_10s{namespace="ns",pod="pod",container="app"} 0
container_memory_usage_bytes{namespace="ns",pod="pod",container="other"} 999
container_spec_memory_limit_bytes{namespace="ns",pod="pod",container="other"} 0
container_spec_memory_limit_bytes{namespace="ns",pod="missing",container="app"} 100
`), "node")
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, metric := range metrics {
		if strings.HasSuffix(metric.MetricName, "_fraction") && (metric.Tags["container"] != "app" || metric.Tags["pod"] != "pod") {
			t.Fatalf("fabricated or cross-container ratio: %v", metric)
		}
		if metric.Tags["container"] == "app" && metric.Tags["pod"] == "pod" {
			values[metric.MetricName] = metric.Value
		}
	}
	if values["k8s.container.memory_usage_fraction"] != .25 || values["k8s.container.memory_swap_usage_fraction"] != .25 {
		t.Fatal(values)
	}
	if load, exists := values["k8s.container.cpu_load_10s_avg"]; !exists || load != 0 {
		t.Fatal(values)
	}
}

func (f summaryFixture) Summary(context.Context) (*kubeletSummary, error) { return f.summary, nil }

func TestKubeletContainerRSSIsIndependentFromWorkingSet(t *testing.T) {
	var summary kubeletSummary
	if err := json.Unmarshal([]byte(`{"node":{"nodeName":"node"},"pods":[{"podRef":{"name":"pod","namespace":"ns"},"containers":[{"name":"app","memory":{"workingSetBytes":100,"rssBytes":80}},{"name":"missing"}]}]}`), &summary); err != nil {
		t.Fatal(err)
	}
	check := k8sKubeletCheck{fetcher: summaryFixture{&summary}}
	metrics, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, metric := range metrics {
		if metric.Tags["container"] == "missing" {
			t.Fatalf("fabricated sample: %v", metric)
		}
		if metric.Tags["container"] == "app" {
			values[metric.MetricName] = metric.Value
		}
	}
	if values["k8s.container.memory_rss_bytes"] != 80 || values["k8s.container.memory_working_set_bytes"] != 100 {
		t.Fatalf("RSS and working set must remain distinct: %v", values)
	}
}

func TestCadvisorFailurePreservesSummaryAndReportsCoverage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stats/summary" {
			_, _ = w.Write([]byte(`{"node":{"nodeName":"node","cpu":{"usageNanoCores":42},"fs":{"usedBytes":25,"capacityBytes":100},"runtime":{"imageFs":{"usedBytes":1,"capacityBytes":0}}}}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	check := k8sKubeletCheck{fetcher: &httpKubeletFetcher{url: server.URL + "/stats/summary", client: server.Client()}}
	metrics, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, metric := range metrics {
		values[metric.MetricName] = metric.Value
	}
	if values["k8s.node.cpu_usage_nanocores"] != 42 {
		t.Fatalf("Summary lost: %v", values)
	}
	if values["k8s.node.fs_usage_fraction"] != 0.25 {
		t.Fatalf("filesystem ratio lost: %v", values)
	}
	if _, exists := values["k8s.node.image_fs_usage_fraction"]; exists {
		t.Fatal("zero capacity must not fabricate image filesystem usage")
	}
	up, exists := values["k8s.node.cadvisor_up"]
	if !exists || up != 0 {
		t.Fatalf("missing coverage failure: %v", values)
	}
}

func TestCadvisorAddsOnlyMissingSignalsAndKeepsPodNetworkScope(t *testing.T) {
	check := k8sKubeletCheck{}
	metrics, err := check.parseCadvisor(strings.NewReader(`container_cpu_cfs_throttled_seconds_total{namespace="ns",pod="pod",container="app"} 3
container_memory_working_set_bytes{namespace="ns",pod="pod",container="app"} 100
container_network_receive_errors_total{namespace="ns",pod="pod",container="POD",interface="eth0"} 2 1791342603227
container_memory_usage_bytes{namespace="ns",pod="pod",container=""} 999
container_memory_usage_bytes{namespace="ns",pod="pod",container="app"} NaN
`), "node")
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 2 {
		t.Fatalf("duplicated or invalid metrics: %v", metrics)
	}
	if metrics[0].MetricName != "k8s.container.cpu_cfs_throttled_seconds_total" || metrics[0].Value != 3 {
		t.Fatal(metrics[0])
	}
	if metrics[1].MetricName != "k8s.pod.network_rx_errors_total" || metrics[1].Tags["interface"] != "eth0" || metrics[1].Tags["container"] != "" {
		t.Fatal(metrics[1])
	}
}

func TestKubeletOperationalMetricsKeepUnitsAndOnlySafeLabels(t *testing.T) {
	check := k8sKubeletCheck{}
	metrics, err := check.parseOperational(strings.NewReader(`kubelet_runtime_operations_duration_seconds_sum{operation_type="start_container",url="https://secret"} 1.5
kubelet_runtime_operations_duration_seconds_bucket{operation_type="start_container",le="1"} 9
prober_probe_total{namespace="ns",pod="pod",container="app",probe_type="Readiness",result="failed",pod_uid="uid"} 3
prober_probe_total{namespace="ns",pod="pod",container="app",probe_type="bogus",result="failed"} 99
kubernetes_healthcheck{name="ping",type="healthz"} 1
rest_client_request_duration_seconds_sum{verb="GET",host="10.43.0.1:443",url="https://user:password@10.43.0.1:443/api/v1/pods?token=secret"} 2.5
go_threads -1
kubelet_runtime_operations_duration_seconds_bucket{operation_type="start_container",le="+Inf"} 12
kubelet_runtime_operations_duration_seconds_bucket{operation_type="start_container",le="NaN"} 999
kubelet_runtime_operations_duration_seconds_bucket{operation_type="start_container",le="-1"} 999
kubelet_runtime_operations_duration_seconds_bucket{operation_type="start_container"} 999
`), "node")
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 6 {
		t.Fatalf("unexpected metrics: %v", metrics)
	}
	if metrics[0].MetricName != "k8s.kubelet.runtime_operations_duration_seconds_sum" || metrics[0].Value != 1.5 || metrics[0].Tags["url"] != "" {
		t.Fatal(metrics[0])
	}
	if metrics[1].MetricName != "k8s.kubelet.runtime_operations_duration_seconds_bucket" || metrics[1].Tags["le"] != "1" || metrics[1].Value != 9 || metrics[5].Tags["le"] != "+Inf" || metrics[5].Value != 12 {
		t.Fatal(metrics)
	}
	if metrics[2].MetricName != "k8s.container.readiness_probe_failure_total" || metrics[2].Tags["container"] != "app" || metrics[2].Tags["pod_uid"] != "" {
		t.Fatal(metrics[1])
	}
	if metrics[3].Tags["sli_name"] != "ping" || metrics[3].Tags["type"] != "" {
		t.Fatal(metrics[2])
	}
	if metrics[4].Value != 2.5 || metrics[4].Tags["url"] != "/api/v1/pods" || metrics[4].Tags["verb"] != "GET" || metrics[4].Tags["host"] != "10.43.0.1:443" {
		t.Fatal(metrics[3])
	}
}
