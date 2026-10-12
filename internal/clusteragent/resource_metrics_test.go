package clusteragent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetadataMetricsNeverRequestOrExportSecretValues(t *testing.T) {
	fullObjects := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if fullObjects {
			_, _ = w.Write([]byte(`{"kind":"SecretList","items":[{"metadata":{"name":"test"},"data":{"password":"NEVER_EXPORT"}}]}`))
			return
		}
		switch r.URL.Path {
		case "/api/v1/secrets":
			if r.Header.Get("Accept") != "application/json;as=Table;g=meta.k8s.io;v=v1" || r.URL.Query().Get("includeObject") != "Metadata" {
				t.Error("Secret must request metadata Table")
			}
			_, _ = w.Write([]byte(`{"kind":"Table","columnDefinitions":[{"name":"Name"},{"name":"Type"}],"rows":[{"cells":["test","Opaque"],"object":{"metadata":{"name":"test","namespace":"apps","annotations":{"private":"NEVER_EXPORT"}}}}]}`))
		case "/api/v1/configmaps":
			if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1" {
				t.Error("ConfigMap must request metadata only")
			}
			_, _ = w.Write([]byte(`{"kind":"PartialObjectMetadataList","items":[{"metadata":{"name":"settings","namespace":"apps","annotations":{"private":"NEVER_EXPORT"}}}]}`))
		default:
			_, _ = w.Write([]byte(`{"items":[]}`))
		}
	}))
	defer server.Close()
	a := Agent{cfg: Config{Cluster: "production", APIServerURL: server.URL, EventLimit: 100}, client: server.Client(), log: slog.Default()}
	metrics := a.collectStateExtras(context.Background())
	values := map[string]float64{}
	for _, metric := range metrics {
		values[metric.MetricName] = metric.Value
		if metric.MetricName == "k8s.secret.type" && metric.Tags["type"] != "Opaque" {
			t.Fatal(metric)
		}
	}
	for _, name := range []string{"k8s.secret.count", "k8s.secret.type", "k8s.configmap.count"} {
		if values[name] != 1 {
			t.Fatalf("missing %s", name)
		}
	}
	encoded, _ := json.Marshal(metrics)
	if strings.Contains(string(encoded), "NEVER_EXPORT") || strings.Contains(string(encoded), "annotations") {
		t.Fatal("private metadata exported")
	}
	fullObjects = true
	for _, metric := range a.collectStateExtras(context.Background()) {
		if strings.HasPrefix(metric.MetricName, "k8s.secret.") || strings.HasPrefix(metric.MetricName, "k8s.configmap.") {
			t.Fatal("accepted full object fallback")
		}
	}
}

func TestPodReadinessPreservesFalseAndUnknownConditions(t *testing.T) {
	pod, err := inventoryResource("Pod", []byte(`{"metadata":{"uid":"uid","name":"done","namespace":"ns"},"status":{"phase":"Succeeded","conditions":[{"type":"Ready","status":"False"},{"type":"PodScheduled","status":"True"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	a := Agent{cfg: Config{Cluster: "production"}}
	got := map[string]float64{}
	for _, metric := range a.inventoryMetrics([]map[string]any{pod}) {
		if metric.MetricName == "k8s.pod.ready" || metric.MetricName == "k8s.pod.scheduled" {
			got[metric.MetricName+"/"+metric.Tags["condition"]] = metric.Value
		}
	}
	if len(got) != 6 || got["k8s.pod.ready/false"] != 1 || got["k8s.pod.ready/true"] != 0 || got["k8s.pod.scheduled/true"] != 1 || got["k8s.pod.scheduled/unknown"] != 0 {
		t.Fatal(got)
	}
}

func TestPodMetricIdentityDoesNotSplitWorkloadTotals(t *testing.T) {
	pod, err := inventoryResource("Pod", []byte(`{"metadata":{"uid":"uid-a","name":"pod-a","namespace":"ns","ownerReferences":[{"kind":"ReplicaSet","name":"backend-123"}],"labels":{"app.kubernetes.io/name":"backend","private":"NEVER_EXPORT"}},"spec":{"nodeName":"node","priorityClassName":"critical","containers":[{"name":"app","resources":{"requests":{"cpu":"250m"}}}]},"status":{"phase":"Running"}}`))
	if err != nil {
		t.Fatal(err)
	}
	a := Agent{cfg: Config{Cluster: "production"}}
	owner := map[string]any{"kind": "ReplicaSet", "namespace": "ns", "name": "backend-123", "workload_kind": "Deployment", "workload_name": "backend"}
	for _, metric := range a.inventoryMetrics([]map[string]any{pod, owner}) {
		if metric.Tags["pod_name"] != "" && (metric.Tags["uid"] != "uid-a" || metric.Tags["pod_phase"] != "Running" || metric.Tags["kube_app_name"] != "backend" || metric.Tags["kube_priority_class"] != "critical" || metric.Tags["kube_replica_set"] != "backend-123" || metric.Tags["kube_node"] != "node" || metric.Tags["kube_deployment"] != "backend") {
			t.Fatalf("missing pod identity: %v", metric)
		}
		if strings.HasSuffix(metric.MetricName, ".total") && (metric.Tags["uid"] != "" || metric.Tags["kube_app_name"] != "") {
			t.Fatalf("pod labels split aggregate: %v", metric)
		}
		encoded, _ := json.Marshal(metric.Tags)
		if strings.Contains(string(encoded), "NEVER_EXPORT") {
			t.Fatal("arbitrary label exported")
		}
	}
}

func TestPodKeepsJobTagWhenJobHasCustomOwner(t *testing.T) {
	pod, err := inventoryResource("Pod", []byte(`{"metadata":{"uid":"uid","name":"pod","namespace":"ns","ownerReferences":[{"kind":"Job","name":"install"}]},"spec":{"nodeName":"node"},"status":{"phase":"Succeeded","conditions":[{"type":"Ready","status":"False"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	owner := map[string]any{"kind": "Job", "namespace": "ns", "name": "install", "workload_kind": "HelmChart", "workload_name": "chart"}
	a := Agent{cfg: Config{Cluster: "production"}}
	for _, metric := range a.inventoryMetrics([]map[string]any{pod, owner}) {
		if metric.Tags["pod_name"] != "" && metric.Tags["kube_job"] != "install" {
			t.Fatalf("direct Job owner lost: %v", metric.Tags)
		}
	}
}

func TestJobCountKeepsDistinctJobsWithUnsupportedOwnerKinds(t *testing.T) {
	a := Agent{cfg: Config{Cluster: "production"}}
	resources := []map[string]any{
		{"kind": "Job", "namespace": "kube-system", "name": "helm-install-traefik", "workload_kind": "HelmChart", "workload_name": "traefik"},
		{"kind": "Job", "namespace": "kube-system", "name": "helm-install-traefik-crd", "workload_kind": "HelmChart", "workload_name": "traefik-crd"},
	}
	jobs := map[string]float64{}
	for _, metric := range a.inventoryMetrics(resources) {
		if metric.MetricName == "k8s.job.count" {
			jobs[metric.Tags["kube_job"]] = metric.Value
		}
	}
	if len(jobs) != 2 || jobs["helm-install-traefik"] != 1 || jobs["helm-install-traefik-crd"] != 1 {
		t.Fatalf("distinct native Jobs collapsed: %v", jobs)
	}
}

func TestInventoryMetricsUseAPIQuantitiesWithoutFabricatingMissingLimits(t *testing.T) {
	for text, want := range map[string]float64{"250m": .25, "1Gi": 1073741824, "1e3": 1000, "0": 0, "500000n": .0005} {
		got, ok := resourceQuantity(text)
		if !ok || got != want {
			t.Fatalf("quantity %s = %v,%v", text, got, ok)
		}
	}
	for _, text := range []string{"", "-1", "NaN", "1MiB", "1e999"} {
		if _, ok := resourceQuantity(text); ok {
			t.Fatalf("accepted invalid quantity %q", text)
		}
	}
	pod, err := inventoryResource("Pod", []byte(`{"metadata":{"uid":"uid","name":"pod","namespace":"ns"},"spec":{"nodeName":"node","containers":[{"name":"app","resources":{"requests":{"cpu":"250m"},"limits":{"memory":"1Gi"}}}]},"status":{"containerStatuses":[{"name":"app","ready":true,"restartCount":2}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	a := Agent{cfg: Config{Cluster: "production"}}
	metrics := a.inventoryMetrics([]map[string]any{pod})
	values := map[string]float64{}
	for _, metric := range metrics {
		if metric.MetricName == "k8s.container.requests.cpu_cores.total" || metric.MetricName == "k8s.container.limits.memory_bytes.total" {
			continue
		}
		if metric.MetricName == "k8s.pod.count" {
			if metric.Value != 1 || metric.Tags["pod_name"] != "pod" {
				t.Fatal(metric)
			}
			continue
		}
		if metric.Tags["kube_container_name"] != "app" || metric.Tags["pod_name"] != "pod" {
			t.Fatal(metric)
		}
		values[metric.MetricName] = metric.Value
	}
	if len(values) != 4 || values["k8s.container.requests.cpu_cores"] != .25 || values["k8s.container.limits.memory_bytes"] != 1073741824 || values["k8s.container.restarts"] != 2 || values["k8s.container.ready"] != 1 {
		t.Fatal(values)
	}
}

func TestInventoryOperationalStateAndReplicaMetrics(t *testing.T) {
	r, err := inventoryResource("DaemonSet", []byte(`{"metadata":{"uid":"ds","name":"agent","namespace":"ns"},"status":{"desiredNumberScheduled":2,"numberReady":1,"numberUnavailable":1,"numberMisscheduled":0,"updatedNumberScheduled":2}}`))
	if err != nil {
		t.Fatal(err)
	}
	a := Agent{cfg: Config{Cluster: "production"}}
	values := map[string]float64{}
	for _, m := range a.inventoryMetrics([]map[string]any{r}) {
		if m.Tags["kube_daemonset"] != "agent" || m.Tags["kube_namespace"] != "ns" {
			t.Fatal(m)
		}
		values[m.MetricName] = m.Value
	}
	if values["k8s.daemonset.desired"] != 2 || values["k8s.daemonset.ready"] != 1 || values["k8s.daemonset.daemons_unavailable"] != 1 {
		t.Fatal(values)
	}
}

func TestAllocationTotalsExcludeTerminalAndUnscheduledPods(t *testing.T) {
	var resources []map[string]any
	for _, scenario := range []struct{ name, phase, node string }{
		{"running", "Running", "node"}, {"done", "Succeeded", "node"},
		{"failed", "Failed", "node"}, {"pending", "Pending", ""},
	} {
		resource, err := inventoryResource("Pod", []byte(`{"metadata":{"uid":"`+scenario.name+`","name":"`+scenario.name+`","namespace":"ns"},"spec":{"nodeName":"`+scenario.node+`","containers":[{"name":"app","resources":{"requests":{"cpu":"100m","memory":"20M"}}}]},"status":{"phase":"`+scenario.phase+`"}}`))
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, resource)
	}
	a := Agent{cfg: Config{Cluster: "production"}}
	var cpu, memory float64
	declared := 0
	for _, metric := range a.inventoryMetrics(resources) {
		switch metric.MetricName {
		case "k8s.container.requests.cpu_cores.total":
			cpu += metric.Value
		case "k8s.container.requests.memory_bytes.total":
			memory += metric.Value
		case "k8s.container.requests.cpu_cores":
			declared++
		}
	}
	if cpu != .1 || memory != 20000000 || declared != 4 {
		t.Fatalf("allocation CPU=%v memory=%v declared=%v", cpu, memory, declared)
	}
}

func TestStateExtrasUseRealCapacityAndEndpointReadiness(t *testing.T) {
	a := Agent{cfg: Config{Cluster: "production"}}
	for _, test := range []struct {
		kind, body, name string
		value            float64
	}{
		{"Endpoints", `{"metadata":{"name":"backend","namespace":"lab"},"subsets":[{"addresses":[{"ip":"10.0.0.1"},{"ip":"10.0.0.2"}],"notReadyAddresses":[{"ip":"10.0.0.3"}],"ports":[{"name":"http","port":8080,"protocol":"TCP"}]}]}`, "k8s.endpoint.address_available", 2},
		{"EndpointSlice", `{"metadata":{"name":"backend","namespace":"lab"},"endpoints":[{"addresses":["a"]},{"addresses":["b"],"conditions":{"ready":true}},{"addresses":["c"],"conditions":{"ready":false}}]}`, "k8s.endpointslice.address_available", 2},
		{"EndpointSlice", `{"metadata":{"name":"backend","namespace":"lab"},"endpoints":[{"addresses":["a"]},{"addresses":["b"],"conditions":{"ready":false}}]}`, "k8s.endpointslice.address_not_ready", 1},
		{"PersistentVolumeClaim", `{"metadata":{"name":"metrics","namespace":"lab"},"spec":{"resources":{"requests":{"storage":"2Gi"}},"accessModes":["ReadWriteOnce"]},"status":{"phase":"Bound"}}`, "k8s.persistentvolumeclaim.request_storage_bytes", 2147483648},
	} {
		var object map[string]any
		if err := json.Unmarshal([]byte(test.body), &object); err != nil {
			t.Fatal(err)
		}
		found := false
		var total float64
		for _, m := range a.stateExtraMetrics(test.kind, object) {
			if m.MetricName == test.name {
				found = true
				total += m.Value
				if m.Tags["kube_namespace"] != "lab" {
					t.Fatal(m)
				}
				if test.kind == "Endpoints" && (m.Tags["port_number"] != "8080" || m.Tags["port_name"] != "http" || m.Tags["ip"] == "") {
					t.Fatal(m)
				}
			}
		}
		if !found || total != test.value {
			t.Fatal(test.name)
		}
	}
}

func TestContainerFailureReasonsMatchStateAndRemainBounded(t *testing.T) {
	for _, scenario := range []struct {
		phase, reason string
		wanted        bool
	}{
		{"waiting", "CrashLoopBackOff", true}, {"terminated", "OOMKilled", true},
		{"terminated", "Completed", false}, {"waiting", "UnboundedCustomReason", false},
	} {
		resource, err := inventoryResource("Pod", []byte(`{"metadata":{"uid":"pod","name":"pod","namespace":"lab"},"spec":{"nodeName":"node"},"status":{"phase":"Running","containerStatuses":[{"name":"app","state":{"`+scenario.phase+`":{"reason":"`+scenario.reason+`"}}}]}}`))
		if err != nil {
			t.Fatal(err)
		}
		a := Agent{cfg: Config{Cluster: "production"}}
		found := false
		for _, metric := range a.inventoryMetrics([]map[string]any{resource}) {
			if metric.MetricName == "k8s.container.status_report.count."+scenario.phase {
				found = true
				if metric.Value != 1 || metric.Tags["reason"] != scenario.reason || metric.Tags["kube_container_name"] != "app" || metric.Tags["kube_node"] != "node" {
					t.Fatal(metric)
				}
			}
		}
		if found != scenario.wanted {
			t.Fatal(scenario)
		}
	}
}

func TestNodeImageSizeUsesAPIBytesAndDoesNotReadRegistryCredentials(t *testing.T) {
	node, err := inventoryResource("Node", []byte(`{"metadata":{"uid":"node","name":"node-a"},"spec":{},"status":{"images":[{"names":["registry:5050/app@sha256:abc","registry:5050/app:v1"],"sizeBytes":1048576}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	a := Agent{cfg: Config{Cluster: "production"}}
	found := 0
	for _, m := range a.inventoryMetrics([]map[string]any{node}) {
		if m.MetricName == "k8s.node.image.size_bytes" {
			found++
			if m.Value != 1048576 || m.Tags["image_name"] != "registry:5050/app" || m.Tags["short_image"] != "app" || m.Tags["kube_node"] != "node-a" {
				t.Fatal(m)
			}
			if strings.HasSuffix(m.Tags["image"], ":v1") && m.Tags["image_tag"] != "v1" {
				t.Fatal(m)
			}
		}
	}
	if found != 2 {
		t.Fatal("image size missing")
	}
}
