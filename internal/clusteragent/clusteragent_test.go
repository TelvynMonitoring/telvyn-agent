package clusteragent

import "testing"

func TestServiceInventoryPreservesRoutingWithoutWholeSpec(t *testing.T) {
	got, err := inventoryResource("Service", []byte(`{"metadata":{"uid":"svc","name":"web","namespace":"lab"},"spec":{"type":"LoadBalancer","clusterIP":"10.43.1.2","sessionAffinity":"None","selector":{"app":"web"},"ports":[{"port":80,"targetPort":8080}],"externalIPs":["192.168.1.24"],"unknown":"excluded"},"status":{"loadBalancer":{"ingress":[{"ip":"192.168.1.24"}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	details := got["details"].(map[string]any)
	if details["clusterIP"] != "10.43.1.2" || details["type"] != "LoadBalancer" || details["sessionAffinity"] != "None" || details["selector"] == nil || details["ports"] == nil || details["loadBalancer"] == nil {
		t.Fatalf("routing details lost: %#v", details)
	}
	if _, ok := details["unknown"]; ok {
		t.Fatal("whole spec forwarded")
	}
}

func TestNodeInventoryPreservesAddressesAndRoleLabels(t *testing.T) {
	got, err := inventoryResource("Node", []byte(`{"metadata":{"uid":"node-uid","name":"node-a","labels":{"node-role.kubernetes.io/control-plane":""}},"status":{"addresses":[{"type":"InternalIP","address":"192.168.1.24"},{"type":"Hostname","address":"node-a"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	addresses := got["details"].(map[string]any)["addresses"].([]any)
	if len(addresses) != 2 || addresses[0].(map[string]any)["address"] != "192.168.1.24" {
		t.Fatalf("node addresses lost: %#v", addresses)
	}
	if _, ok := got["labels"].(map[string]any)["node-role.kubernetes.io/control-plane"]; !ok {
		t.Fatal("node role label lost")
	}
}

func TestInventoryResourceMapsPodIdentityAndState(t *testing.T) {
	raw := []byte(`{
      "metadata": {
        "uid": "pod-uid",
        "name": "web-abc",
        "namespace": "prod",
        "resourceVersion": "42",
        "labels": {"app": "web"},
        "ownerReferences": [{"kind":"ReplicaSet","name":"web-123"}]
      },
      "spec": {"nodeName":"node-a"},
      "status": {"phase":"Running", "conditions":[{"type":"Ready","status":"True"}]}
    }`)

	got, err := inventoryResource("Pod", raw)
	if err != nil {
		t.Fatal(err)
	}
	if got["uid"] != "pod-uid" || got["namespace"] != "prod" || got["node_name"] != "node-a" {
		t.Fatalf("identity mapping incorrect: %#v", got)
	}
	if got["phase"] != "Running" || got["workload_kind"] != "ReplicaSet" {
		t.Fatalf("state mapping incorrect: %#v", got)
	}
}

func TestInventoryResourceRejectsMissingIdentity(t *testing.T) {
	_, err := inventoryResource("Pod", []byte(`{"metadata":{"name":"missing-uid"}}`))
	if err == nil {
		t.Fatal("expected missing uid error")
	}
}

func TestInventoryOperationalDetailsExcludeCredentials(t *testing.T) {
	got, err := inventoryResource("Pod", []byte(`{"metadata":{"uid":"p","name":"web","creationTimestamp":"2026-10-07T01:00:00Z"},"spec":{"containers":[{"name":"web","image":"web:v1","env":[{"name":"PASSWORD","value":"secret"}],"resources":{"limits":{"memory":"1Gi"}}}]},"status":{"podIP":"10.42.0.26","qosClass":"Burstable","containerStatuses":[{"name":"web","ready":true,"restartCount":2,"image":"web:v1"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	details := got["details"].(map[string]any)
	if details["podIP"] != "10.42.0.26" || details["qosClass"] != "Burstable" {
		t.Fatalf("missing details: %#v", details)
	}
	container := details["containers"].([]any)[0].(map[string]any)
	if _, exists := container["env"]; exists {
		t.Fatal("credentials included")
	}
	if container["resources"] == nil {
		t.Fatal("limits discarded")
	}
}
