package clusteragent

import "testing"

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
