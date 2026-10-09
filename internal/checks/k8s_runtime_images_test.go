package checks

import (
	runtimev1 "k8s.io/cri-api/pkg/apis/runtime/v1"
	"testing"
)

func TestRuntimeImageAliasesKeepIDsAndDeduplicate(t *testing.T) {
	c := k8sKubeletCheck{}
	metrics := c.runtimeImageMetrics([]*runtimev1.Image{{Id: "sha256:abc", RepoTags: []string{"registry:5000/app:v1", "registry:5000/app:v1"}, RepoDigests: []string{"registry:5000/app@sha256:def"}, Size: 123}}, "node-a")
	if len(metrics) != 4 {
		t.Fatalf("expected count and three unique aliases, got %d", len(metrics))
	}
	for _, metric := range metrics[1:] {
		if metric.GetValue() != 123 || metric.GetTags()["image_id"] != "sha256:abc" {
			t.Fatalf("invalid image metric: %v", metric)
		}
	}
	if metrics[2].GetTags()["image_name"] != "registry:5000/app" || metrics[2].GetTags()["image_tag"] != "v1" {
		t.Fatal("registry port mistaken for image tag")
	}
}
