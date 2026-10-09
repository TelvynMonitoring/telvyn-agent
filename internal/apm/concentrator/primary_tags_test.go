package concentrator

import (
	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"testing"
)

func TestPrimaryTagsSeparateVerifiedNamespacesAndUnknown(t *testing.T) {
	c := New(nil)
	if err := c.ApplyPrimaryTags([]string{"kube_namespace"}); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"a", "b", ""} {
		c.Add(&collectorv1.Span{ServiceName: "same", Name: "http", Kind: 2, StartUnixNano: 1, EndUnixNano: 2, Attributes: map[string]string{PrimaryTagPrefix + "kube_namespace": ns, "k8s.namespace.name": "forged"}})
	}
	groups := c.Flush()
	if len(groups) != 3 {
		t.Fatalf("merged distinct verified origins: %d", len(groups))
	}
	total := uint64(0)
	for _, g := range groups {
		total += g.Hits
		if g.PrimaryTags["kube_namespace"] == "forged" {
			t.Fatal("SDK tag admitted")
		}
	}
	if total != 3 {
		t.Fatalf("lost hits: %d", total)
	}
	if c.ApplyPrimaryTags([]string{"sdk.region"}) == nil {
		t.Fatal("arbitrary SDK source allowed")
	}
}
