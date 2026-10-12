package primarytags

import "testing"

func TestOperatorHostMetadataAndReservedOverflow(t *testing.T) {
	tags, err := ParseHostTags(`{"team":"São Paulo / operações","zone":"East 1"}`)
	if err != nil || tags["team"] != "São Paulo / operações" {
		t.Fatalf("valid UTF8 metadata rejected: %v", err)
	}
	for _, raw := range []string{`{"team":"__other__"}`, `{"team":"line\nvalue"}`, `{"bad key":"value"}`} {
		if _, err := ParseHostTags(raw); err == nil {
			t.Fatalf("invalid metadata allowed: %s", raw)
		}
	}
	if ValidKey("sdk.region") || !ValidKey("kube_label.app.kubernetes.io/name") {
		t.Fatal("source namespaces invalid")
	}
}
