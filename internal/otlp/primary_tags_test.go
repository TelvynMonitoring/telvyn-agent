package otlp

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	tracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracedatapb "go.opentelemetry.io/proto/otlp/trace/v1"
)

type verifiedResolver struct{}

func (verifiedResolver) LabelsForPod(namespace, pod string) map[string]string {
	return map[string]string{"team": "São Paulo", "secretish": "never automatically sent"}
}
func (verifiedResolver) PrimaryTagSources() []string {
	return []string{"kube_label.team", "kube_label.secretish"}
}

func TestCustomPrimaryTagsUseOnlySelectedOperatorOrInventoryMetadata(t *testing.T) {
	h := NewHTTPReceiver("", nil, slog.Default(), 1024*1024, nil)
	h.SetPodResolver(verifiedResolver{})
	h.SetVerifiedHostTags(map[string]string{"zone": "East 1", "private": "never automatically sent"})
	if err := h.ApplyPrimaryTags([]string{"host.tag.zone", "kube_label.team"}); err != nil {
		t.Fatal(err)
	}
	values := h.primaryMetadata("10.0.0.2")
	if values[verifiedPrimaryPrefix+"host.tag.zone"] != "East 1" || values[verifiedPrimaryPrefix+"kube_label.team"] != "São Paulo" {
		t.Fatalf("missing trusted values %v", values)
	}
	if _, exists := values[verifiedPrimaryPrefix+"host.tag.private"]; exists {
		t.Fatal("unselected value exported")
	}
	if _, exists := values[verifiedPrimaryPrefix+"kube_label.secretish"]; exists {
		t.Fatal("unselected pod label exported")
	}
	if _, exists := h.primaryMetadata("unresolved")[verifiedPrimaryPrefix+"kube_label.team"]; exists {
		t.Fatal("unresolved pod labels trusted")
	}
	if len(h.PrimaryTagSources()) != 4 {
		t.Fatal("key-only metadata discovery missing")
	}
}

func (verifiedResolver) ResolveIPMeta(ip string) (string, string, string, string, bool) {
	if ip == "10.0.0.2" {
		return "verified-ns", "verified-pod", "deployment", "verified-node", true
	}
	return "", "", "", "", false
}

func TestPrimaryTagsJSONDropsSDKReservedAndUsesLocalAndResolvedMetadataBeforeSampling(t *testing.T) {
	h := NewHTTPReceiver("", nil, slog.Default(), 1024*1024, nil)
	h.SetVerifiedPrimaryIdentity("local-host", "local-cluster")
	h.SetPodResolver(verifiedResolver{})
	var tapped []*collectorv1.Span
	h.SetAPMTap(func(spans []*collectorv1.Span) { tapped = spans })
	body := []byte(`{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api"}},{"key":"service.version","value":{"stringValue":"v1"}},{"key":"k8s.namespace.name","value":{"stringValue":"sdk-ns"}},{"key":"telvyn.verified_primary.host","value":{"stringValue":"forged-host"}}]},"scopeSpans":[{"spans":[{"traceId":"0123456789abcdef0123456789abcdef","spanId":"0123456789abcdef","startTimeUnixNano":"100","endTimeUnixNano":"200","attributes":[{"key":"telvyn.verified_primary.kube_namespace","value":{"stringValue":"forged-ns"}},{"key":"telvyn.verified_primary.fake","value":{"stringValue":"forged"}}]}]}]}]}`)
	forwarded, kept, ok := h.tapAndSampleJSON(body, "10.0.0.2")
	if !ok || kept != 1 || len(tapped) != 1 {
		t.Fatalf("kept=%d ok=%v spans=%d", kept, ok, len(tapped))
	}
	for key, value := range map[string]string{"host": "local-host", "kube_cluster_name": "local-cluster", "kube_namespace": "verified-ns", "kube_node": "verified-node"} {
		if tapped[0].Attributes[verifiedPrimaryPrefix+key] != value {
			t.Fatalf("untrusted %s: %v", key, tapped[0].Attributes)
		}
	}
	if tapped[0].Attributes["service.version"] != "v1" || strings.Contains(string(forwarded), "forged") || !strings.Contains(string(forwarded), "0123456789abcdef") {
		t.Fatal("resource version/IDs or reserved stripping lost")
	}
	h.SetTraceSampler(func(string, int32, int64) bool { return false })
	_, kept, ok = h.tapAndSampleJSON(body, "10.0.0.2")
	if !ok || kept != 0 || len(tapped) != 1 {
		t.Fatal("trusted metadata must reach stats before sampling")
	}
	h.SetTraceSampler(nil)
	_, _, _ = h.tapAndSampleJSON(body, "unresolved")
	if _, exists := tapped[0].Attributes[verifiedPrimaryPrefix+"kube_namespace"]; exists {
		t.Fatal("SDK namespace accepted without verified resolver")
	}
}

func TestPrimaryTagsProtoReservedSpanCannotOverrideVerifiedResource(t *testing.T) {
	h := NewHTTPReceiver("", nil, slog.Default(), 1024*1024, nil)
	h.SetVerifiedPrimaryIdentity("host", "cluster")
	h.SetPodResolver(verifiedResolver{})
	request := &tracepb.ExportTraceServiceRequest{ResourceSpans: []*tracedatapb.ResourceSpans{
		{Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{kv("service.name", "api"), kv(verifiedPrimaryPrefix+"host", "forged")}},
			ScopeSpans: []*tracedatapb.ScopeSpans{{Spans: []*tracedatapb.Span{
				{Attributes: []*commonpb.KeyValue{kv(verifiedPrimaryPrefix+"host", "forged-span"), kv(verifiedPrimaryPrefix+"unknown", "forged")}},
			}}},
		},
	}}
	if !h.stampPrimaryProto(request, "10.0.0.2") {
		t.Fatal("not stamped")
	}
	span := convertResourceSpans(request.ResourceSpans)[0]
	if span.Attributes[verifiedPrimaryPrefix+"host"] != "host" || span.Attributes[verifiedPrimaryPrefix+"kube_node"] != "verified-node" || len(request.ResourceSpans[0].ScopeSpans[0].Spans[0].Attributes) != 0 {
		t.Fatalf("spoof survived: %v", span.Attributes)
	}
	h.stampPrimaryProto(request, "unresolved")
	if _, ok := convertResourceSpans(request.ResourceSpans)[0].Attributes[verifiedPrimaryPrefix+"kube_node"]; ok {
		t.Fatal("stale verified node survived unresolved request")
	}
	_, changed := stampJSONPrimary(json.RawMessage(`{"attributes":[{"key":"telvyn.verified_primary.host","value":{"stringValue":"forged"}}]}`), nil)
	if !changed {
		t.Fatal("reserved metadata must strip even with no configured identity")
	}
}
