package otlp

import (
	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"log/slog"
	"testing"

	tracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracedatapb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func TestSamplingKeepsBatchTraceAcrossResources(t *testing.T) {
	for _, childFirst := range []bool{false, true} {
		parent := &tracedatapb.Span{TraceId: bytes16("same"), Name: "parent"}
		child := &tracedatapb.Span{TraceId: bytes16("same"), Name: "child", Status: &tracedatapb.Status{Code: tracedatapb.Status_STATUS_CODE_ERROR}}
		spans := []*tracedatapb.Span{parent, child}
		if childFirst {
			spans[0], spans[1] = child, parent
		}
		req := &tracepb.ExportTraceServiceRequest{}
		for _, s := range spans {
			req.ResourceSpans = append(req.ResourceSpans, &tracedatapb.ResourceSpans{ScopeSpans: []*tracedatapb.ScopeSpans{{Spans: []*tracedatapb.Span{s}}}})
		}
		if n := filterSampledSpans(req, func(_ string, status int32, _ int64) bool { return status == 2 }); n != 2 {
			t.Fatalf("childFirst=%v: retained %d", childFirst, n)
		}
	}
}

func TestJSONSamplingKeepsTraceAcrossResourcesAndCountsAll(t *testing.T) {
	h := NewHTTPReceiver(":0", nil, slog.Default(), DefaultMaxBodyBytes, nil)
	tapped := 0
	h.SetAPMTap(func(spans []*collectorv1.Span) { tapped = len(spans) })
	h.SetTraceSampler(func(_ string, status int32, _ int64) bool { return status == 2 })
	body := []byte(`{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"ABCDEF0123456789ABCDEF0123456789","name":"parent"},{"traceId":"00000000000000000000000000000000","name":"other"}]}]},{"scopeSpans":[{"spans":[{"traceId":"abcdef0123456789abcdef0123456789","name":"child","status":{"code":2}}]}]}]}`)
	_, kept, ok := h.tapAndSampleJSON(body, "127.0.0.1")
	if !ok || kept != 2 || tapped != 3 {
		t.Fatalf("ok=%v retained=%d tapped=%d", ok, kept, tapped)
	}
}
