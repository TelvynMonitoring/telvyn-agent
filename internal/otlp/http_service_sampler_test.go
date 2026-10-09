package otlp

import (
	tracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracedatapb "go.opentelemetry.io/proto/otlp/trace/v1"
	"log/slog"
	"testing"
)

func TestScopeSamplerProtobufPreservesScopeAndBatchIdentity(t *testing.T) {
	attr := func(k, v string) *commonpb.KeyValue {
		return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
	}
	req := &tracepb.ExportTraceServiceRequest{ResourceSpans: []*tracedatapb.ResourceSpans{{Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{attr("service.name", "api"), attr("deployment.environment", "prod")}}, ScopeSpans: []*tracedatapb.ScopeSpans{{Spans: []*tracedatapb.Span{{TraceId: bytes16("same"), Name: "route", Kind: tracedatapb.Span_SPAN_KIND_SERVER, Attributes: []*commonpb.KeyValue{attr("http.request.method", "GET"), attr("http.route", "/a")}}}}}}}}
	calls := 0
	kept := filterScopeSampledSpans(req, func(_, service, env, resource string, _, kind int32, _ int64) bool {
		calls++
		if service != "api" || env != "prod" || resource != "GET /a" || kind != 2 {
			t.Errorf("scope %s/%s/%s kind%d", service, env, resource, kind)
		}
		return true
	})
	if kept != 1 || calls != 1 || string(req.ResourceSpans[0].ScopeSpans[0].Spans[0].TraceId) != string(bytes16("same")) {
		t.Fatal("scope sampler changed trace identity")
	}
}

func TestScopeSamplerJSONObservesEveryResourceEvenWhenTraceAlreadyKept(t *testing.T) {
	h := NewHTTPReceiver("", nil, slog.Default(), 1024*1024, nil)
	scopes := []string{}
	h.SetScopeTraceSampler(func(_, service, env, resource string, _, kind int32, _ int64) bool {
		scopes = append(scopes, service+":"+env+":"+resource)
		if kind != 2 {
			t.Error("server kind lost")
		}
		return true
	})
	body := []byte(`{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api"}},{"key":"deployment.environment.name","value":{"stringValue":"prod"}}]},"scopeSpans":[{"spans":[{"traceId":"0123456789abcdef0123456789abcdef","spanId":"0123456789abcdef","name":"GET /a","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"100","endTimeUnixNano":"200"},{"traceId":"0123456789abcdef0123456789abcdef","spanId":"abcdef0123456789","name":"GET /b","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"100","endTimeUnixNano":"200"}]}]}]}`)
	_, kept, ok := h.tapAndSampleJSON(body, "")
	if !ok || kept != 2 || len(scopes) != 2 || scopes[0] != "api:prod:GET /a" || scopes[1] != "api:prod:GET /b" {
		t.Fatalf("scope=%v kept=%d ok=%v", scopes, kept, ok)
	}
}

func TestServiceSamplerJSONUsesResourceThenSpanFallback(t *testing.T) {
	h := NewHTTPReceiver("", nil, slog.Default(), 1024*1024, nil)
	services := []string{}
	h.SetServiceTraceSampler(func(_ string, service string, _ int32, _ int64) bool {
		services = append(services, service)
		return false
	})
	body := []byte(`{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api"}}]},"scopeSpans":[{"spans":[{"traceId":"0123456789abcdef0123456789abcdef","spanId":"0123456789abcdef","startTimeUnixNano":"100","endTimeUnixNano":"200","attributes":[{"key":"service.name","value":{"stringValue":"wrong"}}]}]}]},{"scopeSpans":[{"spans":[{"traceId":"abcdef0123456789abcdef0123456789","spanId":"abcdef0123456789","startTimeUnixNano":"100","endTimeUnixNano":"200","attributes":[{"key":"service.name","value":{"stringValue":"worker"}}]}]}]}]}`)
	_, kept, ok := h.tapAndSampleJSON(body, "")
	if !ok || kept != 0 || len(services) != 2 || services[0] != "api" || services[1] != "worker" {
		t.Fatalf("services=%v kept=%d parsed=%v", services, kept, ok)
	}
	called := false
	h.SetTraceSampler(func(_ string, _ int32, _ int64) bool { called = true; return true })
	_, kept, ok = h.tapAndSampleJSON(body, "")
	if !ok || kept != 2 || !called {
		t.Fatal("legacy sampling callback no longer works")
	}
}
