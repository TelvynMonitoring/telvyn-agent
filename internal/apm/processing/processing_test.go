package processing

import (
	"encoding/json"
	tracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	spanpb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"strings"
	"testing"
)

func ptr(s string) *string { return &s }

func TestOrderedProcessingOnBothOTLPEncodings(t *testing.T) {
	for _, contentType := range []string{"application/json", "application/x-protobuf"} {
		t.Run(contentType, func(t *testing.T) {
			p := &Processor{}
			if err := p.Update(Policy{Version: 1, Rules: []Rule{
				{Name: "rename", Service: ptr("backend"), Action: "remap_service", Value: ptr("api")},
				{Name: "mask", Service: ptr("api"), Env: ptr("local"), Action: "mask_attribute", Key: ptr("customer.email")},
				{Name: "remove", Service: ptr("api"), Action: "remove_attribute", Key: ptr("private.value")},
				{Name: "resource", Service: ptr("api"), Action: "remap_resource", Value: ptr("GET /public")},
			}}); err != nil {
				t.Fatal(err)
			}
			resource := &resourcepb.Resource{Attributes: setAttribute(setAttribute(nil, "service.name", "backend"), "deployment.environment", "local")}
			span := &spanpb.Span{Name: "http.request", Attributes: setAttribute(setAttribute(nil, "customer.email", "secret@example.test"), "private.value", "secret")}
			request := &tracepb.ExportTraceServiceRequest{ResourceSpans: []*spanpb.ResourceSpans{{Resource: resource, ScopeSpans: []*spanpb.ScopeSpans{{Spans: []*spanpb.Span{span}}}}}}
			var body []byte
			if contentType == "application/json" {
				body, _ = protojson.Marshal(request)
			} else {
				body, _ = proto.Marshal(request)
			}
			body, err := p.ProcessTraces(contentType, body)
			if err != nil {
				t.Fatal(err)
			}
			if contentType == "application/json" {
				err = protojson.Unmarshal(body, request)
			} else {
				err = proto.Unmarshal(body, request)
			}
			if err != nil {
				t.Fatal(err)
			}
			rs := request.ResourceSpans[0]
			result := rs.ScopeSpans[0].Spans[0]
			if attribute(rs.Resource.Attributes, "service.name") != "api" || attribute(result.Attributes, "customer.email") != "[REDACTED]" || attribute(result.Attributes, "private.value") != "" || attribute(result.Attributes, "resource.name") != "GET /public" || result.Name != "http.request" {
				t.Fatalf("wrong processing result: %v", request)
			}
		})
	}
}

func TestRejectsProtectedAndInvalidPoliciesWithoutReplacingCurrent(t *testing.T) {
	p := &Processor{}
	if err := p.Update(Policy{Version: 1}); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []Policy{{Version: 2}, {Version: 1, Rules: []Rule{{Name: "bad", Action: "remove_attribute", Key: ptr("service.name")}}}, {Version: 1, Rules: make([]Rule, 51)}} {
		if p.Update(policy) == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	body, err := p.ProcessTraces("application/json", []byte("not parsed because policy is empty"))
	if err != nil || len(body) == 0 {
		t.Fatal("valid old policy lost")
	}
}

func TestJSONPreservesHexIDsUnknownFieldsAndNanosecondPrecision(t *testing.T) {
	p := &Processor{}
	if err := p.Update(Policy{Version: 1, Rules: []Rule{{Name: "mask", Action: "mask_attribute", Key: ptr("private")}, {Name: "rename", Action: "remap_service", Value: ptr("api")}}}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"unknownField":{"keep":true},"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"backend"}}]},"scopeSpans":[{"spans":[{"traceId":"0123456789abcdef0123456789abcdef","spanId":"0123456789abcdef","parentSpanId":"abcdef0123456789","startTimeUnixNano":"1791453700663000000","endTimeUnixNano":1791453700663999999,"attributes":[{"key":"private","value":{"stringValue":"secret"}}]}]}]}]}`)
	result, err := p.ProcessTraces("application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatal(err)
	}
	var original map[string]json.RawMessage
	_ = json.Unmarshal(body, &original)
	if string(parsed["unknownField"]) != string(original["unknownField"]) {
		t.Fatal("unknown field changed")
	}
	for _, literal := range []string{`"traceId":"0123456789abcdef0123456789abcdef"`, `"spanId":"0123456789abcdef"`, `"parentSpanId":"abcdef0123456789"`, `"startTimeUnixNano":"1791453700663000000"`, `"endTimeUnixNano":1791453700663999999`, `"stringValue":"[REDACTED]"`, `"stringValue":"api"`} {
		if !strings.Contains(string(result), literal) {
			t.Fatalf("lost literal %s: %s", literal, result)
		}
	}
	if _, err := p.ProcessTraces("application/json", []byte(`{"resourceSpans":[{"scopeSpans":"bad"}]}`)); err == nil {
		t.Fatal("invalid JSON forwarded despite configured masking")
	}
}
