package otlp

import (
	"encoding/json"
	"testing"

	tracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

func TestAppendResourceAttributePreservaOsAtributosExistentes(t *testing.T) {
	raw := json.RawMessage(`{"attributes":[{"key":"service.name","value":{"stringValue":"api"}}],"droppedAttributesCount":0}`)
	out, ok := appendResourceAttribute(raw, "container.image.id", "sha256:abc")
	if !ok {
		t.Fatal("não carimbou")
	}
	attrs := kvToMap(mustAttrs(t, out))
	if attrs["service.name"] != "api" || attrs["container.image.id"] != "sha256:abc" {
		t.Fatalf("atributos = %v", attrs)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out, &m); err != nil || m["droppedAttributesCount"] == nil {
		t.Fatalf("campos do resource foram perdidos: %s", out)
	}
}

func TestAppendResourceAttributeSemAtributosPrevios(t *testing.T) {
	out, ok := appendResourceAttribute(nil, "container.image.id", "sha256:abc")
	if !ok || kvToMap(mustAttrs(t, out))["container.image.id"] != "sha256:abc" {
		t.Fatalf("resource vazio: ok=%v %s", ok, out)
	}
}

func mustAttrs(t *testing.T, raw json.RawMessage) []otlpKeyValue {
	t.Helper()
	var rf otlpResourceFields
	if err := json.Unmarshal(raw, &rf); err != nil {
		t.Fatal(err)
	}
	return rf.Attributes
}

type fakeImages map[string]string

func (f fakeImages) ImageIDForPod(ns, pod, container string) string {
	return f[ns+"/"+pod+"/"+container]
}

func TestEnrichImageIDProtoCarimbaSoQuemNaoTraz(t *testing.T) {
	req := &tracepb.ExportTraceServiceRequest{ResourceSpans: []*tracev1.ResourceSpans{
		{Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{kv("k8s.namespace.name", "ns"), kv("k8s.pod.name", "p"), kv("k8s.container.name", "api")}}},
		{Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{kv("k8s.namespace.name", "ns"), kv("k8s.pod.name", "p"), kv("k8s.container.name", "api"), kv("container.image.id", "sha256:da-app")}}},
		{Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{kv("service.name", "sem-pod")}}},
	}}
	h := &HTTPReceiver{}
	h.SetImageResolver(fakeImages{"ns/p/api": "sha256:abc"})
	if !h.enrichImageIDProto(req) {
		t.Fatal("deveria ter carimbado")
	}
	get := func(i int) string {
		for _, a := range req.ResourceSpans[i].Resource.Attributes {
			if a.GetKey() == "container.image.id" {
				return a.GetValue().GetStringValue()
			}
		}
		return ""
	}
	if get(0) != "sha256:abc" {
		t.Errorf("sem atributo: %q", get(0))
	}
	if get(1) != "sha256:da-app" {
		t.Errorf("a aplicação tem prioridade: %q", get(1))
	}
	if get(2) != "" {
		t.Errorf("sem pod não carimba: %q", get(2))
	}
}
