package otlp

import (
	"encoding/json"
	"testing"
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
