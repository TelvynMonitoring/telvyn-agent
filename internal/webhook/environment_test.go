package webhook

import (
	"encoding/json"
	"strings"
	"testing"
)

func podFromJSON(t *testing.T, raw string) podMeta {
	t.Helper()
	var p podMeta
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func resourceAttributes(t *testing.T, ops []patchOp) string {
	t.Helper()
	raw, err := json.Marshal(ops)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

const semNamespaceNoPod = `{"metadata":{"labels":{"app":"x"}},"spec":{"containers":[{"name":"app","image":"app/x:1"}]}}`

func TestNodeUsaONamespaceDaAdmissaoQuandoNaoHaRotuloDeAmbiente(t *testing.T) {
	pod := podFromJSON(t, semNamespaceNoPod)
	pod.namespace = "lab-vulneravel" // vem do pedido de admissão; metadata.namespace chega vazio
	ops, err := nodePatch(pod, "app", "img", "http://x:4318")
	if err != nil {
		t.Fatal(err)
	}
	if got := resourceAttributes(t, ops); !strings.Contains(got, "deployment.environment=lab-vulneravel") {
		t.Errorf("ambiente padrão ausente do patch: %s", got)
	}
}

func TestRotuloDeAmbienteVenceONamespace(t *testing.T) {
	pod := podFromJSON(t, `{"metadata":{"labels":{"telvyn.io/env":"producao"}},"spec":{"containers":[{"name":"app","image":"app/x:1"}]}}`)
	pod.namespace = "lab-vulneravel"
	ops, err := nodePatch(pod, "app", "img", "http://x:4318")
	if err != nil {
		t.Fatal(err)
	}
	got := resourceAttributes(t, ops)
	if !strings.Contains(got, "deployment.environment=producao") || strings.Contains(got, "deployment.environment=lab-vulneravel") {
		t.Errorf("o rótulo deveria vencer o namespace: %s", got)
	}
}

func TestAtributosDoClienteNaoSaoSobrescritos(t *testing.T) {
	pod := podFromJSON(t, `{"metadata":{},"spec":{"containers":[{"name":"app","image":"app/x:1","env":[{"name":"OTEL_RESOURCE_ATTRIBUTES","value":"deployment.environment=do-cliente"}]}]}}`)
	pod.namespace = "lab-vulneravel"
	ops, err := nodePatch(pod, "app", "img", "http://x:4318")
	if err != nil {
		t.Fatal(err)
	}
	if got := resourceAttributes(t, ops); strings.Contains(got, "deployment.environment=lab-vulneravel") {
		t.Errorf("o ambiente que o cliente definiu foi sobrescrito: %s", got)
	}
}

func TestJavaUsaONamespaceDaAdmissao(t *testing.T) {
	pod := podFromJSON(t, `{"metadata":{},"spec":{"containers":[{"name":"app","image":"webgoat/webgoat:v1"}]}}`)
	pod.namespace = "lab-vulneravel"
	ops := buildPatch(pod, []int{0}, "agent:1", "", "http://x:4318", "http/protobuf", "webgoat")
	if got := resourceAttributes(t, ops); !strings.Contains(got, "deployment.environment=lab-vulneravel") {
		t.Errorf("ambiente padrão ausente do patch Java: %s", got)
	}
}
