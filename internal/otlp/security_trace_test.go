package otlp

import "testing"

func TestSecurityTraceKeepsMarkedTrace(t *testing.T) {
	h := &HTTPReceiver{}
	if h.securityTrace("abc", false) {
		t.Fatal("trace sem evento de segurança não deve ser retido")
	}
	if !h.securityTrace("abc", true) {
		t.Fatal("span com evento de segurança deve ser retido")
	}
	if !h.securityTrace("abc", false) {
		t.Fatal("outros spans do mesmo trace devem ser retidos")
	}
	if h.securityTrace("", true) {
		t.Fatal("trace vazio não é registrado")
	}
}
