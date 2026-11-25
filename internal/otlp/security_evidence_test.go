package otlp

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// O agente do nó é o caminho real dos eventos: o que os SDKs mandam (inclusive a evidência) tem de passar por ele.
func postSecurity(t *testing.T, path, body string) (int, string) {
	t.Helper()
	h := NewHTTPReceiver(":0", nil, slog.Default(), DefaultMaxBodyBytes, nil)
	forwarded := ""
	h.SetForwardRaw(func(signal, contentType string, raw []byte) error { forwarded = signal; return nil })
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.handleSecurity(rec, req)
	return rec.Code, forwarded
}

func TestSecurityEventsAcceptEvidence(t *testing.T) {
	evidence := `{"parameter":"q","value":"<script>alert(1)</script>","highlight":[0,25],"headers":{"user-agent":"curl/8"}}`
	for path, signal := range map[string]string{"/v1/security/events": "security/events", "/v1/security/iast": "security/iast"} {
		body := `{"id":"1","service":"s","host":"h","environment":"e","outcome":"detected","rule_id":"942100","rules_version":"1","engine_version":"1","elapsed_us":5,"request_method":"GET","request_path":"/q","evidence":` + evidence + `}`
		if code, got := postSecurity(t, path, body); code != http.StatusOK || got != signal {
			t.Fatalf("%s com evidência: status %d, encaminhado %q", path, code, got)
		}
	}
}

func TestSecurityEvidenceIsNotAcceptedWhereItDoesNotBelong(t *testing.T) {
	if code, _ := postSecurity(t, "/v1/security/users", `{"id":"1","service":"s","evidence":{}}`); code != http.StatusBadRequest {
		t.Fatalf("usuários não levam evidência: status %d", code)
	}
}

func TestSecurityEventsLimitFitsEvidence(t *testing.T) {
	big := strings.Repeat("a", 9000)
	body := `{"id":"1","service":"s","host":"h","environment":"e","outcome":"detected","rule_id":"r","rules_version":"1","engine_version":"1","elapsed_us":5,"evidence":{"value":"` + big + `"}}`
	if code, _ := postSecurity(t, "/v1/security/events", body); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("evidência acima do teto deve ser recusada, status %d", code)
	}
}
