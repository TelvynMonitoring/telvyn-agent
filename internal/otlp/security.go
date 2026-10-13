package otlp

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Forward only the sanitised security contract; credentials remain in the collector.
func (h *HTTPReceiver) handleSecurity(w http.ResponseWriter, r *http.Request) {
	signal := "security/events"
	if r.URL.Path == "/v1/security/iast" {
		signal = "security/iast"
	}
	h.serveOTLP(w, r, "/v1/"+signal, func(body []byte, ct, clientIP string) (int, error) {
		if ct != "application/json" {
			return http.StatusUnsupportedMediaType, errors.New("security requires JSON")
		}
		if len(body) > 8192 {
			return http.StatusRequestEntityTooLarge, errors.New("security report too large")
		}
		var report map[string]json.RawMessage
		if json.Unmarshal(body, &report) != nil || report == nil {
			return http.StatusBadRequest, errors.New("security report required")
		}
		for field := range report {
			switch field {
			case "id", "service", "host", "environment", "service_version", "outcome", "rule_id", "rules_version", "engine_version", "elapsed_us", "trace_id", "span_id":
			case "code_method", "code_line":
				if signal != "security/iast" {
					return http.StatusBadRequest, errors.New("unsupported security field")
				}
			default:
				return http.StatusBadRequest, errors.New("unsupported security field")
			}
		}
		if h.forwardRaw == nil {
			return http.StatusServiceUnavailable, errors.New("security forwarding unavailable")
		}
		if err := h.forwardRaw(signal, "application/json", body); err != nil {
			return http.StatusBadGateway, err
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"forwarded":true}`))
		return http.StatusOK, nil
	})
}
