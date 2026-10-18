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
	} else if r.URL.Path == "/v1/security/lab" {
		signal = "security/lab"
	} else if r.URL.Path == "/v1/security/users" {
		signal = "security/users"
	}
	h.serveOTLP(w, r, "/v1/"+signal, func(body []byte, ct, clientIP string) (int, error) {
		if ct != "application/json" {
			return http.StatusUnsupportedMediaType, errors.New("security requires JSON")
		}
		// Code findings also carry a masked statement and a call stack.
		limit := 8192
		if signal == "security/iast" {
			limit = 32768
		}
		if len(body) > limit {
			return http.StatusRequestEntityTooLarge, errors.New("security report too large")
		}
		var report map[string]json.RawMessage
		if json.Unmarshal(body, &report) != nil || report == nil {
			return http.StatusBadRequest, errors.New("security report required")
		}
		for field := range report {
			if signal == "security/users" {
				// User activity (login success/failure, signup), as Datadog user events: no credentials, only identity.
				switch field {
				case "id", "service", "host", "environment", "service_version", "event", "usr_id", "usr_login", "usr_exists", "client_ip", "user_agent", "framework", "collection_mode", "trace_id", "span_id":
					continue
				default:
					return http.StatusBadRequest, errors.New("unsupported security field")
				}
			}
			switch field {
			case "id", "service", "host", "environment", "service_version", "outcome", "rule_id", "rules_version", "engine_version", "elapsed_us", "trace_id", "span_id":
			case "request_method", "request_path", "user_agent":
				// Attack events carry the request of a blocked or detected attack (as Datadog); code findings too.
				if signal != "security/iast" && signal != "security/events" {
					return http.StatusBadRequest, errors.New("unsupported security field")
				}
			case "client_ip", "blocked", "usr_id", "match_address", "blocked_by":
				if signal != "security/events" {
					return http.StatusBadRequest, errors.New("unsupported security field")
				}
			case "code_method", "code_line", "sink", "sql", "stack", "source":
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
