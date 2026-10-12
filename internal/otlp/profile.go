package otlp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

func (h *HTTPReceiver) stampProfile(body []byte, clientIP string) ([]byte, error) {
	var profile map[string]json.RawMessage
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, errors.New("profile object required")
	}
	// Never trust an application's host name, labels, or reserved metadata.
	tags := map[string]string{}
	for key, value := range h.primaryMetadata(clientIP) {
		tags[strings.TrimPrefix(key, verifiedPrimaryPrefix)] = value
	}
	profile["verified_primary_tags"], _ = json.Marshal(tags)
	return json.Marshal(profile)
}
func (h *HTTPReceiver) handleProfile(w http.ResponseWriter, r *http.Request) {
	h.serveOTLP(w, r, "/v1/profile", func(body []byte, ct, clientIP string) (int, error) {
		if ct != "application/json" {
			return http.StatusUnsupportedMediaType, errors.New("profile requires JSON")
		}
		if h.forwardRaw == nil {
			return http.StatusServiceUnavailable, errors.New("profile forwarding unavailable")
		}
		stamped, err := h.stampProfile(body, clientIP)
		if err != nil {
			return http.StatusBadRequest, err
		}
		if err = h.forwardRaw("profile", "application/json", stamped); err != nil {
			return http.StatusBadGateway, err
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"forwarded":true}`))
		return http.StatusOK, nil
	})
}
