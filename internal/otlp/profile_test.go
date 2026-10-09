package otlp

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProfileGatewayReplacesSpoofedOriginAndReportsForwardFailure(t *testing.T) {
	h := NewHTTPReceiver("", nil, slog.Default(), 1024, nil)
	h.SetVerifiedPrimaryIdentity("actual-node", "")
	h.SetForwardRaw(func(signal, ct string, body []byte) error {
		var profile map[string]json.RawMessage
		if signal != "profile" || ct != "application/json" || json.Unmarshal(body, &profile) != nil {
			t.Fatal("invalid destination")
		}
		var tags map[string]string
		_ = json.Unmarshal(profile["verified_primary_tags"], &tags)
		if tags["host"] != "actual-node" || len(tags) != 1 {
			t.Fatalf("unverified metadata: %v", tags)
		}
		return nil
	})
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/profile", bytes.NewBufferString(`{"service":"backend","folded":"root 1","verified_primary_tags":{"host":"spoof","kube_namespace":"fake"}}`))
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	w := httptest.NewRecorder()
	h.handleProfile(w, request())
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	h.SetForwardRaw(func(string, string, []byte) error { return errors.New("offline") })
	w = httptest.NewRecorder()
	h.handleProfile(w, request())
	if w.Code != http.StatusBadGateway {
		t.Fatal("false success", w.Code)
	}
}
