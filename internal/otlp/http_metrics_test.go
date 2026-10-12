package otlp

import (
	"bytes"
	"errors"
	metricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetricsValidateConvertAndPropagateForwardFailure(t *testing.T) {
	h := NewHTTPReceiver("", nil, slog.Default(), 1024, nil)
	forwarded := 0
	h.SetForwardRaw(func(signal, ct string, body []byte) error {
		forwarded++
		var decoded metricspb.ExportMetricsServiceRequest
		if signal != "metrics" || ct != "application/json" || protojson.Unmarshal(body, &decoded) != nil {
			t.Fatal("not backend-compatible OTLP JSON")
		}
		return nil
	})
	for _, ct := range []string{"application/json", "application/x-protobuf"} {
		body := []byte("{}")
		if ct == "application/x-protobuf" {
			body, _ = proto.Marshal(&metricspb.ExportMetricsServiceRequest{})
		}
		r := httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader(body))
		r.Header.Set("Content-Type", ct)
		w := httptest.NewRecorder()
		h.handleMetrics(w, r)
		if w.Code != 200 {
			t.Fatalf("valid %s: %d", ct, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader([]byte("invalid")))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleMetrics(w, r)
	if w.Code != 400 || forwarded != 2 {
		t.Fatal("invalid payload forwarded or acknowledged")
	}
	h.SetForwardRaw(func(_, _ string, _ []byte) error { return errors.New("offline") })
	r = httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader([]byte("{}")))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.handleMetrics(w, r)
	if w.Code != 502 {
		t.Fatal("failed delivery acknowledged")
	}
}
