package otlp

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func TestTraceProcessingPrecedesStatisticsAndForwarding(t *testing.T) {
	h := NewHTTPReceiver(":0", nil, slog.Default(), DefaultMaxBodyBytes, nil)
	processed := []byte(`{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"remapped"}}]},"scopeSpans":[{"spans":[{"traceId":"abcdef0123456789abcdef0123456789","spanId":"abcdef0123456789","name":"request"}]}]}]}`)
	h.SetTraceProcessor(func(_ string, _ []byte) ([]byte, error) { return processed, nil })
	var service string
	h.SetAPMTap(func(spans []*collectorv1.Span) { service = spans[0].ServiceName })
	var forwarded []byte
	h.SetForwardRaw(func(_, _ string, body []byte) error { forwarded = body; return nil })
	request := httptest.NewRequest(http.MethodPost, "/v1/traces", bytes.NewBufferString(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	h.handleTraces(response, request)
	if response.Code != http.StatusOK || service != "remapped" || !bytes.Contains(forwarded, []byte("remapped")) {
		t.Fatalf("status=%d service=%q forwarded=%s", response.Code, service, forwarded)
	}

	h.SetTraceProcessor(func(_ string, _ []byte) ([]byte, error) { return nil, errors.New("invalid input") })
	forwarded = nil
	request = httptest.NewRequest(http.MethodPost, "/v1/traces", bytes.NewBufferString(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	h.handleTraces(response, request)
	if response.Code != http.StatusBadRequest || forwarded != nil {
		t.Fatalf("processing failure must not forward raw input: status=%d", response.Code)
	}
}
