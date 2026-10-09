package otlp

import (
	"bytes"
	"compress/gzip"
	"errors"
	"github.com/ispwatch/collector/internal/apm/usage"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReceiverUsageCountsActualGzipPayloadAndSampling(t *testing.T) {
	body := []byte(`{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"backend"}}]},"scopeSpans":[{"spans":[{"traceId":"0123456789abcdef0123456789abcdef","spanId":"0123456789abcdef","name":"GET /a","startTimeUnixNano":"100","endTimeUnixNano":"200"},{"traceId":"abcdef0123456789abcdef0123456789","spanId":"abcdef0123456789","name":"GET /b","startTimeUnixNano":"100","endTimeUnixNano":"200"}]}]}]}`)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(body)
	_ = writer.Close()
	receiver := NewHTTPReceiver("", nil, slog.Default(), 1024*1024, nil)
	var observation usage.Observation
	receiver.SetTraceUsageObserver(func(value usage.Observation) { observation = value })
	var sentBytes int
	receiver.SetForwardRaw(func(_, _ string, body []byte) error { sentBytes = len(body); return nil })
	receiver.SetTraceSampler(func(id string, _ int32, _ int64) bool { return id == "0123456789abcdef0123456789abcdef" })
	request := httptest.NewRequest(http.MethodPost, "/v1/traces", bytes.NewReader(compressed.Bytes()))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "gzip")
	response := httptest.NewRecorder()
	receiver.handleTraces(response, request)
	if response.Code != http.StatusOK || len(observation.Received) != 2 || len(observation.Retained) != 1 || observation.ReceivedBytes != int64(len(body)) || observation.ForwardedBytes != int64(sentBytes) || observation.ParseFailed {
		t.Fatalf("wrong receiver accounting: %+v", observation)
	}
	receiver.SetForwardRaw(func(_, _ string, _ []byte) error { return errors.New("offline") })
	request = httptest.NewRequest(http.MethodPost, "/v1/traces", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	receiver.handleTraces(response, request)
	if !observation.ForwardFailed || len(observation.Retained) != 0 || observation.ForwardedBytes != 0 {
		t.Fatal("failed delivery counted as retained")
	}
}
