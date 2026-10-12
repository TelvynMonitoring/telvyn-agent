package otlp

import (
	"log/slog"
	"testing"
	"time"

	"github.com/ispwatch/collector/internal/apm/sampler"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func TestJSONNumericAttributesCountBeforeSampling(t *testing.T) {
	for _, status := range []string{"200", `"200"`} {
		h := NewHTTPReceiver(":0", nil, slog.Default(), DefaultMaxBodyBytes, nil)
		var tapped []*collectorv1.Span
		h.SetAPMTap(func(spans []*collectorv1.Span) { tapped = spans })
		h.SetTraceSampler(sampler.New(0, 2*time.Second).KeepRaw)
		body := []byte(`{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"real-app"}},{"key":"deployment.environment","value":{"stringValue":"validation"}}]},"scopeSpans":[{"spans":[{"traceId":"0123456789abcdef0123456789abcdef","name":"GET /normal","kind":2,"startTimeUnixNano":"1000000000","endTimeUnixNano":"1001000000","attributes":[{"key":"http.response.status_code","value":{"intValue":` + status + `}}]}]}]}]}`)
		_, kept, ok := h.tapAndSampleJSON(body, "127.0.0.1")
		if !ok || kept != 0 || len(tapped) != 1 {
			t.Fatalf("integer=%s: ok=%v kept=%d stats=%d", status, ok, kept, len(tapped))
		}
		if tapped[0].Attributes["http.response.status_code"] != "200" || tapped[0].ServiceName != "real-app" {
			t.Fatalf("integer=%s: unexpected span: %v", status, tapped[0])
		}
	}
}
