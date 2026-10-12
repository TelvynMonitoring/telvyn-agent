package configpull

import (
	"context"
	"fmt"
	"github.com/ispwatch/collector/internal/apm/processing"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestProcessingAppliedBeforeRevisionACK(t *testing.T) {
	for _, fail := range []bool{false, true} {
		applied, acks := false, 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				if !applied {
					t.Error("ACK before apply")
				}
				acks++
				return
			}
			fmt.Fprintf(w, `{"version":0,"apm_processing":{"revision":"%s","policy":{"version":1,"rules":[]}}}`, strings.Repeat("a", 64))
		}))
		var version atomic.Int64
		err := pullOnce(context.Background(), server.Client(), Config{Endpoint: server.URL, TenantID: "2", CollectorID: "collector", ApplyAPMProcessing: func(policy processing.Policy) error {
			if fail {
				return fmt.Errorf("invalid policy")
			}
			if policy.Version != 1 {
				t.Error("schema version")
			}
			applied = true
			return nil
		}}, &version, recordingApplier{}, slog.Default())
		server.Close()
		if fail && (err == nil || acks != 0) {
			t.Fatalf("failed apply err=%v ACK=%d", err, acks)
		}
		if !fail && (err != nil || acks != 1) {
			t.Fatalf("success err=%v ACK=%d", err, acks)
		}
	}
}
