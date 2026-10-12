package configpull

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ispwatch/collector/internal/apm/sampler"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMonthlyPolicyAppliesAndEchoesExactBudgetRevision(t *testing.T) {
	revision := strings.Repeat("a", 64)
	for _, fail := range []bool{false, true} {
		applied, acks := false, 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				acks++
				var payload map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&payload)
				if !applied || payload["budget_revision"] != revision || payload["mode"] != "adaptive_monthly" {
					t.Error("unapplied or wrong monthly ACK")
				}
				return
			}
			fmt.Fprintf(w, `{"version":0,"apm_sampling":{"version":2,"mode":"adaptive_monthly","base_rate":0.03,"slow_threshold_ms":2000,"budget_revision":"%s"}}`, revision)
		}))
		var version atomic.Int64
		err := pullOnce(context.Background(), server.Client(), Config{Endpoint: server.URL, TenantID: "2", CollectorID: "c", ApplyAPMSamplingPolicy: func(p sampler.Policy) error {
			if fail {
				return fmt.Errorf("apply rejected")
			}
			if p.Mode != "adaptive_monthly" || p.BudgetRevision != revision || p.BaseRate != .03 {
				t.Error("monthly policy lost")
			}
			applied = true
			return nil
		}}, &version, recordingApplier{}, slog.Default())
		server.Close()
		if fail && (err == nil || acks != 0) || !fail && (err != nil || acks != 1) {
			t.Fatalf("fail=%v err=%v acks=%d", fail, err, acks)
		}
	}
}

func TestAdaptivePolicyRequiresFullApplicationAndAcknowledgesMode(t *testing.T) {
	for _, capable := range []bool{false, true} {
		acks := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				acks++
				var body map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&body)
				if body["mode"] != "adaptive_agent" || body["target_traces_per_second"] != float64(12) {
					t.Error("ACK did not echo full mode")
				}
				return
			}
			fmt.Fprint(w, `{"version":0,"apm_sampling":{"version":4,"mode":"adaptive_agent","target_traces_per_second":12,"base_rate":0.1,"slow_threshold_ms":2000}}`)
		}))
		cfg := Config{Endpoint: server.URL, TenantID: "2", CollectorID: "collector", ApplyAPMSampling: func(float64, time.Duration) error { t.Error("adaptive used legacy apply"); return nil }}
		if capable {
			cfg.ApplyAPMSamplingPolicy = func(p sampler.Policy) error {
				if p.Mode != "adaptive_agent" || p.TargetTracesPerSecond != 12 {
					t.Error("wrong full policy")
				}
				return nil
			}
		}
		var version atomic.Int64
		err := pullOnce(context.Background(), server.Client(), cfg, &version, recordingApplier{}, slog.Default())
		server.Close()
		if capable && (err != nil || acks != 1) || !capable && (err == nil || acks != 0) {
			t.Fatalf("capable=%v err=%v ACKs=%d", capable, err, acks)
		}
	}
}

func TestSamplingAcknowledgedOnlyAfterApplication(t *testing.T) {
	for _, fail := range []bool{false, true} {
		applied, acks := false, 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				if !applied {
					t.Error("ACK before applying")
				}
				acks++
				return
			}
			fmt.Fprint(w, `{"version":0,"apm_sampling":{"version":3,"base_rate":0.4,"slow_threshold_ms":2000}}`)
		}))
		var version atomic.Int64
		err := pullOnce(context.Background(), server.Client(), Config{Endpoint: server.URL, TenantID: "2", CollectorID: "collector", ApplyAPMSampling: func(rate float64, slow time.Duration) error {
			if fail {
				return fmt.Errorf("apply failed")
			}
			if rate != 0.4 || slow != 2*time.Second {
				t.Error("wrong policy")
			}
			applied = true
			return nil
		}}, &version, recordingApplier{}, slog.Default())
		server.Close()
		if fail && (err == nil || acks != 0) {
			t.Fatalf("failed apply err=%v ACK=%d", err, acks)
		}
		if !fail && (err != nil || acks != 1) {
			t.Fatalf("successful apply err=%v ACK=%d", err, acks)
		}
	}
}
