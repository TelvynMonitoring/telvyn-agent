package otlp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterCollectorReportsBinaryVersion(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest/v1/collector/register" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"collector_id":"11111111-1111-1111-1111-111111111111","tenant":"2"}`)
	}))
	defer server.Close()

	exporter := NewIngestExporter(server.URL, "iwI_test", "host", "cluster", "v0.4.4",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, _, err := exporter.RegisterCollector(context.Background(), "poller", []string{"metrics"}, "docker"); err != nil {
		t.Fatalf("RegisterCollector: %v", err)
	}
	if got := payload["agent_version"]; got != "v0.4.4" {
		t.Fatalf("agent_version = %v, want v0.4.4", got)
	}
	if got := payload["install_mode"]; got != "docker" {
		t.Fatalf("install_mode = %v, want docker", got)
	}
}

func TestRegisterCollectorReportsSanitizedRuntimeSnapshot(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"collector_id":"11111111-1111-1111-1111-111111111111","tenant":"2"}`)
	}))
	defer server.Close()

	exporter := NewIngestExporter(server.URL, "iwI_test", "host", "", "v0.4.15",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.SetCollectorRuntimeStatsProvider(func() CollectorRuntimeStats {
		return CollectorRuntimeStats{ActiveChecks: 3, PollRuns: 9, PollFailures: 2, PollTimeouts: 1}
	})
	if _, _, err := exporter.RegisterCollector(context.Background(), "poller", []string{"snmp"}, "docker"); err != nil {
		t.Fatalf("RegisterCollector: %v", err)
	}
	runtime, ok := payload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("runtime ausente: %v", payload)
	}
	if runtime["active_checks"] != float64(3) || runtime["poll_runs"] != float64(9) {
		t.Fatalf("runtime inesperado: %v", runtime)
	}
	if runtime["pending_payloads"] != float64(0) || runtime["ingest_blocked"] != false {
		t.Fatalf("fila inesperada: %v", runtime)
	}
	if raw, ok := runtime["agent_time"].(string); !ok || raw == "" {
		t.Fatalf("agent_time ausente: %v", runtime)
	}
}

func TestRegisterDatabaseCollectorReportsSeparateAgentAndMachineUUIDs(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"collector_id":"11111111-1111-4111-8111-111111111111","tenant":"2"}`)
	}))
	defer server.Close()

	exporter := NewIngestExporter(server.URL, "iwI_test", "postgres-01", "", "vtest",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.SetDatabaseAgentIdentity("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	if _, _, err := exporter.RegisterCollector(context.Background(), "postgres-01 · banco · 11111111", []string{"metrics"}, "linux"); err != nil {
		t.Fatalf("RegisterCollector: %v", err)
	}
	if payload["agent_id"] != "11111111-1111-4111-8111-111111111111" || payload["machine_id"] != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("identity payload=%v", payload)
	}
	if payload["host_name"] != "postgres-01" {
		t.Fatalf("host_name=%v", payload["host_name"])
	}
}
