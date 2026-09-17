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

func TestPostDatabaseDiagnosticsPostsDedicatedSignal(t *testing.T) {
	var gotPath string
	var got DatabaseDiagnosticsPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := NewIngestExporter(server.URL, "iwI_test", "host-1", "", "0.4.9",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.client = server.Client()
	exporter.SetEnabledModules([]string{"BANCOS_DADOS"})
	err := exporter.PostDatabaseDiagnostics(context.Background(), DatabaseDiagnosticsPayload{
		DBServer: "db.internal", DBName: "billing", Capabilities: map[string]string{"sessions": "available"},
		Sessions: []DatabaseDiagnosticsSession{{PID: 7, User: "app"}},
	})
	if err != nil {
		t.Fatalf("PostDatabaseDiagnostics failed: %v", err)
	}
	if gotPath != "/api/ingest/v1/db/diagnostics" || got.DBServer != "db.internal" || len(got.Sessions) != 1 {
		t.Fatalf("unexpected diagnostics payload path=%q body=%+v", gotPath, got)
	}
}

func TestSignalAllowedDatabaseDiagnosticsRequiresDatabaseModule(t *testing.T) {
	exporter := NewIngestExporter("http://localhost", "iwI_test", "host-1", "", "0.4.9",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.SetEnabledModules([]string{"APM"})
	if exporter.signalAllowed("db/diagnostics") {
		t.Fatal("database diagnostics must be blocked without BANCOS_DADOS")
	}
	exporter.SetEnabledModules([]string{"BANCOS_DADOS"})
	if !exporter.signalAllowed("db/diagnostics") {
		t.Fatal("database diagnostics must be allowed with BANCOS_DADOS")
	}
}
