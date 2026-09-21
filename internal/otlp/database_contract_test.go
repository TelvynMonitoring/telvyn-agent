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

func TestDatabaseSignalsCarryVersionedEnvelope(t *testing.T) {
	var got DatabaseCapabilitiesPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest/v1/db/capabilities" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := NewIngestExporter(server.URL, "iwI_test", "host-1", "", "test",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.client = server.Client()
	exporter.SetEnabledModules([]string{"BANCOS_DADOS"})

	err := exporter.PostDatabaseCapabilities(context.Background(), DatabaseCapabilitiesPayload{
		InstallationID: "11111111-1111-1111-1111-111111111111",
		DatabaseID:     "22222222-2222-2222-2222-222222222222",
		DBServer:       "postgres.internal",
		DBName:         "billing",
		Capabilities: []DatabaseCapability{{
			Name: "replication", Status: "available",
		}},
	})
	if err != nil {
		t.Fatalf("PostDatabaseCapabilities: %v", err)
	}
	if got.ContractVersion != DatabaseContractVersion || got.Signal != DatabaseSignalCapabilities {
		t.Fatalf("invalid envelope: %+v", got.DatabaseSignalEnvelope)
	}
	if got.Engine != "postgres" || got.CollectedAt == "" {
		t.Fatalf("missing engine/time: %+v", got.DatabaseSignalEnvelope)
	}
}

func TestDatabaseRuntimeRequiresDatabaseEntitlement(t *testing.T) {
	exporter := NewIngestExporter("http://localhost", "iwI_test", "host-1", "", "test",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.SetEnabledModules([]string{"APM"})
	if exporter.signalAllowed("db/runtime") || exporter.signalAllowed("db/capabilities") {
		t.Fatal("foundation database signals must require BANCOS_DADOS")
	}
	exporter.SetEnabledModules([]string{"BANCOS_DADOS"})
	if !exporter.signalAllowed("db/runtime") || !exporter.signalAllowed("db/capabilities") {
		t.Fatal("foundation database signals should be enabled")
	}
}
