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

func TestPostDatabaseQueryStatsPostsDedicatedSignal(t *testing.T) {
	var gotPath string
	var got DatabaseQueryStatsPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Header.Get("Authorization") != "Bearer iwI_test" {
			t.Errorf("missing bearer authorization: %q", r.Header.Get("Authorization"))
		}
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
	err := exporter.PostDatabaseQueryStats(context.Background(), DatabaseQueryStatsPayload{
		DBServer: "db.internal", DBName: "billing", WindowSeconds: 60,
		Queries: []DatabaseQueryStat{{QueryID: "42", Text: "SELECT count(*)", Calls: 3, TotalMS: 12, MeanMS: 4, Rows: 3}},
	})
	if err != nil {
		t.Fatalf("PostDatabaseQueryStats failed: %v", err)
	}
	if gotPath != "/api/ingest/v1/db/query-stats" {
		t.Fatalf("unexpected path: %q", gotPath)
	}
	if got.DBServer != "db.internal" || got.DBName != "billing" || len(got.Queries) != 1 || got.Queries[0].Calls != 3 {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

func TestSignalAllowedDatabaseQueryStatsRequiresDatabaseModule(t *testing.T) {
	exporter := NewIngestExporter("http://localhost", "iwI_test", "host-1", "", "0.4.9",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.SetEnabledModules([]string{"APM"})
	if exporter.signalAllowed("db/query-stats") {
		t.Fatal("database query stats must be blocked without BANCOS_DADOS")
	}
	exporter.SetEnabledModules([]string{"BANCOS_DADOS"})
	if !exporter.signalAllowed("db/query-stats") {
		t.Fatal("database query stats must be allowed with BANCOS_DADOS")
	}
}

func TestPostDatabaseCatalogPostsDedicatedSignal(t *testing.T) {
	var gotPath string
	var got DatabaseCatalogPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Header.Get("Authorization") != "Bearer iwI_test" {
			t.Errorf("missing bearer authorization: %q", r.Header.Get("Authorization"))
		}
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
	err := exporter.PostDatabaseCatalog(context.Background(), DatabaseCatalogPayload{
		DBServer: "db.internal", DBName: "billing", ServerVersion: "16.4",
		DatabaseSizeBytes: 123, Fingerprint: "abc", Tables: []DatabaseCatalogTable{{
			SchemaName: "public", TableName: "invoices", TableKind: "table",
		}},
	})
	if err != nil {
		t.Fatalf("PostDatabaseCatalog failed: %v", err)
	}
	if gotPath != "/api/ingest/v1/db/catalog" {
		t.Fatalf("unexpected path: %q", gotPath)
	}
	if got.DBServer != "db.internal" || got.DBName != "billing" || len(got.Tables) != 1 {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

func TestSignalAllowedDatabaseCatalogRequiresDatabaseModule(t *testing.T) {
	exporter := NewIngestExporter("http://localhost", "iwI_test", "host-1", "", "0.4.9",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.SetEnabledModules([]string{"APM"})
	if exporter.signalAllowed("db/catalog") {
		t.Fatal("database catalog must be blocked without BANCOS_DADOS")
	}
	exporter.SetEnabledModules([]string{"BANCOS_DADOS"})
	if !exporter.signalAllowed("db/catalog") {
		t.Fatal("database catalog must be allowed with BANCOS_DADOS")
	}
}
