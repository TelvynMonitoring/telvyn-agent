package otlp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	metricscolpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestRegisterDatabaseCollectorIncludesInstallationID(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest/v1/collector/register" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		_, _ = io.WriteString(w, `{"collector_id":"collector-1","tenant":"tenant-1"}`)
	}))
	defer server.Close()

	exporter := NewIngestExporter(server.URL, "iwI_test", "db-host", "", "vtest", slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.SetDatabaseInstallationID("installation-1")
	if _, _, err := exporter.RegisterCollector(context.Background(), "db-host · banco · installa", []string{"metrics", "db-postgres"}, "linux"); err != nil {
		t.Fatalf("RegisterCollector: %v", err)
	}
	if payload["installation_id"] != "installation-1" {
		t.Fatalf("installation_id=%v, want installation-1", payload["installation_id"])
	}
}

func TestDatabaseInstanceDiscoveryUsesScopedIdentity(t *testing.T) {
	var payload DatabaseInstanceDiscoveryPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest/v1/db/instances/discover" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		if r.Header.Get("X-Ispwatch-Collector") != "collector-1" {
			t.Fatalf("collector header=%q", r.Header.Get("X-Ispwatch-Collector"))
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	exporter := NewIngestExporter(server.URL, "iwI_test", "db-host", "", "vtest", slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.SetDatabaseInstallationID("installation-1")
	exporter.SetCollectorID("collector-1")
	err := exporter.PostDatabaseInstanceDiscovery(context.Background(), DatabaseInstanceDiscoveryPayload{
		InstallationID: "stale-installation", Engine: "postgres", Server: "postgres.internal", Port: 5432,
		ServerVersion: "PostgreSQL 17.2", Databases: []string{"app", "reporting"},
	})
	if err != nil {
		t.Fatalf("PostDatabaseInstanceDiscovery: %v", err)
	}
	if payload.InstallationID != "installation-1" || len(payload.Databases) != 2 {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestDatabaseProfileRejectsStructuredPayloadWithoutLogicalDatabaseID(t *testing.T) {
	exporter := NewIngestExporter("http://127.0.0.1", "iwI_test", "db-host", "", "vtest", slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.SetDatabaseInstallationID("installation-1")
	err := exporter.PostDatabaseQueryStats(context.Background(), DatabaseQueryStatsPayload{
		DBServer: "postgres.internal", DBName: "app", WindowSeconds: 60,
		Queries: []DatabaseQueryStat{{QueryID: "1", Calls: 1}},
	})
	if err == nil {
		t.Fatal("database profile must require database_id for structured payload")
	}
}

func TestTerminalRemovalOnlyFiresForGone(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusGone} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			exporter := NewIngestExporter(server.URL, "iwI_test", "db-host", "", "vtest", slog.New(slog.NewTextHandler(io.Discard, nil)))
			called := make(chan int, 1)
			exporter.SetTerminalFailureHandler(func(got int) { called <- got })
			if err := exporter.PostRaw(context.Background(), "metrics", "application/json", []byte(`{}`)); err == nil {
				t.Fatal("expected HTTP error")
			}
			select {
			case got := <-called:
				if status != http.StatusGone || got != http.StatusGone {
					t.Fatalf("terminal callback status=%d, response=%d", got, status)
				}
			default:
				if status == http.StatusGone {
					t.Fatal("410 must trigger terminal removal")
				}
			}
		})
	}
}

func TestForbiddenSignalDoesNotBlockHostMetricsQueue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	exporter := NewIngestExporter(server.URL, "iwI_test", "db-host", "", "vtest", slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.client = server.Client()
	defer exporter.metricsPending.Close()

	if err := exporter.PostRaw(context.Background(), "db/runtime", "application/json", []byte(`{}`)); err == nil {
		t.Fatal("expected HTTP 403")
	}
	if exporter.metricsPending.Blocked() {
		t.Fatal("403 de um sinal de banco não pode bloquear as métricas do host")
	}
}

func TestDatabaseProfileMetricsUseExporterInstallationID(t *testing.T) {
	t.Setenv("ISPWATCH_STATE_DIR", t.TempDir())
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest/v1/metrics" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	exporter := NewIngestExporter(server.URL, "iwI_test", "db-host", "", "vtest", slog.New(slog.NewTextHandler(io.Discard, nil)))
	exporter.client = server.Client()
	defer exporter.metricsPending.Close()
	exporter.SetDatabaseInstallationID("installation-1")
	if err := exporter.PostMetrics(context.Background(), []*collectorv1.Metric{{
		MetricName: "cpu_usage_percent",
		Value:      42,
		Tags: map[string]string{
			"installation_id": "stale-installation",
			"database_id":     "logical-db-1",
		},
	}}); err != nil {
		t.Fatalf("PostMetrics: %v", err)
	}

	var request metricscolpb.ExportMetricsServiceRequest
	if err := protojson.Unmarshal(body, &request); err != nil {
		t.Fatalf("decode OTLP metrics: %v", err)
	}
	resource := request.GetResourceMetrics()[0].GetResource().GetAttributes()
	if got := flattenAttrs(resource)["installation_id"]; got != "installation-1" {
		t.Fatalf("resource installation_id=%q", got)
	}
	point := request.GetResourceMetrics()[0].GetScopeMetrics()[0].GetMetrics()[0].GetGauge().GetDataPoints()[0]
	attrs := flattenAttrs(point.GetAttributes())
	if got := attrs["installation_id"]; got != "installation-1" {
		t.Fatalf("point installation_id=%q", got)
	}
	if got := attrs["database_id"]; got != "logical-db-1" {
		t.Fatalf("point database_id=%q", got)
	}
}
