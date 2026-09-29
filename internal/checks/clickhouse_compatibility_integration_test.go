package checks

import (
	"context"
	"os"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestClickHouseDiscoveryCompatibility(t *testing.T) {
	dsn := os.Getenv("CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("set CLICKHOUSE_TEST_DSN for a local ClickHouse instance")
	}
	cfg := &collectorv1.CheckConfig{CheckId: "clickhouse-discovery-integration", CheckType: "clickhouse.instance_discovery",
		HostId: "host", Interval: durationpb.New(time.Minute),
		Params:     map[string]string{"dsn": dsn, "installation_id": "installation-1"},
		StaticTags: map[string]string{"db_server": "127.0.0.1", "db_port": "8123"}}
	check, err := newClickHouseInstanceDiscoveryCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	discovery, err := check.(InstanceDiscoveryCheck).RunInstanceDiscovery(context.Background())
	if err != nil || discovery.Engine != "clickhouse" || discovery.ServerVersion == "" {
		t.Fatalf("ClickHouse discovery: %+v, %v", discovery, err)
	}
	found := false
	for _, name := range discovery.Databases {
		if name == "app" {
			found = true
		}
	}
	if !found {
		t.Fatalf("database app missing from ClickHouse discovery: %+v", discovery.Databases)
	}
	cfg.CheckType = "clickhouse.server"
	cfg.StaticTags["db_name"] = "app"
	server, err := newClickHouseServerCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.(interface{ Close() error }).Close()
	metrics, err := server.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"clickhouse.total_connections": false, "clickhouse.database_size_bytes": false,
		"clickhouse.query_count_5m": false}
	for _, metric := range metrics {
		if metric.MetricName == "clickhouse.queries" {
			t.Fatal("global query counter must not be tagged as a logical database")
		}
		if metric.MetricName == "clickhouse.query_count_5m" && os.Getenv("CLICKHOUSE_TEST_EXPECT_QUERY") != "" && metric.Value <= 0 {
			t.Fatal("application query did not contribute to its database-specific counter")
		}
		if _, ok := want[metric.MetricName]; ok {
			want[metric.MetricName] = true
		}
	}
	for name, present := range want {
		if !present {
			t.Errorf("metric %s missing", name)
		}
	}
	cfg.CheckType = "clickhouse.catalog"
	cfg.Params["database_id"] = "database-1"
	catalogCheck, err := newClickHouseCatalogCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer catalogCheck.(interface{ Close() error }).Close()
	catalog, err := catalogCheck.(CatalogCheck).RunCatalog(context.Background())
	if err != nil || catalog.Engine != "clickhouse" {
		t.Fatalf("ClickHouse catalog: %+v, %v", catalog, err)
	}
	found = false
	for _, table := range catalog.Tables {
		if table.TableName == "telvyn_test" && len(table.Columns) > 0 && len(table.Indexes) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("ClickHouse catalog missing telvyn_test: %+v", catalog.Tables)
	}
	cfg.CheckType = "clickhouse.queries"
	queries, err := newClickHouseQueriesCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer queries.(interface{ Close() error }).Close()
	stats, err := queries.(QueryStatsCheck).RunQueryStats(context.Background())
	if err != nil || stats.Engine != "clickhouse" {
		t.Fatalf("ClickHouse query stats: %+v, %v", stats, err)
	}
	if os.Getenv("CLICKHOUSE_TEST_EXPECT_QUERY") != "" && len(stats.Queries) == 0 {
		t.Fatal("ClickHouse query log returned no application query")
	}
	if samples, err := queries.(QuerySamplesCheck).RunQuerySamples(context.Background()); err != nil || samples.Engine != "clickhouse" {
		t.Fatalf("ClickHouse query samples: %+v, %v", samples, err)
	}
}

func TestClickHousePlanCompatibility(t *testing.T) {
	dsn := os.Getenv("CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("set CLICKHOUSE_TEST_DSN for a local ClickHouse instance")
	}
	cfg := &collectorv1.CheckConfig{CheckId: "clickhouse-plan-integration", HostId: "host",
		Interval: durationpb.New(time.Minute),
		Params: map[string]string{"dsn": dsn, "installation_id": "installation-1", "database_id": "database-1",
			"continuous_plans_enabled": "true"}}
	check, err := newClickHouseQueriesCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	plan, status := check.(*clickhouseQueries).explainPlan(context.Background(), "SELECT 1")
	if status != "ready" || len(plan) == 0 {
		t.Fatalf("ClickHouse EXPLAIN PLAN: status=%s plan=%s", status, plan)
	}
}

func TestClickHouseCustomCompatibility(t *testing.T) {
	dsn := os.Getenv("CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("set CLICKHOUSE_TEST_DSN for a local ClickHouse instance")
	}
	cfg := &collectorv1.CheckConfig{CheckId: "clickhouse-custom-integration", HostId: "host",
		Interval: durationpb.New(time.Minute),
		Params: map[string]string{"dsn": dsn, "query": "SELECT 42 AS answer",
			"metric_name": "test.answer", "columns_json": `[{"name":"answer","type":"gauge"}]`},
		StaticTags: map[string]string{"db_server": "clickhouse-test", "db_name": "app"}}
	custom, err := newClickHouseCustomCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer custom.(interface{ Close() error }).Close()
	metrics, err := custom.Run(context.Background())
	if err != nil || len(metrics) != 1 || metrics[0].Value != 42 {
		t.Fatalf("ClickHouse custom metrics: %+v, %v", metrics, err)
	}
}

func TestClickHouseDiagnosticsCompatibility(t *testing.T) {
	dsn := os.Getenv("CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("set CLICKHOUSE_TEST_DSN for a local ClickHouse instance")
	}
	cfg := &collectorv1.CheckConfig{CheckId: "clickhouse-diagnostics-integration", HostId: "host",
		Interval:   durationpb.New(15 * time.Second),
		Params:     map[string]string{"dsn": dsn, "installation_id": "installation-1", "database_id": "database-1"},
		StaticTags: map[string]string{"db_server": "clickhouse-test", "db_name": "app"}}
	check, err := newClickHouseDiagnosticsCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	snapshot, err := check.(DiagnosticsCheck).RunDiagnostics(context.Background())
	if err != nil || snapshot.Engine != "clickhouse" || snapshot.Capabilities["sessions"] != "available" || snapshot.Capabilities["replication"] != "available" {
		t.Fatalf("ClickHouse diagnostics: %+v, %v", snapshot, err)
	}
}
