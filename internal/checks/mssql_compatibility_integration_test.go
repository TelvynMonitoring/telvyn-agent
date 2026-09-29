package checks

import (
	"context"
	"os"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestMSSQLCompatibility(t *testing.T) {
	dsn := os.Getenv("MSSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set MSSQL_TEST_DSN for a local SQL Server instance")
	}
	cfg := &collectorv1.CheckConfig{
		CheckId: "mssql-discovery-integration", CheckType: "mssql.instance_discovery", HostId: "host",
		Interval:   durationpb.New(time.Minute),
		Params:     map[string]string{"dsn": dsn, "installation_id": "installation-1"},
		StaticTags: map[string]string{"db_server": "127.0.0.1", "db_port": "1433", "db_name": "app"},
	}
	check, err := newMSSQLInstanceDiscoveryCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	discovery, err := check.(InstanceDiscoveryCheck).RunInstanceDiscovery(context.Background())
	if err != nil || discovery.Engine != "mssql" {
		t.Fatalf("SQL Server discovery: %+v, %v", discovery, err)
	}
	if os.Getenv("MSSQL_TEST_EXPECT_DATABASE") != "" {
		found := false
		for _, name := range discovery.Databases {
			if name == os.Getenv("MSSQL_TEST_EXPECT_DATABASE") {
				found = true
			}
		}
		if !found {
			t.Fatalf("database not discovered: %+v", discovery.Databases)
		}
	}
	cfg.CheckType = "mssql.server"
	server, err := newMSSQLServerCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.(interface{ Close() error }).Close()
	metrics, err := server.Run(context.Background())
	if err != nil || len(metrics) == 0 {
		t.Fatalf("SQL Server metrics: %d, %v", len(metrics), err)
	}
	want := map[string]bool{"mssql.total_connections": false, "mssql.database_size_bytes": false}
	for _, metric := range metrics {
		if _, ok := want[metric.MetricName]; ok {
			want[metric.MetricName] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("metric %s missing", name)
		}
	}
	cfg.Params["database_id"] = "database-1"
	cfg.CheckType = "mssql.diagnostics"
	diagnosticsCheck, err := newMSSQLDiagnosticsCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer diagnosticsCheck.(interface{ Close() error }).Close()
	diagnostics, err := diagnosticsCheck.(DiagnosticsCheck).RunDiagnostics(context.Background())
	if err != nil || diagnostics.Engine != "mssql" || diagnostics.Capabilities["sessions"] != "available" || diagnostics.Capabilities["replication"] != "available" {
		t.Fatalf("SQL Server diagnostics: %+v, %v", diagnostics, err)
	}
	cfg.CheckType = "mssql.catalog"
	catalogCheck, err := newMSSQLCatalogCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer catalogCheck.(interface{ Close() error }).Close()
	catalog, err := catalogCheck.(CatalogCheck).RunCatalog(context.Background())
	if err != nil || catalog.Engine != "mssql" || len(catalog.Fingerprint) != 64 {
		t.Fatalf("SQL Server catalog: %+v, %v", catalog, err)
	}
	if expected := os.Getenv("MSSQL_TEST_CATALOG_TABLE"); expected != "" {
		found := false
		for _, table := range catalog.Tables {
			if table.TableName == expected && len(table.Columns) > 0 && len(table.Indexes) > 0 {
				found = true
			}
		}
		if !found {
			t.Fatalf("catalog missing table %s with columns and indexes: %+v", expected, catalog.Tables)
		}
	}
	cfg.CheckType = "mssql.queries"
	queries, err := newMSSQLQueriesCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer queries.(interface{ Close() error }).Close()
	var connectedDatabase string
	if err := queries.(*mssqlQueries).pool.QueryRow(context.Background(), "SELECT DB_NAME()").Scan(&connectedDatabase); err != nil {
		t.Fatal(err)
	}
	if connectedDatabase != "app" {
		t.Fatalf("connected to %s, expected app", connectedDatabase)
	}
	if statement := os.Getenv("MSSQL_TEST_QUERY"); statement != "" {
		var value string
		if err := queries.(*mssqlQueries).pool.QueryRow(context.Background(), statement).Scan(&value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := queries.(QueryStatsCheck).RunQueryStats(context.Background()); err != nil {
		t.Fatal(err)
	}
	if statement := os.Getenv("MSSQL_TEST_QUERY"); statement != "" {
		var value string
		if err := queries.(*mssqlQueries).pool.QueryRow(context.Background(), statement).Scan(&value); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := queries.(QueryStatsCheck).RunQueryStats(context.Background())
	if err != nil || stats.Engine != "mssql" || (os.Getenv("MSSQL_TEST_QUERY") != "" && len(stats.Queries) == 0) {
		t.Fatalf("SQL Server query stats: %+v, %v", stats, err)
	}
	if samples, err := queries.(QuerySamplesCheck).RunQuerySamples(context.Background()); err != nil || samples.Engine != "mssql" {
		t.Fatalf("SQL Server query samples: %+v, %v", samples, err)
	}
	cfg.CheckType = "mssql.custom"
	cfg.Params["query"] = "SELECT CAST(42 AS float) AS answer"
	cfg.Params["metric_name"] = "test.answer"
	cfg.Params["columns_json"] = `[{"name":"answer","type":"gauge"}]`
	custom, err := newSQLCustomCheck(cfg, "mssql", defaultMSSQLPoolFactory)
	if err != nil {
		t.Fatal(err)
	}
	defer custom.(interface{ Close() error }).Close()
	customMetrics, err := custom.Run(context.Background())
	if err != nil || len(customMetrics) != 1 || customMetrics[0].Value != 42 {
		t.Fatalf("SQL Server custom metrics: %+v, %v", customMetrics, err)
	}
}

func TestMSSQLCachedPlanCompatibility(t *testing.T) {
	dsn := os.Getenv("MSSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set MSSQL_TEST_DSN for a local SQL Server instance")
	}
	cfg := &collectorv1.CheckConfig{CheckId: "mssql-plan-integration", HostId: "host",
		Interval: durationpb.New(time.Minute),
		Params: map[string]string{"dsn": dsn, "installation_id": "installation-1", "database_id": "database-1",
			"continuous_plans_enabled": "true"}}
	check, err := newMSSQLQueriesCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	queries := check.(*mssqlQueries)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var handle []byte
	var start, end int64
	if err := queries.pool.QueryRow(ctx, `SELECT TOP (1) q.plan_handle,q.statement_start_offset,q.statement_end_offset
		FROM sys.dm_exec_query_stats q CROSS APPLY sys.dm_exec_sql_text(q.sql_handle) t
		WHERE t.text LIKE '%sys.dm_exec_query_stats%' ORDER BY q.last_execution_time DESC`).Scan(&handle, &start, &end); err != nil {
		t.Fatal(err)
	}
	plan, status := queries.cachedPlan(ctx, handle, start, end)
	if status != "ready" || len(plan) == 0 {
		t.Fatalf("SQL Server cached plan: status=%s plan=%s", status, plan)
	}
}
