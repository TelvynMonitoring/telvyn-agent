package checks

import (
	"context"
	"os"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestMySQLCompatibility(t *testing.T) {
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set MYSQL_TEST_DSN for a local MySQL or MariaDB instance")
	}
	base := &collectorv1.CheckConfig{
		CheckId: "mysql-discovery-integration", HostId: "host",
		Interval:   durationpb.New(time.Minute),
		Params:     map[string]string{"dsn": dsn, "installation_id": "installation-1"},
		StaticTags: map[string]string{"db_server": "127.0.0.1", "db_port": "3306", "db_name": "app"},
	}
	base.CheckType = "mysql.instance_discovery"
	discoveryCheck, err := newMySQLInstanceDiscoveryCheck(base)
	if err != nil {
		t.Fatal(err)
	}
	defer discoveryCheck.(interface{ Close() error }).Close()
	discovery, err := discoveryCheck.(InstanceDiscoveryCheck).RunInstanceDiscovery(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Engine != "mysql" || len(discovery.Databases) == 0 {
		t.Fatalf("no visible databases: %+v", discovery)
	}
	base.CheckType = "mysql.server"
	serverCheck, err := newMySQLServerCheck(base)
	if err != nil {
		t.Fatal(err)
	}
	defer serverCheck.(interface{ Close() error }).Close()
	metrics, err := serverCheck.Run(context.Background())
	if err != nil || len(metrics) == 0 {
		t.Fatalf("no MySQL metrics: %d, %v", len(metrics), err)
	}
	want := map[string]bool{
		"mysql.total_connections":   false,
		"mysql.cache_hit_ratio":     false,
		"mysql.commits":             false,
		"mysql.database_size_bytes": false,
	}
	for _, metric := range metrics {
		if _, exists := want[metric.MetricName]; exists {
			want[metric.MetricName] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("metric %s missing", name)
		}
	}
	base.Params["database_id"] = "database-1"
	base.CheckType = "mysql.diagnostics"
	diagnosticsCheck, err := newMySQLDiagnosticsCheck(base)
	if err != nil {
		t.Fatal(err)
	}
	defer diagnosticsCheck.(interface{ Close() error }).Close()
	diagnostics, err := diagnosticsCheck.(DiagnosticsCheck).RunDiagnostics(context.Background())
	if err != nil || diagnostics.Engine != "mysql" || diagnostics.Capabilities["sessions"] != "available" {
		t.Fatalf("MySQL diagnostics failed: %+v, %v", diagnostics, err)
	}
	base.CheckType = "mysql.catalog"
	catalogCheck, err := newMySQLCatalogCheck(base)
	if err != nil {
		t.Fatal(err)
	}
	defer catalogCheck.(interface{ Close() error }).Close()
	catalog, err := catalogCheck.(CatalogCheck).RunCatalog(context.Background())
	if err != nil || catalog.Engine != "mysql" || catalog.DBName != "app" || len(catalog.Fingerprint) != 64 {
		t.Fatalf("invalid MySQL catalog: %+v, %v", catalog, err)
	}
	if expected := os.Getenv("MYSQL_TEST_CATALOG_TABLE"); expected != "" {
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
	base.CheckType = "mysql.queries"
	queryCheck, err := newMySQLQueriesCheck(base)
	if err != nil {
		if err.Error() == "mysql.queries: performance_schema indisponível" {
			t.Log("query digests unavailable because performance_schema is disabled")
			return
		}
		t.Fatal(err)
	}
	defer queryCheck.(interface{ Close() error }).Close()
	if samples, err := queryCheck.(QuerySamplesCheck).RunQuerySamples(context.Background()); err != nil || samples.Engine != "mysql" {
		t.Fatalf("MySQL query samples failed: %+v, %v", samples, err)
	}
	var one int
	if err := queryCheck.(*mysqlQueries).pool.QueryRow(context.Background(), "SELECT 42").Scan(&one); err != nil {
		t.Fatal(err)
	}
	if _, err := queryCheck.(QueryStatsCheck).RunQueryStats(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := queryCheck.(*mysqlQueries).pool.QueryRow(context.Background(), "SELECT 42").Scan(&one); err != nil {
		t.Fatal(err)
	}
	stats, err := queryCheck.(QueryStatsCheck).RunQueryStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Engine != "mysql" || len(stats.Queries) == 0 {
		t.Fatalf("expected MySQL query delta: %+v", stats)
	}
	base.CheckType = "mysql.custom"
	base.Params["query"] = "SELECT 42 AS answer"
	base.Params["metric_name"] = "test.answer"
	base.Params["columns_json"] = `[{"name":"answer","type":"gauge"}]`
	customCheck, err := newMySQLCustomCheck(base)
	if err != nil {
		t.Fatal(err)
	}
	defer customCheck.(interface{ Close() error }).Close()
	customMetrics, err := customCheck.Run(context.Background())
	if err != nil || len(customMetrics) != 1 || customMetrics[0].Value != 42 {
		t.Fatalf("custom query failed: %+v, %v", customMetrics, err)
	}
	plan, status := queryCheck.(*mysqlQueries).explainSample(context.Background(), "SELECT 42")
	if status != "ready" || len(plan) == 0 {
		t.Fatalf("EXPLAIN unavailable: %s, %s", status, plan)
	}
}
