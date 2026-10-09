package checks

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	_ "github.com/sijms/go-ora/v2"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestOracleDriverCompatibility(t *testing.T) {
	dsn := os.Getenv("ORACLE_TEST_DSN")
	if dsn == "" {
		t.Skip("set ORACLE_TEST_DSN for an Oracle Free instance")
	}
	db, err := sql.Open("oracle", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	var value int
	if err := db.QueryRowContext(ctx, "SELECT 1 FROM DUAL").Scan(&value); err != nil || value != 1 {
		t.Fatalf("Oracle SELECT 1: value=%d error=%v", value, err)
	}
	cfg := &collectorv1.CheckConfig{
		CheckId: "oracle-discovery-integration", CheckType: "oracle.instance_discovery", HostId: "host",
		Interval:   durationpb.New(time.Minute),
		Params:     map[string]string{"dsn": dsn, "installation_id": "installation-1"},
		StaticTags: map[string]string{"db_server": "127.0.0.1", "db_port": "1521"},
	}
	check, err := newOracleInstanceDiscoveryCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	discovery, err := check.(InstanceDiscoveryCheck).RunInstanceDiscovery(ctx)
	if err != nil || discovery.Engine != "oracle" || len(discovery.Databases) != 1 {
		t.Fatalf("Oracle discovery: %+v, %v", discovery, err)
	}
	cfg.CheckType = "oracle.server"
	cfg.StaticTags["db_name"] = discovery.Databases[0]
	server, err := newOracleServerCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.(interface{ Close() error }).Close()
	metrics, err := server.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"oracle.total_connections": false, "oracle.database_size_bytes": false}
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
	cfg.CheckType = "oracle.queries"
	cfg.Params["database_id"] = "database-1"
	queries, err := newOracleQueriesCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer queries.(interface{ Close() error }).Close()
	var observed int
	if err := queries.(*oracleQueries).pool.QueryRow(ctx, "SELECT 42 FROM DUAL").Scan(&observed); err != nil {
		t.Fatal(err)
	}
	if _, err := queries.(QueryStatsCheck).RunQueryStats(ctx); err != nil {
		t.Fatal(err)
	}
	if err := queries.(*oracleQueries).pool.QueryRow(ctx, "SELECT 42 FROM DUAL").Scan(&observed); err != nil {
		t.Fatal(err)
	}
	stats, err := queries.(QueryStatsCheck).RunQueryStats(ctx)
	if err != nil || stats.Engine != "oracle" || len(stats.Queries) == 0 {
		t.Fatalf("Oracle query stats: %+v, %v", stats, err)
	}
	if samples, err := queries.(QuerySamplesCheck).RunQuerySamples(ctx); err != nil || samples.Engine != "oracle" {
		t.Fatalf("Oracle query samples: %+v, %v", samples, err)
	}
	cfg.CheckType = "oracle.catalog"
	catalogCheck, err := newOracleCatalogCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer catalogCheck.(interface{ Close() error }).Close()
	catalog, err := catalogCheck.(CatalogCheck).RunCatalog(ctx)
	if err != nil || catalog.Engine != "oracle" {
		t.Fatalf("Oracle catalog: %+v, %v", catalog, err)
	}
	for _, table := range catalog.Tables {
		if table.SchemaName == "TELVYN_APP" && table.TableName == "TELVYN_TEST" && len(table.Columns) > 0 && len(table.Indexes) > 0 {
			return
		}
	}
	t.Fatalf("Oracle catalog missing TELVYN_APP.TELVYN_TEST: %+v", catalog.Tables)
}

func TestOracleCustomCompatibility(t *testing.T) {
	dsn := os.Getenv("ORACLE_TEST_DSN")
	if dsn == "" {
		t.Skip("set ORACLE_TEST_DSN for an Oracle Free instance")
	}
	cfg := &collectorv1.CheckConfig{CheckId: "oracle-custom-integration", HostId: "host",
		Interval: durationpb.New(time.Minute),
		Params: map[string]string{"dsn": dsn, "query": "SELECT 42 AS answer FROM DUAL",
			"metric_name": "test.answer", "columns_json": `[{"name":"answer","type":"gauge"}]`},
		StaticTags: map[string]string{"db_server": "oracle-test", "db_name": "FREEPDB1"}}
	custom, err := newSQLCustomCheck(cfg, "oracle", defaultOraclePoolFactory)
	if err != nil {
		t.Fatal(err)
	}
	defer custom.(interface{ Close() error }).Close()
	metrics, err := custom.Run(context.Background())
	if err != nil || len(metrics) != 1 || metrics[0].Value != 42 {
		t.Fatalf("Oracle custom metrics: %+v, %v", metrics, err)
	}
}

func TestOracleDiagnosticsCompatibility(t *testing.T) {
	dsn := os.Getenv("ORACLE_TEST_DSN")
	if dsn == "" {
		t.Skip("set ORACLE_TEST_DSN for an Oracle Free instance")
	}
	cfg := &collectorv1.CheckConfig{
		CheckId: "oracle-diagnostics-integration", HostId: "host",
		Interval:   durationpb.New(15 * time.Second),
		Params:     map[string]string{"dsn": dsn, "installation_id": "installation-1", "database_id": "database-1"},
		StaticTags: map[string]string{"db_server": "oracle-test", "db_name": "FREEPDB1"},
	}
	check, err := newOracleDiagnosticsCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	snapshot, err := check.(DiagnosticsCheck).RunDiagnostics(context.Background())
	if err != nil || snapshot.Engine != "oracle" || snapshot.Capabilities["sessions"] != "available" || snapshot.Capabilities["replication"] != "available" {
		t.Fatalf("Oracle diagnostics: %+v, %v", snapshot, err)
	}
}

func TestOracleCachedPlanCompatibility(t *testing.T) {
	dsn := os.Getenv("ORACLE_TEST_DSN")
	if dsn == "" {
		t.Skip("set ORACLE_TEST_DSN for an Oracle Free instance")
	}
	cfg := &collectorv1.CheckConfig{CheckId: "oracle-plan-integration", HostId: "host",
		Interval: durationpb.New(time.Minute),
		Params: map[string]string{"dsn": dsn, "installation_id": "installation-1", "database_id": "database-1",
			"continuous_plans_enabled": "true"}}
	check, err := newOracleQueriesCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	queries := check.(*oracleQueries)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var value int
	if err := queries.pool.QueryRow(ctx, "SELECT 42 FROM DUAL").Scan(&value); err != nil {
		t.Fatal(err)
	}
	var id string
	var child int64
	if err := queries.pool.QueryRow(ctx, `SELECT SQL_ID, CHILD_NUMBER FROM V$SQL WHERE
		SQL_TEXT='SELECT 42 FROM DUAL' AND PARSING_SCHEMA_NAME='TELVYN_APP' AND ROWNUM=1`).Scan(&id, &child); err != nil {
		t.Fatal(err)
	}
	plan, status := queries.cachedPlan(ctx, id, child)
	if status != "ready" || len(plan) == 0 || strings.Contains(string(plan), "SELECT 42") {
		t.Fatalf("Oracle cached plan: status=%s plan=%s", status, plan)
	}
}
