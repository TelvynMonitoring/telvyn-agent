package checks

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPostgresObjectMetricsPreserveDimensionsAndNulls(t *testing.T) {
	pool := newStubPgxPool()
	pool.rowsBySQLPrefix[sqlPostgresObjectStats] = &stubRow{vals: []any{`{"table":[{"schema":"public","name":"orders","metrics":{"rows_inserted":12,"last_autovacuum_age_seconds":null}}],"index":[{"schema":"public","name":"orders_pkey","parent":"orders","metrics":{"scan":3}}],"function":[]}`}}
	c := &postgresServer{pool: pool, hostID: "host-1", staticTags: map[string]string{"db_name": "lab"}}
	metrics := c.objectMetrics(context.Background(), timestamppb.Now())
	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(metrics))
	}
	for _, metric := range metrics {
		if metric.Tags["db_name"] != "lab" || metric.Tags["schema_name"] != "public" || metric.Tags["table_name"] != "orders" {
			t.Fatal("object scope lost")
		}
		if metric.MetricName == "postgres.object.index.scan" && metric.Tags["index_name"] != "orders_pkey" {
			t.Fatal("index scope lost")
		}
	}
}

func TestPostgresObjectQuerySQLRequiresNativeCounters(t *testing.T) {
	capabilities := postgresRelationCapabilities{qualifiedName: `"observability"."pg_stat_statements"`, columns: map[string]struct{}{}}
	if buildPostgresObjectQuerySQL(capabilities) != "" {
		t.Fatal("missing counters must not become zero")
	}
	for _, column := range []string{"dbid", "queryid", "calls", "shared_blks_hit", "shared_blks_read", "shared_blks_dirtied"} {
		capabilities.columns[column] = struct{}{}
	}
	sql := buildPostgresObjectQuerySQL(capabilities)
	if !strings.Contains(sql, capabilities.qualifiedName) || !strings.Contains(sql, "LIMIT 200") || strings.Contains(sql, "s.query AS") {
		t.Fatal("must preserve extension schema, bound cardinality, and avoid exporting SQL text")
	}
}
