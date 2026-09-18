package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestPostgresCustom_ExecutesReadOnlyNumericQuery(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix["SELECT count(*)"] = &stubRow{vals: []any{int64(27)}}
	cfg := &collectorv1.CheckConfig{
		CheckId:    "pg-custom-1",
		CheckType:  "postgres.custom",
		Interval:   durationpb.New(30 * time.Second),
		HostId:     "host-1",
		StaticTags: map[string]string{"db_server": "db.internal", "custom_name": "Pedidos", "db_monitor_id": "logical-db-1"},
		Params: map[string]string{
			"dsn":             "postgres://u:p@h:5432/d",
			"query":           "SELECT count(*) FROM orders",
			"metric_name":     "orders.count",
			"installation_id": "installation-1",
		},
	}
	check, err := newPostgresCustomCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	metrics, err := check.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(metrics) != 1 || metrics[0].Value != 27 {
		t.Fatalf("unexpected metrics: %+v", metrics)
	}
	if metrics[0].MetricName != "postgres.custom.orders.count" {
		t.Errorf("unexpected metric name: %q", metrics[0].MetricName)
	}
	if metrics[0].Tags["custom_query"] != "Pedidos" {
		t.Errorf("custom query tag missing: %+v", metrics[0].Tags)
	}
	if metrics[0].Tags["installation_id"] != "installation-1" || metrics[0].Tags["database_id"] != "logical-db-1" {
		t.Errorf("database identity tags missing: %+v", metrics[0].Tags)
	}
}

func TestPostgresCustom_RejectsWriteAndMultipleStatements(t *testing.T) {
	base := &collectorv1.CheckConfig{
		CheckType: "postgres.custom",
		HostId:    "host-1",
		Params: map[string]string{
			"dsn":         "postgres://u:p@h:5432/d",
			"metric_name": "x",
		},
	}
	for _, query := range []string{
		"UPDATE orders SET status = 'paid'",
		"SELECT 1; DELETE FROM orders",
		"WITH x AS (DELETE FROM orders RETURNING id) SELECT count(*) FROM x",
	} {
		cfg := *base
		cfg.Params = map[string]string{"dsn": base.Params["dsn"], "metric_name": "x", "query": query}
		_, err := newPostgresCustomCheckWithFactory(&cfg, newStubPoolFactory(newStubPgxPool(), nil))
		if err == nil || !strings.Contains(err.Error(), "postgres.custom") {
			t.Errorf("query %q should be rejected, got %v", query, err)
		}
	}
}

func TestPostgresCustom_RejectsUnsafeMetricName(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckType: "postgres.custom",
		HostId:    "host-1",
		Params: map[string]string{
			"dsn":         "postgres://u:p@h:5432/d",
			"query":       "SELECT 1",
			"metric_name": "orders count",
		},
	}
	_, err := newPostgresCustomCheckWithFactory(cfg, newStubPoolFactory(newStubPgxPool(), nil))
	if err == nil || !strings.Contains(err.Error(), "metric_name") {
		t.Fatalf("unsafe metric name should be rejected, got %v", err)
	}
}
