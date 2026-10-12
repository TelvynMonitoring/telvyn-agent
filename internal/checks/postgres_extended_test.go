package checks

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPostgresExtendedNativeCountersAndNulls(t *testing.T) {
	pool := newStubPgxPool()
	pool.rowsBySQLPrefix[sqlPostgresExtendedStats] = &stubRow{vals: []any{`{"rows_inserted":123,"function_calls":null,"buffers_bgwriter":0,"checkpoint_sync_time_ms":4.5}`}}
	c := &postgresServer{pool: pool, hostID: "host-1", staticTags: map[string]string{"db_name": "lab"}}
	metrics := c.extendedMetrics(context.Background(), timestamppb.Now())
	if len(metrics) != 3 {
		t.Fatalf("expected 3 real metrics, got %d", len(metrics))
	}
	values := make(map[string]float64)
	for _, metric := range metrics {
		values[metric.MetricName] = metric.Value
		if metric.Tags["db_name"] != "lab" || metric.HostId != "host-1" {
			t.Fatal("database scope lost")
		}
	}
	if values["postgres.rows_inserted"] != 123 || values["postgres.checkpoint_sync_time_ms"] != 4.5 {
		t.Fatal("native values must not be converted to rates in the agent")
	}
	if _, ok := values["postgres.function_calls"]; ok {
		t.Fatal("null must remain unavailable")
	}
	if value, ok := values["postgres.buffers_bgwriter"]; !ok || value != 0 {
		t.Fatal("observed zero must be retained")
	}
}
