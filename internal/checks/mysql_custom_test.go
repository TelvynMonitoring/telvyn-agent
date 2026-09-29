package checks

import (
	"context"
	"strings"
	"testing"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func TestMySQLCustomTypedAndReadOnly(t *testing.T) {
	pool := &stubSQLPool{rowsBySQLSnippet: map[string]*stubSQLRow{
		"JSON_ARRAYAGG": {values: []any{`[{"status":"paid","orders":12}]`}},
	}}
	cfg := &collectorv1.CheckConfig{CheckId: "mysql-custom-1", HostId: "host-1",
		StaticTags: map[string]string{"custom_name": "Orders", "installation_id": "instance-1", "database_id": "database-1"},
		Params: map[string]string{"dsn": "u:p@tcp(db:3306)/app", "query": "SELECT status, count(*) AS orders FROM orders GROUP BY status",
			"metric_name": "orders", "columns_json": `[{"name":"status","type":"tag"},{"name":"orders","type":"count"}]`},
	}
	check, err := newMySQLCustomCheckWithFactory(cfg, stubSQLPoolFactory(pool, nil))
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := check.Run(context.Background())
	if err != nil || len(metrics) != 1 {
		t.Fatalf("metrics=%v err=%v", metrics, err)
	}
	if metrics[0].MetricName != "mysql.custom.orders.orders" || metrics[0].Value != 12 ||
		metrics[0].Tags["custom.status"] != "paid" || metrics[0].Tags["database_id"] != "database-1" {
		t.Fatalf("unexpected metric: %+v", metrics[0])
	}
	for _, query := range []string{"DELETE FROM orders", "SELECT * FROM orders INTO OUTFILE '/tmp/orders'", "SELECT LOAD_FILE('/etc/passwd')"} {
		cfg.Params["query"] = query
		if _, err := newMySQLCustomCheckWithFactory(cfg, stubSQLPoolFactory(pool, nil)); err == nil || !strings.Contains(err.Error(), "mysql.custom") {
			t.Fatalf("unsafe query accepted: %q, %v", query, err)
		}
	}
}
