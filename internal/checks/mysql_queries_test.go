package checks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMySQLPlanSanitizesLiteralsAndLimitsLoad(t *testing.T) {
	pool := &stubSQLPool{rowsBySQLSnippet: map[string]*stubSQLRow{
		"EXPLAIN FORMAT=JSON": {values: []any{`{"query_block":{"table":{"table_name":"orders","access_type":"ref","attached_condition":"email = 'secret@example.com'","rows":4}}}`}},
	}}
	check := &mysqlQueries{pool: pool, planRuns: make(map[string]time.Time)}
	plan, status := check.explainSample(context.Background(), "SELECT * FROM orders WHERE email = 'secret@example.com'")
	if status != "ready" || strings.Contains(string(plan), "secret@example.com") || !strings.Contains(string(plan), `"table_name":"orders"`) {
		t.Fatalf("status=%s plan=%s", status, plan)
	}
	if !json.Valid(plan) {
		t.Fatalf("invalid plan: %s", plan)
	}
	now := time.Now()
	if !check.allowPlan("same", now) || check.allowPlan("same", now.Add(time.Minute)) {
		t.Fatal("per-digest cooldown not enforced")
	}
	for i := 0; i < 59; i++ {
		if !check.allowPlan(string(rune('a'+i)), now) {
			t.Fatalf("plan %d rejected early", i)
		}
	}
	if check.allowPlan("extra", now) {
		t.Fatal("plan budget not enforced")
	}
}
