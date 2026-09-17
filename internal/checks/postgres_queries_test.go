package checks

import (
	"context"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestPostgresQueries_UsesDeltaAndSanitizesText(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix["FROM pg_stat_statements"] = &stubRow{vals: []any{`[{"query_id":"42","text":"SELECT * FROM accounts WHERE email = 'ana@example.com' AND id = 17 -- secret","calls":10,"total_ms":100.0,"rows":20}]`}}
	cfg := &collectorv1.CheckConfig{
		CheckId:    "pg-queries-1",
		CheckType:  "postgres.queries",
		Interval:   durationpb.New(60 * time.Second),
		HostId:     "host-1",
		StaticTags: map[string]string{"db_server": "db.internal", "db_name": "billing"},
		Params:     map[string]string{"dsn": "postgres://u:p@h:5432/d"},
	}
	check, err := newPostgresQueriesCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	qcheck := check.(QueryStatsCheck)

	first, err := qcheck.RunQueryStats(context.Background())
	if err != nil {
		t.Fatalf("first RunQueryStats failed: %v", err)
	}
	if len(first.Queries) != 0 {
		t.Fatalf("first read must only establish baseline; got %d rows", len(first.Queries))
	}

	stub.rowsBySQLPrefix["FROM pg_stat_statements"] = &stubRow{vals: []any{`[{"query_id":"42","text":"SELECT * FROM accounts WHERE email = 'ana@example.com' AND id = 17","calls":13,"total_ms":145.0,"rows":26}]`}}
	second, err := qcheck.RunQueryStats(context.Background())
	if err != nil {
		t.Fatalf("second RunQueryStats failed: %v", err)
	}
	if len(second.Queries) != 1 {
		t.Fatalf("expected one delta row; got %d", len(second.Queries))
	}
	row := second.Queries[0]
	if row.Calls != 3 || row.TotalMS != 45 || row.Rows != 6 {
		t.Errorf("unexpected delta: %+v", row)
	}
	if row.MeanMS != 15 {
		t.Errorf("expected weighted mean 15; got %v", row.MeanMS)
	}
	if row.Text != "SELECT * FROM accounts WHERE email = ? AND id = ?" {
		t.Errorf("query text was not sanitized/normalized: %q", row.Text)
	}
	if second.DBServer != "db.internal" || second.DBName != "billing" || second.WindowSeconds != 60 {
		t.Errorf("unexpected payload identity: %+v", second)
	}
}

func TestPostgresQueries_IsRegistered(t *testing.T) {
	if _, ok := Default.Get("postgres.queries"); !ok {
		t.Fatal("postgres.queries must be registered in Default registry")
	}
}

func TestSanitizeQueryText_RedactsDollarQuotedLiterals(t *testing.T) {
	got := sanitizeQueryText("SELECT $$customer@example.test$$, $token$secret-42$token$")
	if got != "SELECT ?, ?" {
		t.Fatalf("dollar-quoted values must be redacted, got %q", got)
	}
}
