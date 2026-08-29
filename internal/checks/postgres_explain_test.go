package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestPostgresExplain_IsReadOnlyAndRunsOnce(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix = map[string]*stubRow{
		"EXPLAIN (FORMAT JSON, COSTS true, VERBOSE false, BUFFERS false) SELECT": {
			vals: []any{`[{"Plan":{"Node Type":"Index Scan","Index Name":"invoices_pkey"}}]`},
		},
	}
	cfg := &collectorv1.CheckConfig{
		CheckId: "explain-check-1", CheckType: "postgres.explain",
		Interval: durationpb.New(time.Minute), HostId: "host-1",
		StaticTags: map[string]string{"db_server": "db.internal", "db_name": "billing"},
		Params: map[string]string{
			"dsn": "postgres://u:p@h:5432/d", "request_id": "request-1",
			"query": "SELECT id FROM invoices WHERE id = 42",
		},
	}
	check, err := newPostgresExplainCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	first, err := check.(ExplainCheck).RunExplain(context.Background())
	if err != nil {
		t.Fatalf("RunExplain failed: %v", err)
	}
	if first == nil || first.RequestID != "request-1" || first.DBName != "billing" {
		t.Fatalf("unexpected plan: %+v", first)
	}
	check.(ExplainPublishAware).MarkExplainPublished()
	second, err := check.(ExplainCheck).RunExplain(context.Background())
	if err != nil || second != nil {
		t.Fatalf("expected one-shot behavior, got plan=%+v err=%v", second, err)
	}
	if len(stub.queries) != 1 || !strings.HasPrefix(stub.queries[0], "EXPLAIN (FORMAT JSON") {
		t.Fatalf("unexpected SQL calls: %v", stub.queries)
	}
	if strings.Contains(strings.ToUpper(stub.queries[0]), "ANALYZE") {
		t.Fatalf("EXPLAIN must not use ANALYZE: %q", stub.queries[0])
	}
	failure := check.(ExplainFailureProvider).ExplainFailure(fmt.Errorf("permission denied for relation invoices"))
	if failure.Error == "" || failure.PlanJSON != "" || failure.RequestID != "request-1" {
		t.Fatalf("unexpected failure payload: %+v", failure)
	}
}

func TestPostgresExplain_RejectsWriteQuery(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckId: "explain-check-2", CheckType: "postgres.explain", HostId: "host-1",
		Params: map[string]string{
			"dsn": "postgres://u:p@h:5432/d", "request_id": "request-2",
			"query": "UPDATE invoices SET paid = true",
		},
	}
	if _, err := newPostgresExplainCheckWithFactory(cfg, newStubPoolFactory(newStubPgxPool(), nil)); err == nil {
		t.Fatal("expected write query to be rejected")
	}
}

func TestPostgresExplain_RejectsSleepingQuery(t *testing.T) {
	cfg := &collectorv1.CheckConfig{
		CheckId: "explain-check-3", CheckType: "postgres.explain", HostId: "host-1",
		Params: map[string]string{
			"dsn": "postgres://u:p@h:5432/d", "request_id": "request-3",
			"query": "SELECT pg_sleep(60)",
		},
	}
	if _, err := newPostgresExplainCheckWithFactory(cfg, newStubPoolFactory(newStubPgxPool(), nil)); err == nil {
		t.Fatal("expected sleeping query to be rejected")
	}
}

func TestPostgresExplain_IsRegistered(t *testing.T) {
	if _, ok := Default.Get("postgres.explain"); !ok {
		t.Fatal("postgres.explain must be registered in Default registry")
	}
}
