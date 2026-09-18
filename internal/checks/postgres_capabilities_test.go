package checks

import (
	"context"
	"errors"
	"testing"
)

func TestDiscoverPostgresExtensionRelationCapabilities(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix["WITH extension_relation"] = &stubRow{vals: []any{
		`"observability"."pg_stat_statements"`,
		"userid\x1fdbid\x1fqueryid\x1fquery\x1fcalls\x1ftotal_time\x1frows",
	}}

	capabilities, err := discoverPostgresExtensionRelationCapabilities(
		context.Background(),
		stub,
		"pg_stat_statements",
		"pg_stat_statements",
	)
	if err != nil {
		t.Fatalf("capability discovery failed: %v", err)
	}
	if capabilities.qualifiedName != `"observability"."pg_stat_statements"` {
		t.Fatalf("unexpected qualified name: %q", capabilities.qualifiedName)
	}
	for _, column := range []string{"dbid", "queryid", "query", "calls", "total_time", "rows"} {
		if !capabilities.hasColumn(column) {
			t.Errorf("expected discovered column %q", column)
		}
	}
}

func TestDiscoverPostgresExtensionRelationCapabilitiesReportsCatalogFailure(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix["WITH extension_relation"] = &stubRow{err: errors.New("permission denied")}

	_, err := discoverPostgresExtensionRelationCapabilities(
		context.Background(),
		stub,
		"pg_stat_statements",
		"pg_stat_statements",
	)
	if err == nil {
		t.Fatal("expected capability discovery error")
	}
}
