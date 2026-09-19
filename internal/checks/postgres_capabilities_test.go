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

func TestDiscoverPostgresRelationCapabilitiesUsesNativeCatalog(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix["WITH relation AS"] = &stubRow{vals: []any{
		`"pg_catalog"."pg_stat_replication"`,
		"pid\x1fapplication_name\x1fsent_lsn\x1freplay_lsn",
	}}

	capabilities, err := discoverPostgresRelationCapabilities(
		context.Background(), stub, "pg_catalog", "pg_stat_replication",
	)
	if err != nil {
		t.Fatalf("native capability discovery failed: %v", err)
	}
	if !capabilities.hasColumn("sent_lsn") || !capabilities.hasColumn("replay_lsn") {
		t.Fatalf("unexpected native capabilities: %+v", capabilities.columns)
	}
}

func TestDiscoverPostgresWALFunctionsNegotiatesModernAndLegacyNames(t *testing.T) {
	for _, tt := range []struct {
		name, difference, current string
	}{
		{"modern", "pg_wal_lsn_diff", "pg_current_wal_lsn"},
		{"legacy", "pg_xlog_location_diff", "pg_current_xlog_location"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stub := newStubPgxPool()
			stub.rowsBySQLPrefix[sqlPostgresWALFunctions] = &stubRow{vals: []any{tt.difference, tt.current}}
			functions, err := discoverPostgresWALFunctions(context.Background(), stub)
			if err != nil {
				t.Fatalf("WAL capability discovery failed: %v", err)
			}
			if functions.difference != tt.difference || functions.current != tt.current {
				t.Fatalf("unexpected WAL functions: %+v", functions)
			}
		})
	}
}
