package checks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestPostgresDiagnostics_CollectsPrivacySafeOperationalSnapshot(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix = map[string]*stubRow{
		"pid <> pg_backend_pid()":     {vals: []any{`[{"pid":12,"user":"app","application":"api","client":"10.0.0.5","state":"active","wait_type":"Lock","wait_event":"transactionid","query_start":"2026-09-16T10:00:00Z","duration_seconds":3.5,"query":"SELECT * FROM invoices WHERE email = 'customer@example.test'"}]`}},
		"pg_blocking_pids":            {vals: []any{`[{"blocked_pid":12,"blocking_pid":9,"blocked_user":"app","blocking_user":"worker","blocked_query":"UPDATE invoices SET state = 'paid' WHERE id = 42","blocking_query":"SELECT * FROM invoices WHERE id = 42"}]`}},
		"wait_event_type IS NOT NULL": {vals: []any{`[{"wait_type":"Lock","wait_event":"transactionid","count":2}]`}},
	}
	cfg := &collectorv1.CheckConfig{
		CheckType: "postgres.diagnostics", CheckId: "pg-diagnostics-1", HostId: "host-1",
		Interval: durationpb.New(15 * time.Second), Params: map[string]string{"dsn": "postgres://u:p@h:5432/app", "bloat_enabled": "false"},
		StaticTags: map[string]string{"db_server": "postgres.internal", "db_name": "app"},
	}
	check, err := newPostgresDiagnosticsCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	snapshot, err := check.(DiagnosticsCheck).RunDiagnostics(context.Background())
	if err != nil {
		t.Fatalf("RunDiagnostics failed: %v", err)
	}
	if snapshot.DBServer != "postgres.internal" || snapshot.DBName != "app" || snapshot.BloatEnabled {
		t.Fatalf("unexpected identity: %+v", snapshot)
	}
	if snapshot.Capabilities["sessions"] != "available" || snapshot.Capabilities["blocking"] != "available" || snapshot.Capabilities["waits"] != "available" || snapshot.Capabilities["bloat"] != "disabled" {
		t.Fatalf("unexpected capabilities: %+v", snapshot.Capabilities)
	}
	if len(snapshot.Sessions) != 1 || len(snapshot.Blocking) != 1 {
		t.Fatalf("unexpected session/blocking snapshot: sessions=%+v blocking=%+v", snapshot.Sessions, snapshot.Blocking)
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if strings.Contains(string(payload), "customer@example.test") || strings.Contains(string(payload), "state = 'paid'") || strings.Contains(string(payload), `"query"`) {
		t.Fatalf("diagnostics must not transport SQL text: %s", payload)
	}
	if len(snapshot.Waits) != 1 || snapshot.Waits[0].Count != 2 {
		t.Fatalf("unexpected waits: %+v", snapshot.Waits)
	}
}

func TestPostgresDiagnostics_BloatIsExplicitAndBestEffort(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix = map[string]*stubRow{
		"pid <> pg_backend_pid()":     {vals: []any{"[]"}},
		"pg_blocking_pids":            {vals: []any{"[]"}},
		"wait_event_type IS NOT NULL": {vals: []any{"[]"}},
		"pgstattuple_approx":          {vals: []any{`[{"schema_name":"public","table_name":"events","total_size_bytes":1000,"dead_bytes":200,"dead_percent":20.0,"free_bytes":100,"free_percent":10.0}]`}},
	}
	cfg := &collectorv1.CheckConfig{
		CheckType: "postgres.diagnostics", HostId: "host-1",
		Params:     map[string]string{"dsn": "postgres://u:p@h:5432/app", "bloat_enabled": "true"},
		StaticTags: map[string]string{"db_server": "postgres.internal", "db_name": "app"},
	}
	check, err := newPostgresDiagnosticsCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	snapshot, err := check.(DiagnosticsCheck).RunDiagnostics(context.Background())
	if err != nil {
		t.Fatalf("RunDiagnostics failed: %v", err)
	}
	if !snapshot.BloatEnabled || snapshot.Capabilities["bloat"] != "available" || len(snapshot.Bloat) != 1 || snapshot.Bloat[0].DeadPercent != 20 {
		t.Fatalf("unexpected bloat snapshot: %+v", snapshot)
	}
}

func TestPostgresDiagnostics_RequiresDatabaseIdentity(t *testing.T) {
	stub := newStubPgxPool()
	cfg := &collectorv1.CheckConfig{CheckType: "postgres.diagnostics", HostId: "host-1", Params: map[string]string{"dsn": "postgres://u:p@h:5432/app"}}
	_, err := newPostgresDiagnosticsCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err == nil || !strings.Contains(err.Error(), "db_server") || !stub.closed {
		t.Fatalf("expected identity validation after closing pool, err=%v closed=%v", err, stub.closed)
	}
}

func TestPostgresDiagnostics_Registered(t *testing.T) {
	if _, ok := Default.Get("postgres.diagnostics"); !ok {
		t.Fatal("postgres.diagnostics must be registered")
	}
}

func TestPostgresDiagnosticsQueriesFollowDiscoveredCapabilities(t *testing.T) {
	modern := postgresRelationCapabilities{
		qualifiedName: `"pg_catalog"."pg_replication_slots"`,
		columns: map[string]struct{}{
			"slot_name": {}, "restart_lsn": {}, "confirmed_flush_lsn": {},
		},
	}
	slots := postgresReplicationSlotsQuery(modern, postgresWALFunctions{
		difference: "pg_wal_lsn_diff", current: "pg_current_wal_lsn",
	})
	for _, expected := range []string{"pg_catalog.pg_wal_lsn_diff", "pg_catalog.pg_current_wal_lsn", "retained_bytes"} {
		if !strings.Contains(slots, expected) {
			t.Fatalf("slot query must use discovered capability %q: %s", expected, slots)
		}
	}

	legacy := postgresReplicationSlotsQuery(modern, postgresWALFunctions{
		difference: "pg_xlog_location_diff", current: "pg_current_xlog_location",
	})
	if !strings.Contains(legacy, "pg_catalog.pg_xlog_location_diff") || !strings.Contains(legacy, "pg_catalog.pg_current_xlog_location") {
		t.Fatalf("slot query must support legacy WAL functions: %s", legacy)
	}
	for _, tc := range []struct {
		name      string
		functions postgresWALFunctions
		want      []string
	}{
		{
			name:      "modern",
			functions: postgresWALFunctions{difference: "pg_wal_lsn_diff", current: "pg_current_wal_lsn"},
			want:      []string{"pg_catalog.pg_wal_lsn_diff", "pg_catalog.pg_current_wal_lsn", "'0/0'"},
		},
		{
			name:      "legacy",
			functions: postgresWALFunctions{difference: "pg_xlog_location_diff", current: "pg_current_xlog_location"},
			want:      []string{"pg_catalog.pg_xlog_location_diff", "pg_catalog.pg_current_xlog_location", "'0/0'"},
		},
	} {
		t.Run("wal_position_"+tc.name, func(t *testing.T) {
			query := postgresWALPositionQuery(tc.functions)
			for _, expected := range tc.want {
				if !strings.Contains(query, expected) {
					t.Fatalf("WAL position query must contain %q: %s", expected, query)
				}
			}
		})
	}

	progress := postgresProgressQuery(postgresRelationCapabilities{
		qualifiedName: `"pg_catalog"."pg_stat_progress_create_index"`,
		columns:       map[string]struct{}{"command": {}, "blocks_done": {}, "blocks_total": {}, "phase": {}},
	}, "create_index")
	if !strings.Contains(progress, "replace(COALESCE(r.command") {
		t.Fatalf("progress query must distinguish CREATE INDEX from REINDEX: %s", progress)
	}
}

func TestMergeDatabaseWALPreservesMetricsAndAddsArchiver(t *testing.T) {
	metrics := &DatabaseWAL{
		Records: 42, Bytes: 4096, GeneratedBytes: 512, BytesPerSecond: 8,
		SampleSeconds: 64, StatsReset: "wal-reset",
	}
	archiver := &DatabaseWAL{
		ArchivedCount: 9, FailedCount: 1, LastArchivedWAL: "000000010000000000000001",
		LastArchivedTime: "2026-09-19T10:00:00Z", LastFailedWAL: "000000010000000000000002",
		LastFailedTime: "2026-09-19T10:01:00Z", StatsReset: "archiver-reset",
	}

	got := mergeDatabaseWAL(metrics, archiver)
	if got.Bytes != 4096 || got.GeneratedBytes != 512 || got.BytesPerSecond != 8 || got.Records != 42 {
		t.Fatalf("WAL metrics were overwritten by archiver data: %+v", got)
	}
	if got.ArchivedCount != 9 || got.FailedCount != 1 || got.LastArchivedWAL != archiver.LastArchivedWAL {
		t.Fatalf("archiver data was not merged: %+v", got)
	}
	if got.StatsReset != "wal-reset" {
		t.Fatalf("WAL stats reset must win when both sources report it: %+v", got)
	}
}
