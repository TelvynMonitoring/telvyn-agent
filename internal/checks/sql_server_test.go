package checks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func TestSanitizedMSSQLPlanExcludesQueryValues(t *testing.T) {
	raw := `<ShowPlanXML><StmtSimple StatementText="SELECT * FROM customer WHERE email='secret@example.com'">` +
		`<QueryPlan><RelOp PhysicalOp="Index Seek" LogicalOp="Index Seek" EstimateRows="2" ` +
		`EstimatedTotalSubtreeCost="0.5"><ParameterList ParameterCompiledValue="secret@example.com"/>` +
		`</RelOp></QueryPlan></StmtSimple></ShowPlanXML>`
	plan, err := sanitizedMSSQLPlan(raw)
	if err != nil || strings.Contains(string(plan), "secret@example.com") {
		t.Fatalf("plano vazou valores: %s, %v", plan, err)
	}
	var parsed map[string][]map[string]any
	if err := json.Unmarshal(plan, &parsed); err != nil || len(parsed["Plan"]) != 1 || parsed["Plan"][0]["Node Type"] != "Index Seek" {
		t.Fatalf("estrutura do plano ausente: %s, %v", plan, err)
	}
}

type stubSQLRow struct {
	values []any
	err    error
}

func (r *stubSQLRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("stubSQLRow: dest count mismatch")
	}
	for index, target := range dest {
		value := r.values[index]
		switch typed := target.(type) {
		case *int64:
			v, ok := value.(int64)
			if !ok {
				return errors.New("stubSQLRow: expected int64")
			}
			*typed = v
		case *sql.NullFloat64:
			if value == nil {
				typed.Valid = false
				continue
			}
			v, ok := value.(float64)
			if !ok {
				return errors.New("stubSQLRow: expected float64")
			}
			typed.Float64, typed.Valid = v, true
		case *string:
			v, ok := value.(string)
			if !ok {
				return errors.New("stubSQLRow: expected string")
			}
			*typed = v
		default:
			return errors.New("stubSQLRow: unsupported destination")
		}
	}
	return nil
}

type stubSQLPool struct {
	pingErr          error
	rowsBySQLSnippet map[string]*stubSQLRow
	defaultRow       *stubSQLRow
	closed           bool
}

func (p *stubSQLPool) Ping(context.Context) error { return p.pingErr }

func (p *stubSQLPool) QueryRow(_ context.Context, query string, _ ...any) sqlDatabaseRow {
	for snippet, row := range p.rowsBySQLSnippet {
		if strings.Contains(query, snippet) {
			return row
		}
	}
	if p.defaultRow != nil {
		return p.defaultRow
	}
	return &stubSQLRow{err: errors.New("stubSQLPool: no row for query")}
}

func (p *stubSQLPool) Query(context.Context, string, ...any) (sqlDatabaseRows, error) {
	return nil, errors.New("stubSQLPool: no rows for query")
}

func (p *stubSQLPool) Close() error {
	p.closed = true
	return nil
}

func stubSQLPoolFactory(pool sqlDatabasePool, err error) sqlDatabasePoolFactory {
	return func(context.Context, string) (sqlDatabasePool, error) {
		if err != nil {
			return nil, err
		}
		return pool, nil
	}
}

func TestMySQLServer_EmitsCommonDatabaseMetrics(t *testing.T) {
	pool := &stubSQLPool{rowsBySQLSnippet: map[string]*stubSQLRow{
		"Threads_running":                        {values: []any{"Threads_running", "3"}},
		"Threads_connected":                      {values: []any{"Threads_connected", "9"}},
		"@@GLOBAL.max_connections":               {values: []any{int64(200)}},
		"Innodb_buffer_pool_reads'":              {values: []any{"Innodb_buffer_pool_reads", "3"}},
		"Innodb_buffer_pool_read_requests'":      {values: []any{"Innodb_buffer_pool_read_requests", "1000"}},
		"information_schema.processlist":         {values: []any{int64(2)}},
		"SHOW GLOBAL STATUS LIKE 'Com_commit'":   {values: []any{"Com_commit", "71"}},
		"SHOW GLOBAL STATUS LIKE 'Com_rollback'": {values: []any{"Com_rollback", "4"}},
		"performance_schema.data_lock_waits":     {values: []any{int64(1)}},
		"information_schema.tables":              {values: []any{int64(1024)}},
		"replication_applier_status_by_worker":   {values: []any{nil}},
	}}
	cfg := &collectorv1.CheckConfig{
		CheckType: "mysql.server", CheckId: "mysql-1", HostId: "host-1",
		Interval: durationpb.New(time.Minute), Params: map[string]string{"dsn": "u:p@tcp(db:3306)/app"},
		StaticTags: map[string]string{"db_server": "mysql.internal", "db_name": "app"},
	}
	check, err := newMySQLServerCheckWithFactory(cfg, stubSQLPoolFactory(pool, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	metrics, err := check.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	want := map[string]bool{
		"mysql.active_connections": false, "mysql.total_connections": false,
		"mysql.cache_hit_ratio": false, "mysql.database_size_bytes": false,
		"mysql.commits": false, "mysql.rollbacks": false,
	}
	for _, metric := range metrics {
		if _, ok := want[metric.MetricName]; ok {
			want[metric.MetricName] = true
		}
		if metric.Tags["db_engine"] != "mysql" || metric.Source != "mysql.server" {
			t.Fatalf("metric must preserve mysql identity: %+v", metric)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("metric %q was not emitted", name)
		}
	}
	for _, metric := range metrics {
		if metric.MetricName == "mysql.replication_lag_seconds" {
			t.Fatal("NULL replication state must not be reported as lag zero")
		}
	}
	pool.rowsBySQLSnippet["Innodb_buffer_pool_reads'"] = &stubSQLRow{values: []any{"Innodb_buffer_pool_reads", "1001"}}
	metrics, err = check.Run(context.Background())
	if err != nil {
		t.Fatalf("Run with inconsistent cache counters failed: %v", err)
	}
	for _, metric := range metrics {
		if metric.MetricName == "mysql.cache_hit_ratio" {
			t.Fatal("inconsistent cache counters must not produce a negative hit ratio")
		}
	}
}

func TestMySQLServer_UsesMariaDBLockView(t *testing.T) {
	pool := &stubSQLPool{rowsBySQLSnippet: map[string]*stubSQLRow{
		"SELECT VERSION()":                     {values: []any{"11.8.3-MariaDB"}},
		"information_schema.INNODB_LOCK_WAITS": {values: []any{int64(2)}},
	}}
	cfg := &collectorv1.CheckConfig{
		CheckType: "mysql.server", Params: map[string]string{"dsn": "u:p@tcp(db:3306)/app"},
	}
	check, err := newMySQLServerCheckWithFactory(cfg, stubSQLPoolFactory(pool, nil))
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := check.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, metric := range metrics {
		if metric.MetricName == "mysql.locks_waiting" && metric.Value == 2 {
			return
		}
	}
	t.Fatal("MariaDB lock wait metric missing")
}

func TestMSSQLServer_EmitsNativeRateWithoutCounterMasquerade(t *testing.T) {
	pool := &stubSQLPool{rowsBySQLSnippet: map[string]*stubSQLRow{
		"sys.dm_exec_requests":                {values: []any{int64(4)}},
		"sys.dm_exec_sessions":                {values: []any{int64(12)}},
		"@@MAX_CONNECTIONS":                   {values: []any{int64(32767)}},
		"Buffer cache hit ratio":              {values: []any{float64(0.996)}},
		"total_elapsed_time":                  {values: []any{int64(1)}},
		"Batch Requests/sec":                  {values: []any{float64(37)}},
		"sys.dm_os_waiting_tasks":             {values: []any{int64(2)}},
		"sys.database_files":                  {values: []any{int64(4096)}},
		"sys.dm_hadr_database_replica_states": {values: []any{nil}},
	}}
	cfg := &collectorv1.CheckConfig{
		CheckType: "mssql.server", CheckId: "mssql-1", HostId: "host-1",
		Interval: durationpb.New(time.Minute), Params: map[string]string{"dsn": "sqlserver://u:p@db:1433?databaseName=app"},
		StaticTags: map[string]string{"db_server": "sql.internal", "db_name": "app"},
	}
	check, err := newMSSQLServerCheckWithFactory(cfg, stubSQLPoolFactory(pool, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	metrics, err := check.Run(context.Background())
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	gotRate := false
	for _, metric := range metrics {
		if metric.Tags["db_engine"] != "mssql" || metric.Source != "mssql.server" {
			t.Fatalf("metric must preserve mssql identity: %+v", metric)
		}
		if metric.MetricName == "mssql.batch_requests_per_second" && metric.Value == 37 {
			gotRate = true
		}
		if metric.MetricName == "mssql.commits" || metric.MetricName == "mssql.rollbacks" {
			t.Fatalf("SQL Server native rate must not be exposed as a cumulative counter: %q", metric.MetricName)
		}
	}
	if !gotRate {
		t.Fatal("expected mssql.batch_requests_per_second")
	}
}

func TestSQLDatabaseChecks_ClosePoolAndRejectMissingDSN(t *testing.T) {
	pool := &stubSQLPool{}
	for _, item := range []struct {
		name    string
		factory func(*collectorv1.CheckConfig, sqlDatabasePoolFactory) (Check, error)
	}{
		{name: "mysql", factory: newMySQLServerCheckWithFactory},
		{name: "mssql", factory: newMSSQLServerCheckWithFactory},
	} {
		t.Run(item.name, func(t *testing.T) {
			_, err := item.factory(&collectorv1.CheckConfig{CheckType: item.name + ".server"}, stubSQLPoolFactory(pool, nil))
			if err == nil || !strings.Contains(err.Error(), "dsn") {
				t.Fatalf("expected missing dsn error, got %v", err)
			}
			cfg := &collectorv1.CheckConfig{CheckType: item.name + ".server", HostId: "host", Params: map[string]string{"dsn": "test"}}
			check, err := item.factory(cfg, stubSQLPoolFactory(pool, nil))
			if err != nil {
				t.Fatalf("factory failed: %v", err)
			}
			if err := check.(interface{ Close() error }).Close(); err != nil || !pool.closed {
				t.Fatalf("pool must close cleanly: err=%v closed=%v", err, pool.closed)
			}
		})
	}
}

func TestDatabaseServerChecks_Registered(t *testing.T) {
	for _, kind := range []string{"mysql.server", "mssql.server"} {
		if _, ok := Default.Get(kind); !ok {
			t.Fatalf("%s must be registered", kind)
		}
	}
}
