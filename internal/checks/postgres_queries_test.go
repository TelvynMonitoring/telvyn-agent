package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func postgresQueryCapabilities(columns ...string) postgresRelationCapabilities {
	capabilities := postgresRelationCapabilities{
		qualifiedName: `"public"."pg_stat_statements"`,
		columns:       make(map[string]struct{}, len(columns)),
	}
	for _, column := range columns {
		capabilities.columns[column] = struct{}{}
	}
	return capabilities
}

func postgresActivityCapabilities(columns ...string) postgresRelationCapabilities {
	capabilities := postgresQueryCapabilities(columns...)
	capabilities.qualifiedName = `"pg_catalog"."pg_stat_activity"`
	return capabilities
}

func TestBuildPostgresQueryStatsSQLSelectsAvailableTimeCapability(t *testing.T) {
	tests := []struct {
		name       string
		columns    []string
		wantColumn string
	}{
		{
			name:       "execution time capability",
			columns:    []string{"dbid", "queryid", "query", "calls", "total_exec_time", "rows"},
			wantColumn: "s.total_exec_time::float8",
		},
		{
			name:       "legacy total time capability",
			columns:    []string{"dbid", "queryid", "query", "calls", "total_time", "rows"},
			wantColumn: "s.total_time::float8",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := buildPostgresQueryStatsSQL(postgresQueryCapabilities(tt.columns...))
			if err != nil {
				t.Fatalf("query build failed: %v", err)
			}
			if !strings.Contains(query, tt.wantColumn) {
				t.Fatalf("query does not use discovered capability %q: %s", tt.wantColumn, query)
			}
		})
	}
}

func TestBuildPostgresQueryStatsSQLUsesSafeFallbacks(t *testing.T) {
	query, err := buildPostgresQueryStatsSQL(postgresQueryCapabilities(
		"dbid", "query", "calls", "total_time",
	))
	if err != nil {
		t.Fatalf("query build failed: %v", err)
	}
	if !strings.Contains(query, "md5(s.query::text) AS query_id") {
		t.Fatalf("query must derive an identifier when queryid is unavailable: %s", query)
	}
	if !strings.Contains(query, "0::bigint AS rows") {
		t.Fatalf("query must keep collecting when rows is unavailable: %s", query)
	}
}

func TestBuildPostgresQueryStatsSQLRejectsMissingRequiredCapability(t *testing.T) {
	_, err := buildPostgresQueryStatsSQL(postgresQueryCapabilities("dbid", "query", "calls"))
	if err == nil {
		t.Fatal("expected missing time capability error")
	}
}

func TestPostgresQueriesFactoryRejectsUnavailableExtensionAndClosesPool(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix["WITH extension_relation"] = &stubRow{vals: []any{"", ""}}
	cfg := &collectorv1.CheckConfig{
		CheckType:  "postgres.queries",
		HostId:     "host-1",
		StaticTags: map[string]string{"db_server": "db.internal", "db_name": "billing"},
		Params:     map[string]string{"dsn": "postgres://u:p@h:5432/d"},
	}

	_, err := newPostgresQueriesCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err == nil || !strings.Contains(err.Error(), "pg_stat_statements") {
		t.Fatalf("expected clear unavailable extension error, got %v", err)
	}
	if !stub.closed {
		t.Fatal("pool must be closed when capability discovery rejects the check")
	}
}

func TestPostgresQueriesFactoryKeepsAggregatesWhenActivityDiscoveryFails(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix["WITH extension_relation"] = &stubRow{vals: []any{
		`"public"."pg_stat_statements"`,
		"dbid\x1fqueryid\x1fquery\x1fcalls\x1ftotal_exec_time\x1frows",
	}}
	cfg := &collectorv1.CheckConfig{
		CheckType:  "postgres.queries",
		HostId:     "host-1",
		StaticTags: map[string]string{"db_server": "db.internal", "db_name": "billing"},
		Params:     map[string]string{"dsn": "postgres://u:p@h:5432/d"},
	}

	check, err := newPostgresQueriesCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("activity samples are optional and must not disable aggregates: %v", err)
	}
	if check == nil || stub.closed {
		t.Fatal("aggregate query check must remain active")
	}
	if !check.(*postgresQueries).continuousPlans || check.(QuerySamplesCheck).SampleInterval() != 0 {
		t.Fatal("plans default to enabled, but unavailable activity must not start a fast sampling loop")
	}
}

func TestPostgresQueries_UsesDeltaAndSanitizesText(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix["WITH extension_relation"] = &stubRow{vals: []any{
		`"public"."pg_stat_statements"`,
		"userid\x1fdbid\x1fqueryid\x1fquery\x1fcalls\x1ftotal_exec_time\x1frows",
	}}
	stub.rowsBySQLPrefix["WITH relation AS"] = &stubRow{vals: []any{
		`"pg_catalog"."pg_stat_activity"`,
		"datname\x1fpid\x1fusename\x1fapplication_name\x1fclient_addr\x1fstate\x1fwait_event_type\x1fwait_event\x1fquery\x1fquery_start",
	}}
	stub.rowsBySQLPrefix[`WITH query_stats AS`] = &stubRow{vals: []any{`{"queries":[{"query_id":"42","text":"SELECT * FROM accounts WHERE email = 'ana@example.com' AND id = 17 -- secret","calls":10,"total_ms":100.0,"rows":20}],"samples":[]}`}}
	cfg := &collectorv1.CheckConfig{
		CheckId:    "pg-queries-1",
		CheckType:  "postgres.queries",
		Interval:   durationpb.New(60 * time.Second),
		HostId:     "host-1",
		StaticTags: map[string]string{"db_server": "db.internal", "db_name": "billing"},
		Params:     map[string]string{"dsn": "postgres://u:p@h:5432/d", "query_samples_interval_seconds": "1"},
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

	stub.rowsBySQLPrefix[`WITH query_stats AS`] = &stubRow{vals: []any{`{"queries":[{"query_id":"42","text":"SELECT * FROM accounts WHERE email = 'ana@example.com' AND id = 17","calls":13,"total_ms":145.0,"rows":26}],"samples":[]}`}}
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
	if len(second.Samples) != 0 {
		t.Fatalf("aggregate collection must not include fast samples: %+v", second.Samples)
	}
	stub.rowsBySQLPrefix[`WITH query_samples AS`] = &stubRow{vals: []any{`{"samples":[{"sample_id":"sample-1:10","query_id":"sample-1","query":"SELECT * FROM accounts WHERE email = 'ana@example.com'","user":"app","application":"api","client":"10.0.0.5","state":"active","wait_type":"","wait_event":"","duration_ms":120,"sampled_at":"2026-09-20T10:00:00Z"}]}`}}
	samples, err := check.(QuerySamplesCheck).RunQuerySamples(context.Background())
	if err != nil || len(samples.Samples) != 1 || samples.Samples[0].Text != "SELECT * FROM accounts WHERE email = ?" {
		t.Fatalf("expected one separate redacted query sample, got %+v, %v", samples, err)
	}
	if samples.Samples[0].SampleID != "sample-1:10" || samples.Samples[0].SampledAt != "2026-09-20T10:00:00Z" {
		t.Fatalf("sample identity/timestamp was not preserved: %+v", samples.Samples[0])
	}
}

func TestPostgresQuerySamplesAreIndependentAndPlansAreBounded(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix["WITH extension_relation"] = &stubRow{vals: []any{
		`"public"."pg_stat_statements"`, "dbid\x1fqueryid\x1fquery\x1fcalls\x1ftotal_exec_time",
	}}
	stub.rowsBySQLPrefix["WITH relation AS"] = &stubRow{vals: []any{
		`"pg_catalog"."pg_stat_activity"`, "datname\x1fpid\x1fquery\x1fquery_start",
	}}
	stub.rowsBySQLPrefix[`WITH query_samples AS`] = &stubRow{vals: []any{`{"samples":[
		{"sample_id":"1","query_id":"raw-1","query":"SELECT * FROM orders WHERE id = 1","duration_ms":5,"sampled_at":"2026-09-20T10:00:00Z"},
		{"sample_id":"2","query_id":"raw-2","query":"SELECT * FROM orders WHERE id = 2","duration_ms":6,"sampled_at":"2026-09-20T10:00:00Z"}]}`}}
	stub.rowsBySQLPrefix["EXPLAIN (FORMAT JSON)"] = &stubRow{vals: []any{`[{"Plan":{"Node Type":"Index Scan","Total Cost":2.1}}]`}}
	cfg := &collectorv1.CheckConfig{
		CheckId: "pg-queries", CheckType: "postgres.queries", HostId: "host-1",
		StaticTags: map[string]string{"db_server": "db.internal", "db_name": "billing"},
		Params:     map[string]string{"dsn": "postgres://u:p@h:5432/d", "continuous_plans_enabled": "true", "query_samples_interval_seconds": "1"},
	}
	check, err := newPostgresQueriesCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatal(err)
	}
	sampleCheck := check.(QuerySamplesCheck)
	if sampleCheck.SampleInterval() != time.Second {
		t.Fatalf("expected one-second sample cadence, got %s", sampleCheck.SampleInterval())
	}
	result, err := sampleCheck.RunQuerySamples(context.Background())
	if err != nil || len(result.Samples) != 2 {
		t.Fatalf("sample collection failed: %+v, %v", result, err)
	}
	if result.Samples[0].PlanStatus != "ready" || len(result.Samples[0].PlanJSON) == 0 {
		t.Fatalf("expected a structural plan: %+v", result.Samples[0])
	}
	if result.Samples[1].PlanStatus != "rate_limited" {
		t.Fatalf("same normalized query must be explained once per pass: %+v", result.Samples[1])
	}
	explainCount := 0
	for _, query := range stub.queries {
		if strings.HasPrefix(query, "EXPLAIN (FORMAT JSON)") {
			explainCount++
		}
		if strings.Contains(query, "EXPLAIN ANALYZE") {
			t.Fatal("continuous collection must never execute EXPLAIN ANALYZE")
		}
	}
	if explainCount != 1 {
		t.Fatalf("expected one explain for normalized query, got %d", explainCount)
	}
}

func TestPostgresQuerySamplesRequireExplicitInterval(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix["WITH extension_relation"] = &stubRow{vals: []any{
		`"public"."pg_stat_statements"`, "dbid\x1fqueryid\x1fquery\x1fcalls\x1ftotal_exec_time",
	}}
	stub.rowsBySQLPrefix["WITH relation AS"] = &stubRow{vals: []any{
		`"pg_catalog"."pg_stat_activity"`, "datname\x1fpid\x1fquery\x1fquery_start",
	}}
	cfg := &collectorv1.CheckConfig{
		CheckId: "legacy-queries", CheckType: "postgres.queries", HostId: "host-1",
		StaticTags: map[string]string{"db_server": "db.internal", "db_name": "billing"},
		Params:     map[string]string{"dsn": "postgres://u:p@h:5432/d"},
	}
	check, err := newPostgresQueriesCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := check.(QuerySamplesCheck).SampleInterval(); got != 0 {
		t.Fatalf("legacy check must not activate one-second sampling, got %s", got)
	}
}

func TestPostgresPlanRateLimitsPerNormalizedQueryAndPlan(t *testing.T) {
	check := &postgresQueries{planRuns: make(map[string]postgresRateWindow), planSamples: make(map[string]postgresRateWindow)}
	now := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	for i := 0; i < postgresPlanRateLimit; i++ {
		if !check.allowPlanRun("SELECT * FROM orders WHERE id = ?", now) {
			t.Fatalf("plan attempt %d was rejected prematurely", i)
		}
	}
	if check.allowPlanRun("SELECT * FROM orders WHERE id = ?", now) {
		t.Fatal("same normalized query exceeded hourly plan limit")
	}
	if !check.allowPlanRun("SELECT * FROM customers WHERE id = ?", now) {
		t.Fatal("another normalized query must have its own limit")
	}
	plan := []byte(`[{"Plan":{"Node Type":"Index Scan"}}]`)
	for i := 0; i < postgresPlanSampleRateLimit; i++ {
		if !check.allowPlanSample("orders", plan, now) {
			t.Fatalf("plan sample %d was rejected prematurely", i)
		}
	}
	if check.allowPlanSample("orders", plan, now) {
		t.Fatal("same normalized plan exceeded hourly event limit")
	}
	if !check.allowPlanRun("SELECT * FROM orders WHERE id = ?", now.Add(time.Hour)) ||
		!check.allowPlanSample("orders", plan, now.Add(time.Hour)) {
		t.Fatal("hourly limits must reset")
	}
}

func TestPostgresQueryParametersIgnoreQuotedLiterals(t *testing.T) {
	if !hasQueryParameters("SELECT * FROM orders WHERE id = $1") {
		t.Fatal("prepared statement parameter was not detected")
	}
	for _, query := range []string{"SELECT '$1'", "SELECT $$ $2 $$", "SELECT $tag$ $3 $tag$"} {
		if hasQueryParameters(query) {
			t.Fatalf("literal was mistaken for a parameter: %s", query)
		}
	}
}

func TestPostgresQuerySamplesCTENegotiatesLegacyActivityColumns(t *testing.T) {
	query := postgresQuerySamplesCTE(postgresActivityCapabilities(
		"datname", "procpid", "usename", "current_query", "query_start",
	), 10)
	if !strings.Contains(query, "a.current_query") || !strings.Contains(query, "a.procpid") {
		t.Fatalf("legacy activity columns were not negotiated: %s", query)
	}
	if strings.Contains(query, "a.wait_event") || strings.Contains(query, "a.application_name") {
		t.Fatalf("query referenced optional columns unavailable on the server: %s", query)
	}
}

func TestSanitizeContinuousPlanKeepsStructureAndDropsExpressions(t *testing.T) {
	plan, err := sanitizeContinuousPlan([]byte(`[{"Plan":{"Node Type":"Index Scan","Relation Name":"orders","Index Name":"orders_pkey","Filter":"(email = 'secret@example.com')","Total Cost":8.2}}]`))
	if err != nil {
		t.Fatalf("sanitize plan: %v", err)
	}
	got := string(plan)
	if strings.Contains(got, "secret") || strings.Contains(got, "Filter") {
		t.Fatalf("plan leaked expressions: %s", got)
	}
	if !strings.Contains(got, "Index Scan") || !strings.Contains(got, "orders_pkey") {
		t.Fatalf("plan lost structural fields: %s", got)
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
