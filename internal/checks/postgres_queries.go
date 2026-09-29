// postgres_queries.go — coleta agregada de pg_stat_statements.
//
// O check não cria uma série por consulta no VictoriaMetrics. Ele guarda a
// leitura anterior dos contadores cumulativos do Postgres, calcula o delta da
// janela e entrega um lote ao endpoint próprio de query stats.
package checks

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/jackc/pgx/v5"
)

const (
	postgresQueryStatsLimit     = 200
	postgresQueryTextLimit      = 4096
	postgresQuerySampleLimit    = 50
	postgresContinuousPlanLimit = 5
	postgresPlanRateLimit       = 60
	postgresPlanSampleRateLimit = 15
	postgresPlanRateCacheSize   = 5000
)

// DatabaseQueryStat é uma linha de uma janela de coleta. Calls, TotalMS e
// Rows já são deltas; nunca são os contadores cumulativos crus do Postgres.
type DatabaseQueryStat struct {
	QueryID string
	Text    string
	Calls   int64
	TotalMS float64
	MeanMS  float64
	Rows    int64
}

type DatabaseQueryStats struct {
	Engine         string
	InstallationID string
	DatabaseID     string
	DBServer       string
	DBName         string
	WindowSeconds  int
	Queries        []DatabaseQueryStat
	Samples        []DatabaseQuerySample
}

// DatabaseQuerySample is a bounded, redacted observation from
// pg_stat_activity. Query literals never leave the monitored host. PlanJSON is
// optional and contains only the structural/cost fields allowlisted below.
type DatabaseQuerySample struct {
	SampleID    string          `json:"sample_id"`
	QueryID     string          `json:"query_id"`
	Text        string          `json:"text"`
	User        string          `json:"user"`
	Application string          `json:"application"`
	Client      string          `json:"client"`
	State       string          `json:"state"`
	WaitType    string          `json:"wait_type"`
	WaitEvent   string          `json:"wait_event"`
	DurationMS  float64         `json:"duration_ms"`
	SampledAt   string          `json:"sampled_at"`
	PlanJSON    json.RawMessage `json:"plan,omitempty"`
	PlanStatus  string          `json:"plan_status,omitempty"`
}

// QueryStatsCheck é implementado por checks que têm um canal agregado além de
// métricas nativas. O scheduler o detecta para não executar Run duas vezes.
type QueryStatsCheck interface {
	Check
	RunQueryStats(context.Context) (*DatabaseQueryStats, error)
}

// QuerySamplesCheck coleta amostras independentemente da janela agregada.
type QuerySamplesCheck interface {
	Check
	SampleInterval() time.Duration
	RunQuerySamples(context.Context) (*DatabaseQueryStats, error)
}

type postgresQueryStatRow struct {
	QueryID string  `json:"query_id"`
	Text    string  `json:"text"`
	Calls   int64   `json:"calls"`
	TotalMS float64 `json:"total_ms"`
	Rows    int64   `json:"rows"`
}

type postgresQueryCounter struct {
	calls   int64
	totalMS float64
	rows    int64
}

type postgresQuerySampleRow struct {
	SampleID    string  `json:"sample_id"`
	QueryID     string  `json:"query_id"`
	Query       string  `json:"query"`
	User        string  `json:"user"`
	Application string  `json:"application"`
	Client      string  `json:"client"`
	State       string  `json:"state"`
	WaitType    string  `json:"wait_type"`
	WaitEvent   string  `json:"wait_event"`
	DurationMS  float64 `json:"duration_ms"`
	SampledAt   string  `json:"sampled_at"`
}

type postgresQuerySnapshot struct {
	Queries []postgresQueryStatRow   `json:"queries"`
	Samples []postgresQuerySampleRow `json:"samples"`
}

type postgresRateWindow struct {
	start time.Time
	count int
}

type postgresQueries struct {
	id                          string
	interval                    time.Duration
	hostID                      string
	dbServer                    string
	dbName                      string
	installationID              string
	databaseID                  string
	staticTags                  map[string]string
	pool                        pgxPool
	querySQL                    string
	sampleSQL                   string
	sampleLimit                 int
	sampleInterval              time.Duration
	continuousPlans             bool
	continuousPlanLimit         int
	continuousPlanMinDurationMS float64

	mu          sync.Mutex
	previous    map[string]postgresQueryCounter
	planRuns    map[string]postgresRateWindow
	planSamples map[string]postgresRateWindow
}

func buildPostgresQuerySamplesSQL(capabilities postgresRelationCapabilities, sampleLimit int) string {
	return fmt.Sprintf(`WITH %s
SELECT json_build_object(
	'samples', COALESCE((SELECT json_agg(s ORDER BY s.duration_ms DESC) FROM query_samples s), '[]'::json)
)::text`, postgresQuerySamplesCTE(capabilities, sampleLimit))
}

func buildPostgresQueryStatsSQL(capabilities postgresRelationCapabilities) (string, error) {
	return buildPostgresQuerySnapshotSQL(capabilities, postgresRelationCapabilities{}, postgresQueryStatsLimit, postgresQuerySampleLimit)
}

func buildPostgresQuerySnapshotSQL(capabilities, activityCapabilities postgresRelationCapabilities, statsLimit, sampleLimit int) (string, error) {
	if !capabilities.available() {
		return "", fmt.Errorf("extensão pg_stat_statements não instalada ou indisponível")
	}
	for _, required := range []string{"dbid", "query", "calls"} {
		if !capabilities.hasColumn(required) {
			return "", fmt.Errorf("pg_stat_statements sem capacidade obrigatória %q", required)
		}
	}

	timeColumn := ""
	for _, candidate := range []string{"total_exec_time", "total_time"} {
		if capabilities.hasColumn(candidate) {
			timeColumn = candidate
			break
		}
	}
	if timeColumn == "" {
		return "", fmt.Errorf("pg_stat_statements não fornece contador de tempo total")
	}

	queryIDExpression := "md5(s.query::text)"
	if capabilities.hasColumn("queryid") {
		queryIDExpression = "s.queryid::text"
	}
	rowsExpression := "0::bigint"
	if capabilities.hasColumn("rows") {
		rowsExpression = "s.rows::bigint"
	}

	statsLimit = boundedInt(statsLimit, 1, postgresQueryStatsLimit, postgresQueryStatsLimit)
	sampleLimit = boundedInt(sampleLimit, 1, postgresQuerySampleLimit, postgresQuerySampleLimit)
	sampleCTE := postgresQuerySamplesCTE(activityCapabilities, sampleLimit)
	return fmt.Sprintf(`WITH query_stats AS (
    SELECT %s AS query_id,
           s.query AS text,
           s.calls::bigint AS calls,
           s.%s::float8 AS total_ms,
           %s AS rows
      FROM %s s
      JOIN pg_database d ON d.oid = s.dbid
     WHERE d.datname = current_database()
       AND s.calls > 0
     ORDER BY total_ms DESC
     LIMIT %d
	), %s
SELECT json_build_object(
	'queries', COALESCE((SELECT json_agg(q ORDER BY q.total_ms DESC) FROM query_stats q), '[]'::json),
	'samples', COALESCE((SELECT json_agg(s ORDER BY s.duration_ms DESC) FROM query_samples s), '[]'::json)
)::text`,
		queryIDExpression,
		timeColumn,
		rowsExpression,
		capabilities.qualifiedName,
		statsLimit,
		sampleCTE,
	), nil
}

func postgresQuerySamplesCTE(capabilities postgresRelationCapabilities, sampleLimit int) string {
	empty := `query_samples AS (
	SELECT ''::text AS sample_id, ''::text AS query_id, ''::text AS query,
	       ''::text AS "user", ''::text AS application, ''::text AS client,
	       ''::text AS state, ''::text AS wait_type, ''::text AS wait_event,
	       0::float8 AS duration_ms, clock_timestamp()::text AS sampled_at
	 WHERE false
)`
	if !capabilities.available() || !capabilities.hasColumn("datname") {
		return empty
	}
	queryColumn := firstPostgresColumn(capabilities, "query", "current_query")
	pidColumn := firstPostgresColumn(capabilities, "pid", "procpid")
	if queryColumn == "" || pidColumn == "" {
		return empty
	}
	expression := func(column, fallback string) string {
		if capabilities.hasColumn(column) {
			return fmt.Sprintf("COALESCE(a.%s::text, '')", column)
		}
		return fallback
	}
	stateFilter := ""
	if capabilities.hasColumn("state") {
		stateFilter = " AND COALESCE(a.state, '') <> 'idle'"
	} else if queryColumn == "current_query" {
		stateFilter = " AND a.current_query <> '<IDLE>'"
	}
	duration := "0::float8"
	order := ""
	if capabilities.hasColumn("query_start") {
		duration = "GREATEST(COALESCE(EXTRACT(EPOCH FROM clock_timestamp() - a.query_start) * 1000, 0), 0)::float8"
		order = " ORDER BY a.query_start NULLS LAST"
	}
	return fmt.Sprintf(`query_samples AS (
	SELECT md5(COALESCE(a.%[1]s::text, '') || ':' || a.%[2]s::text) AS sample_id,
	       md5(a.%[1]s::text) AS query_id,
	       a.%[1]s::text AS query,
	       %[3]s AS "user",
	       %[4]s AS application,
	       %[5]s AS client,
	       %[6]s AS state,
	       %[7]s AS wait_type,
	       %[8]s AS wait_event,
	       %[9]s AS duration_ms,
	       clock_timestamp()::text AS sampled_at
	  FROM %[10]s a
	 WHERE a.datname = current_database()
	   AND a.%[2]s <> pg_backend_pid()
	   AND a.%[1]s IS NOT NULL
	   AND a.%[1]s::text <> ''%[11]s%[12]s
	 LIMIT %[13]d
)`, queryColumn, pidColumn,
		expression("usename", "''::text"), expression("application_name", "''::text"),
		expression("client_addr", "''::text"), expression("state", "''::text"),
		expression("wait_event_type", "''::text"), expression("wait_event", "''::text"),
		duration, capabilities.qualifiedName, stateFilter, order,
		boundedInt(sampleLimit, 1, postgresQuerySampleLimit, postgresQuerySampleLimit))
}

func firstPostgresColumn(capabilities postgresRelationCapabilities, candidates ...string) string {
	for _, candidate := range candidates {
		if capabilities.hasColumn(candidate) {
			return candidate
		}
	}
	return ""
}

func newPostgresQueriesCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newPostgresQueriesCheckWithFactory(cfg, defaultPgxPoolFactory)
}

func newPostgresQueriesCheckWithFactory(cfg *collectorv1.CheckConfig, factory pgxPoolFactory) (Check, error) {
	params := cfg.GetParams()
	pool, err := openPostgresPool(cfg, factory, "postgres.queries")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 60 * time.Second
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}
	normalizeDatabaseMetricTags(params, tags)
	server := strings.TrimSpace(tags["db_server"])
	if server == "" {
		pool.Close()
		return nil, fmt.Errorf("postgres.queries: static_tags.db_server obrigatório")
	}
	database := strings.TrimSpace(tags["db_name"])
	installationID, databaseID := databaseIdentity(params, tags)
	capabilities, err := discoverPostgresExtensionRelationCapabilities(
		context.Background(),
		pool,
		"pg_stat_statements",
		"pg_stat_statements",
	)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres.queries: %w", err)
	}
	// Valida primeiro a extensão. Assim uma instalação sem
	// pg_stat_statements continua recebendo o erro correto, sem depender da
	// descoberta opcional de amostras em pg_stat_activity.
	if _, err := buildPostgresQuerySnapshotSQL(capabilities, postgresRelationCapabilities{}, 1, 1); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres.queries: %w", err)
	}
	activityCapabilities, err := discoverPostgresRelationCapabilities(
		context.Background(), pool, "pg_catalog", "pg_stat_activity",
	)
	if err != nil {
		// Amostras são adicionais. Uma falha de descoberta não pode desligar o
		// ranking agregado de pg_stat_statements que já foi negociado acima.
		log.Printf("postgres.queries: pg_stat_activity indisponível para amostras: %v", err)
		activityCapabilities = postgresRelationCapabilities{}
	}
	statsLimit := boundedParam(params, "query_limit", 1, postgresQueryStatsLimit, postgresQueryStatsLimit)
	sampleLimit := boundedParam(params, "sample_limit", 1, postgresQuerySampleLimit, 20)
	querySQL, err := buildPostgresQuerySnapshotSQL(capabilities, postgresRelationCapabilities{}, statsLimit, sampleLimit)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres.queries: %w", err)
	}
	var sampleInterval time.Duration
	if params["query_samples_interval_seconds"] != "" {
		sampleInterval = time.Duration(boundedParam(params, "query_samples_interval_seconds", 1, 60, 1)) * time.Second
	}
	if !activityCapabilities.available() || firstPostgresColumn(activityCapabilities, "query", "current_query") == "" {
		sampleInterval = 0
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "postgres.queries-" + cfg.GetHostId()
	}
	return &postgresQueries{
		id: id, interval: interval, hostID: cfg.GetHostId(), dbServer: server, dbName: database,
		installationID: installationID, databaseID: databaseID,
		staticTags: tags, pool: pool, querySQL: querySQL,
		sampleSQL:                   buildPostgresQuerySamplesSQL(activityCapabilities, sampleLimit),
		sampleLimit:                 sampleLimit,
		sampleInterval:              sampleInterval,
		continuousPlans:             boolParam(params, "continuous_plans_enabled", true),
		continuousPlanLimit:         boundedParam(params, "continuous_plan_limit", 1, postgresContinuousPlanLimit, 2),
		continuousPlanMinDurationMS: floatParam(params, "continuous_plan_min_duration_ms", 0, 300000, 0),
		previous:                    make(map[string]postgresQueryCounter),
		planRuns:                    make(map[string]postgresRateWindow),
		planSamples:                 make(map[string]postgresRateWindow),
	}, nil
}

func (c *postgresQueries) ID() string                    { return c.id }
func (c *postgresQueries) Interval() time.Duration       { return c.interval }
func (c *postgresQueries) Tags() map[string]string       { return c.staticTags }
func (c *postgresQueries) SampleInterval() time.Duration { return c.sampleInterval }

func (c *postgresQueries) Close() error {
	if c.pool != nil {
		c.pool.Close()
	}
	return nil
}

// Run mantém a interface Check para consumidores legados. O scheduler usa
// RunQueryStats diretamente e publica o lote no sinal db/query-stats.
func (c *postgresQueries) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunQueryStats(ctx)
	return nil, err
}

func (c *postgresQueries) RunQueryStats(ctx context.Context) (*DatabaseQueryStats, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()
	var body string
	if err := c.pool.QueryRow(qctx, c.querySQL).Scan(&body); err != nil {
		log.Printf("postgres.queries[%s]: query failed: %v", c.id, err)
		return nil, err
	}
	var snapshot postgresQuerySnapshot
	if err := json.Unmarshal([]byte(body), &snapshot); err != nil {
		return nil, fmt.Errorf("postgres.queries: resposta inválida: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	out := &DatabaseQueryStats{
		InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.dbServer, DBName: c.dbName, WindowSeconds: max(1, int(c.interval/time.Second)),
		Queries: make([]DatabaseQueryStat, 0, len(snapshot.Queries)),
		Samples: make([]DatabaseQuerySample, 0, len(snapshot.Samples)),
	}
	for _, row := range snapshot.Queries {
		if row.QueryID == "" || row.Calls <= 0 {
			continue
		}
		current := postgresQueryCounter{calls: row.Calls, totalMS: row.TotalMS, rows: row.Rows}
		previous, hadPrevious := c.previous[row.QueryID]
		c.previous[row.QueryID] = current
		if !hadPrevious {
			// A primeira leitura só firma a baseline; não inventa uma janela
			// histórica desde o último restart do Postgres.
			continue
		}
		calls := counterDelta(current.calls, previous.calls)
		totalMS := floatDelta(current.totalMS, previous.totalMS)
		readRows := counterDelta(current.rows, previous.rows)
		if calls <= 0 {
			continue
		}
		text := sanitizeQueryText(row.Text)
		if text == "" {
			text = "(consulta sem texto)"
		}
		out.Queries = append(out.Queries, DatabaseQueryStat{
			QueryID: row.QueryID, Text: text, Calls: calls, TotalMS: totalMS,
			MeanMS: totalMS / float64(calls), Rows: readRows,
		})
	}
	return out, nil
}

func (c *postgresQueries) RunQuerySamples(ctx context.Context) (*DatabaseQueryStats, error) {
	if c.sampleInterval <= 0 {
		return nil, nil
	}
	qctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()
	var body string
	if err := c.pool.QueryRow(qctx, c.sampleSQL).Scan(&body); err != nil {
		return nil, fmt.Errorf("postgres.queries: amostras indisponíveis: %w", err)
	}
	var snapshot postgresQuerySnapshot
	if err := json.Unmarshal([]byte(body), &snapshot); err != nil {
		return nil, fmt.Errorf("postgres.queries: amostras inválidas: %w", err)
	}
	out := &DatabaseQueryStats{
		InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.dbServer, DBName: c.dbName,
		WindowSeconds: max(1, int(c.sampleInterval/time.Second)),
		Samples:       make([]DatabaseQuerySample, 0, len(snapshot.Samples)),
	}
	plansCollected := 0
	seenQueries := make(map[string]struct{}, len(snapshot.Samples))
	for index, row := range snapshot.Samples {
		if len(out.Samples) >= c.sampleLimit {
			break
		}
		if strings.TrimSpace(row.Query) == "" {
			continue
		}
		sample := DatabaseQuerySample{
			SampleID: limitText(row.SampleID, 128), QueryID: row.QueryID,
			Text: sanitizeQueryText(row.Query), User: limitText(row.User, 128),
			Application: limitText(row.Application, 128), Client: limitText(row.Client, 128),
			State: limitText(row.State, 32), WaitType: limitText(row.WaitType, 64),
			WaitEvent: limitText(row.WaitEvent, 128), DurationMS: math.Max(row.DurationMS, 0),
			SampledAt: normalizedSampledAt(row.SampledAt),
		}
		if sample.SampleID == "" {
			sample.SampleID = fmt.Sprintf("%s:%d", sample.QueryID, index)
		}
		switch {
		case !c.continuousPlans:
			sample.PlanStatus = "disabled"
		case row.DurationMS < c.continuousPlanMinDurationMS:
			sample.PlanStatus = "below_threshold"
		case plansCollected >= c.continuousPlanLimit:
			sample.PlanStatus = "rate_limited"
		default:
			key := sample.Text
			if _, seen := seenQueries[key]; !seen {
				seenQueries[key] = struct{}{}
				if err := validateReadOnlyQuery(row.Query); err != nil {
					sample.PlanStatus = "ineligible"
				} else if !c.allowPlanRun(key, time.Now()) {
					sample.PlanStatus = "rate_limited"
				} else {
					plansCollected++
					sample.PlanJSON, sample.PlanStatus = c.explainSample(ctx, row.Query)
					if sample.PlanStatus == "ready" && !c.allowPlanSample(key, sample.PlanJSON, time.Now()) {
						sample.PlanJSON = nil
						sample.PlanStatus = "rate_limited"
					}
				}
			} else {
				sample.PlanStatus = "rate_limited"
			}
		}
		out.Samples = append(out.Samples, sample)
	}
	return out, nil
}

func (c *postgresQueries) allowPlanRun(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return allowPostgresRate(c.planRuns, key, postgresPlanRateLimit, now)
}

func (c *postgresQueries) allowPlanSample(query string, plan json.RawMessage, now time.Time) bool {
	key := fmt.Sprintf("%s:%x", query, sha256.Sum256(plan))
	c.mu.Lock()
	defer c.mu.Unlock()
	return allowPostgresRate(c.planSamples, key, postgresPlanSampleRateLimit, now)
}

func allowPostgresRate(windows map[string]postgresRateWindow, key string, limit int, now time.Time) bool {
	window, exists := windows[key]
	if !exists && len(windows) >= postgresPlanRateCacheSize {
		for candidate, value := range windows {
			if now.Sub(value.start) >= time.Hour {
				delete(windows, candidate)
			}
		}
		if len(windows) >= postgresPlanRateCacheSize {
			return false
		}
	}
	if !exists || now.Sub(window.start) >= time.Hour {
		window = postgresRateWindow{start: now}
	}
	if window.count >= limit {
		return false
	}
	window.count++
	windows[key] = window
	return true
}

func normalizedSampledAt(raw string) string {
	value, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func (c *postgresQueries) explainSample(ctx context.Context, query string) (json.RawMessage, string) {
	if err := validateReadOnlyQuery(query); err != nil {
		return nil, "ineligible"
	}
	if hasQueryParameters(query) {
		return c.explainParameterizedSample(ctx, query)
	}
	qctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()
	var raw string
	if err := c.pool.QueryRow(qctx, "EXPLAIN (FORMAT JSON) "+query).Scan(&raw); err != nil {
		return nil, "unavailable"
	}
	plan, err := sanitizeContinuousPlan([]byte(raw))
	if err != nil {
		return nil, "invalid"
	}
	return plan, "ready"
}

// PostgreSQL 12+ can produce a generic plan for a prepared statement without
// executing it. Older servers (or unresolved parameter types) report unavailable.
func (c *postgresQueries) explainParameterizedSample(ctx context.Context, query string) (json.RawMessage, string) {
	pool, ok := c.pool.(interface {
		BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	})
	if !ok {
		return nil, "unavailable"
	}
	qctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()
	tx, err := pool.BeginTx(qctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, "unavailable"
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), time.Second)
		defer rollbackCancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	if _, err := tx.Exec(qctx, "SET LOCAL plan_cache_mode = force_generic_plan"); err != nil {
		return nil, "unavailable"
	}
	name := fmt.Sprintf("telvyn_plan_%x", sha256.Sum256([]byte(query)))[:28]
	if _, err := tx.Exec(qctx, "PREPARE "+name+" AS "+query); err != nil {
		return nil, "unavailable"
	}
	var parameterCount int
	if err := tx.QueryRow(qctx, "SELECT cardinality(parameter_types) FROM pg_prepared_statements WHERE name=$1", name).Scan(&parameterCount); err != nil || parameterCount < 1 || parameterCount > 32 {
		return nil, "unavailable"
	}
	params := strings.TrimSuffix(strings.Repeat("NULL,", parameterCount), ",")
	var raw string
	if err := tx.QueryRow(qctx, "EXPLAIN (FORMAT JSON) EXECUTE "+name+"("+params+")").Scan(&raw); err != nil {
		return nil, "unavailable"
	}
	plan, err := sanitizeContinuousPlan([]byte(raw))
	if err != nil {
		return nil, "invalid"
	}
	return plan, "ready"
}

func hasQueryParameters(query string) bool {
	query = maskDollarQuotedStrings(query)
	query = queryComments.ReplaceAllString(query, " ")
	query = queryStrings.ReplaceAllString(query, " ")
	return queryParameters.MatchString(query)
}

var allowedPlanKeys = map[string]struct{}{
	"Plan": {}, "Plans": {}, "Node Type": {}, "Parent Relationship": {},
	"Parallel Aware": {}, "Async Capable": {}, "Join Type": {}, "Strategy": {},
	"Relation Name": {}, "Schema": {}, "Alias": {}, "Index Name": {},
	"Startup Cost": {}, "Total Cost": {}, "Plan Rows": {}, "Plan Width": {},
}

func sanitizeContinuousPlan(raw []byte) (json.RawMessage, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	var clean func(any) any
	clean = func(input any) any {
		switch typed := input.(type) {
		case []any:
			out := make([]any, 0, len(typed))
			for _, item := range typed {
				out = append(out, clean(item))
			}
			return out
		case map[string]any:
			out := make(map[string]any)
			for key, item := range typed {
				if _, ok := allowedPlanKeys[key]; ok {
					out[key] = clean(item)
				}
			}
			return out
		default:
			return typed
		}
	}
	return json.Marshal(clean(value))
}

func limitText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func counterDelta(current, previous int64) int64 {
	if current < previous {
		return current // contador reiniciou/foi resetado
	}
	return current - previous
}

func floatDelta(current, previous float64) float64 {
	if current < previous {
		return current
	}
	return current - previous
}

var (
	queryComments   = regexp.MustCompile(`(?s)/\*.*?\*/|--[^\r\n]*`)
	queryStrings    = regexp.MustCompile(`'(?:''|[^'])*'`)
	queryNumbers    = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	queryParameters = regexp.MustCompile(`\$[1-9][0-9]*\b`)
	querySpaces     = regexp.MustCompile(`\s+`)
)

// sanitizeQueryText conserva o formato útil para agrupar/ler a consulta sem
// enviar valores literais e comentários que podem conter dados do cliente.
func sanitizeQueryText(query string) string {
	query = maskDollarQuotedStrings(query)
	query = queryComments.ReplaceAllString(query, " ")
	query = queryStrings.ReplaceAllString(query, "?")
	query = queryNumbers.ReplaceAllString(query, "?")
	query = querySpaces.ReplaceAllString(strings.TrimSpace(query), " ")
	if len(query) > postgresQueryTextLimit {
		query = query[:postgresQueryTextLimit]
	}
	return query
}

// maskDollarQuotedStrings cobre literais PostgreSQL como $$segredo$$ e
// $tag$segredo$tag$. RE2 não oferece backreferences para casar o delimitador de
// abertura/fechamento, então fazemos a leitura curta aqui antes das regexes.
// Delimitador sem fechamento é mascarado até o fim por segurança.
func maskDollarQuotedStrings(query string) string {
	var out strings.Builder
	out.Grow(len(query))
	for index := 0; index < len(query); {
		if query[index] != '$' {
			out.WriteByte(query[index])
			index++
			continue
		}
		end := index + 1
		if end < len(query) && query[end] != '$' {
			if !isDollarTagStart(query[end]) {
				out.WriteByte(query[index])
				index++
				continue
			}
			end++
			for end < len(query) && query[end] != '$' && isDollarTagPart(query[end]) {
				end++
			}
		}
		if end >= len(query) || query[end] != '$' {
			out.WriteByte(query[index])
			index++
			continue
		}
		delimiter := query[index : end+1]
		closing := strings.Index(query[end+1:], delimiter)
		out.WriteByte('?')
		if closing < 0 {
			return out.String()
		}
		index = end + 1 + closing + len(delimiter)
	}
	return out.String()
}

func isDollarTagStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isDollarTagPart(value byte) bool {
	return isDollarTagStart(value) || value >= '0' && value <= '9'
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func init() {
	Default.Register("postgres.queries", newPostgresQueriesCheck)
}
