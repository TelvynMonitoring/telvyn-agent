package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// O resumo por digest não guarda o usuário: as consultas de monitoramento saem do ranking pelo formato que só o
// agente usa (dicionários do servidor, SHOW, USE, variáveis e versão). Consultas da aplicação a esses
// dicionários também ficam de fora — são introspecção, não carga.
const sqlMySQLQueryDigests = `SELECT DIGEST, DIGEST_TEXT, COUNT_STAR, SUM_TIMER_WAIT, SUM_ROWS_SENT
FROM performance_schema.events_statements_summary_by_digest
WHERE SCHEMA_NAME = DATABASE() AND DIGEST IS NOT NULL AND COUNT_STAR > 0
AND DIGEST_TEXT NOT LIKE '%%performance_schema%%' AND DIGEST_TEXT NOT LIKE '%%information_schema%%'
AND DIGEST_TEXT NOT LIKE 'SHOW %%' AND DIGEST_TEXT NOT LIKE 'USE %%' AND DIGEST_TEXT NOT LIKE 'SELECT @@%%'
AND DIGEST_TEXT NOT LIKE 'SELECT _VERSION_ ( )%%' AND DIGEST_TEXT NOT LIKE 'SELECT VERSION ( )%%'
ORDER BY SUM_TIMER_WAIT DESC LIMIT %d`

// events_statements_current muda enquanto é lido: uma linha que passou por DIGEST IS NOT NULL pode chegar com o
// DIGEST já nulo (a instrução terminou no meio da leitura). Lido com COALESCE e descartado no laço, em vez de
// derrubar o lote inteiro de amostras com erro de Scan.
const sqlMySQLQuerySamples = `SELECT e.THREAD_ID, e.EVENT_ID, COALESCE(e.DIGEST,''), COALESCE(e.DIGEST_TEXT,''), COALESCE(e.SQL_TEXT,''),
	COALESCE(t.PROCESSLIST_USER,''), COALESCE(t.PROCESSLIST_HOST,''),
	COALESCE(t.PROCESSLIST_STATE,''), COALESCE(e.TIMER_WAIT,0)
FROM performance_schema.events_statements_current e
JOIN performance_schema.threads t ON t.THREAD_ID=e.THREAD_ID
WHERE e.CURRENT_SCHEMA=DATABASE() AND e.DIGEST IS NOT NULL AND e.END_EVENT_ID IS NULL
AND t.PROCESSLIST_ID <> CONNECTION_ID()
AND COALESCE(t.PROCESSLIST_USER,'') <> SUBSTRING_INDEX(CURRENT_USER(),'@',1)
ORDER BY e.TIMER_WAIT DESC LIMIT %d`

type mysqlQueries struct {
	id                      string
	interval                time.Duration
	sampleInterval          time.Duration
	installationID          string
	databaseID              string
	server                  string
	database                string
	tags                    map[string]string
	pool                    sqlDatabasePool
	mu                      sync.Mutex
	previous                map[string]postgresQueryCounter
	queryLimit, sampleLimit int
	continuousPlans         bool
	planLimit               int
	minPlanDurationMS       float64
	planRuns                map[string]time.Time
}

func newMySQLQueriesCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newMySQLQueriesCheckWithFactory(cfg, defaultMySQLPoolFactory)
}

func newMySQLQueriesCheckWithFactory(cfg *collectorv1.CheckConfig, factory sqlDatabasePoolFactory) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" {
		return nil, fmt.Errorf("mysql.queries: installation_id e database_id obrigatórios")
	}
	pool, err := openSQLDatabasePool(cfg, factory, "mysql.queries")
	if err != nil {
		return nil, err
	}
	var enabled int64
	ctx, cancel := context.WithTimeout(context.Background(), sqlDatabaseQueryTimeout)
	err = pool.QueryRow(ctx, "SELECT @@performance_schema").Scan(&enabled)
	cancel()
	if err != nil || enabled != 1 {
		pool.Close()
		return nil, fmt.Errorf("mysql.queries: performance_schema indisponível")
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = time.Minute
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	return &mysqlQueries{
		id: cfg.GetCheckId(), interval: interval, sampleInterval: time.Second,
		installationID: installationID,
		databaseID:     databaseID, server: strings.TrimSpace(tags["db_server"]),
		database: strings.TrimSpace(tags["db_name"]), tags: tags, pool: pool,
		previous:          make(map[string]postgresQueryCounter),
		queryLimit:        boundedParam(cfg.GetParams(), "query_limit", 1, postgresQueryStatsLimit, postgresQueryStatsLimit),
		sampleLimit:       boundedParam(cfg.GetParams(), "sample_limit", 1, postgresQuerySampleLimit, 20),
		continuousPlans:   boolParam(cfg.GetParams(), "continuous_plans_enabled", false),
		planLimit:         boundedParam(cfg.GetParams(), "continuous_plan_limit", 1, postgresContinuousPlanLimit, 2),
		minPlanDurationMS: floatParam(cfg.GetParams(), "continuous_plan_min_duration_ms", 0, 300000, 0),
		planRuns:          make(map[string]time.Time),
	}, nil
}

func (c *mysqlQueries) ID() string                    { return c.id }
func (c *mysqlQueries) Interval() time.Duration       { return c.interval }
func (c *mysqlQueries) SampleInterval() time.Duration { return c.sampleInterval }
func (c *mysqlQueries) Tags() map[string]string       { return c.tags }
func (c *mysqlQueries) Close() error                  { return c.pool.Close() }
func (c *mysqlQueries) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunQueryStats(ctx)
	return nil, err
}

func (c *mysqlQueries) RunQueryStats(ctx context.Context) (*DatabaseQueryStats, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := c.pool.Query(queryCtx, fmt.Sprintf(sqlMySQLQueryDigests, c.queryLimit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &DatabaseQueryStats{
		Engine: "mysql", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, WindowSeconds: max(1, int(c.interval/time.Second)),
		Queries: make([]DatabaseQueryStat, 0),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for rows.Next() {
		var digest, text string
		var calls, rowsSent int64
		var timer float64
		if err := rows.Scan(&digest, &text, &calls, &timer, &rowsSent); err != nil {
			return nil, err
		}
		current := postgresQueryCounter{calls: calls, totalMS: timer / 1e9, rows: rowsSent}
		previous, seen := c.previous[digest]
		c.previous[digest] = current
		if !seen {
			continue
		}
		windowCalls := counterDelta(current.calls, previous.calls)
		if windowCalls <= 0 {
			continue
		}
		windowMS := floatDelta(current.totalMS, previous.totalMS)
		out.Queries = append(out.Queries, DatabaseQueryStat{
			QueryID: digest, Text: sanitizeQueryText(text), Calls: windowCalls,
			TotalMS: windowMS, MeanMS: windowMS / float64(windowCalls),
			Rows: counterDelta(current.rows, previous.rows),
		})
	}
	return out, rows.Err()
}

func (c *mysqlQueries) RunQuerySamples(ctx context.Context) (*DatabaseQueryStats, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := c.pool.Query(queryCtx, fmt.Sprintf(sqlMySQLQuerySamples, c.sampleLimit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &DatabaseQueryStats{
		Engine: "mysql", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, WindowSeconds: 1,
		Samples: make([]DatabaseQuerySample, 0),
	}
	plansCollected := 0
	// O EXPLAIN roda depois de fechar a leitura: a conexão das amostras volta ao pool do servidor antes, e
	// nenhuma checagem segura duas conexões ao mesmo tempo (ver mysql_pool.go).
	explains := map[int]string{}
	for rows.Next() {
		var threadID, eventID int64
		var digest, text, rawQuery, user, client, state string
		var timer float64
		if err := rows.Scan(&threadID, &eventID, &digest, &text, &rawQuery, &user, &client, &state, &timer); err != nil {
			return nil, err
		}
		if digest == "" {
			continue
		}
		sample := DatabaseQuerySample{
			SampleID: fmt.Sprintf("%d:%d", threadID, eventID), QueryID: digest,
			Text: sanitizeQueryText(text), User: user, Client: client, State: state,
			DurationMS: timer / 1e9, SampledAt: time.Now().UTC().Format(time.RFC3339Nano),
		}
		switch {
		case !c.continuousPlans:
			sample.PlanStatus = "disabled"
		case sample.DurationMS < c.minPlanDurationMS:
			sample.PlanStatus = "below_threshold"
		case len(rawQuery) > postgresQueryTextLimit || validateReadOnlyQuery(rawQuery) != nil:
			sample.PlanStatus = "ineligible"
		case plansCollected >= c.planLimit || !c.allowPlan(digest, time.Now()):
			sample.PlanStatus = "rate_limited"
		default:
			plansCollected++
			explains[len(out.Samples)] = rawQuery
		}
		out.Samples = append(out.Samples, sample)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	rows.Close()
	for i, rawQuery := range explains {
		out.Samples[i].PlanJSON, out.Samples[i].PlanStatus = c.explainSample(ctx, rawQuery)
	}
	return out, nil
}

func (c *mysqlQueries) allowPlan(digest string, now time.Time) bool {
	if digest == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if last, ok := c.planRuns[digest]; ok && now.Sub(last) < 15*time.Minute {
		return false
	}
	for key, last := range c.planRuns {
		if now.Sub(last) >= time.Hour {
			delete(c.planRuns, key)
		}
	}
	if len(c.planRuns) >= 60 {
		return false
	}
	c.planRuns[digest] = now
	return true
}

func (c *mysqlQueries) explainSample(ctx context.Context, query string) (json.RawMessage, string) {
	qctx, cancel := context.WithTimeout(ctx, sqlDatabaseQueryTimeout)
	defer cancel()
	var raw string
	if err := c.pool.QueryRow(qctx, "EXPLAIN FORMAT=JSON "+query).Scan(&raw); err != nil {
		return nil, "unavailable"
	}
	plan, err := sanitizeMySQLPlan([]byte(raw))
	if err != nil {
		return nil, "invalid"
	}
	return plan, "ready"
}

var mysqlPlanFields = map[string]bool{
	"query_block": true, "nested_loop": true, "table": true, "select_id": true,
	"table_name": true, "access_type": true, "possible_keys": true, "key": true,
	"used_key_parts": true, "rows_examined_per_scan": true, "rows_produced_per_join": true,
	"rows": true, "filtered": true, "cost_info": true, "query_cost": true,
	"read_cost": true, "eval_cost": true, "prefix_cost": true,
	"using_index": true, "using_temporary_table": true, "using_filesort": true,
}

func sanitizeMySQLPlan(raw []byte) (json.RawMessage, error) {
	if len(raw) > 256*1024 {
		return nil, fmt.Errorf("plan too large")
	}
	var plan any
	if err := json.Unmarshal(raw, &plan); err != nil {
		return nil, err
	}
	var filter func(any) any
	filter = func(value any) any {
		switch typed := value.(type) {
		case []any:
			out := make([]any, 0, len(typed))
			for _, item := range typed {
				out = append(out, filter(item))
			}
			return out
		case map[string]any:
			out := make(map[string]any)
			for key, item := range typed {
				if mysqlPlanFields[key] {
					out[key] = filter(item)
				}
			}
			return out
		default:
			return typed
		}
	}
	return json.Marshal(filter(plan))
}

func init() {
	Default.Register("mysql.queries", newMySQLQueriesCheck)
}
