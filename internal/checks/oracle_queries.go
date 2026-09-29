package checks

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const sqlOracleQueryStats = `SELECT SQL_ID, NVL(SUBSTR(SQL_TEXT,1,4000),' '), EXECUTIONS,
	ELAPSED_TIME, ROWS_PROCESSED FROM (
	SELECT SQL_ID, SQL_TEXT, EXECUTIONS, ELAPSED_TIME, ROWS_PROCESSED
	FROM V$SQL WHERE SQL_ID IS NOT NULL AND PARSING_SCHEMA_NAME NOT IN ('SYS','SYSTEM')
	ORDER BY ELAPSED_TIME DESC) WHERE ROWNUM<=200`

const sqlOracleQuerySamples = `SELECT SID, SQL_ID, NVL(SQL_CHILD_NUMBER,0),
	NVL((SELECT MAX(SUBSTR(Q.SQL_TEXT,1,4000)) FROM V$SQL Q WHERE Q.SQL_ID=S.SQL_ID),' '),
	NVL(USERNAME,' '), NVL(MODULE,' '), NVL(MACHINE,' '),
	NVL(STATE,' '), NVL(EVENT,' '), LAST_CALL_ET
	FROM V$SESSION S WHERE TYPE='USER' AND STATUS='ACTIVE'
	AND SQL_ID IS NOT NULL AND USERNAME NOT IN ('SYS','SYSTEM') AND ROWNUM<=20`

type oracleQueries struct {
	id, installationID, databaseID, server, database string
	interval                                         time.Duration
	queryLimit, sampleLimit                          int
	continuousPlans                                  bool
	planLimit                                        int
	minPlanDurationMS                                float64
	tags                                             map[string]string
	pool                                             sqlDatabasePool
	mu                                               sync.Mutex
	previous                                         map[string]postgresQueryCounter
	planRuns                                         map[string]time.Time
}

func newOracleQueriesCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" {
		return nil, fmt.Errorf("oracle.queries: installation_id e database_id obrigatórios")
	}
	pool, err := openSQLDatabasePool(cfg, defaultOraclePoolFactory, "oracle.queries")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = time.Minute
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	return &oracleQueries{id: cfg.GetCheckId(), installationID: installationID, databaseID: databaseID,
		server: strings.TrimSpace(tags["db_server"]), database: strings.TrimSpace(tags["db_name"]),
		interval: interval, queryLimit: boundedParam(cfg.GetParams(), "query_limit", 1, 200, 200),
		sampleLimit:       boundedParam(cfg.GetParams(), "sample_limit", 1, 50, 20),
		continuousPlans:   boolParam(cfg.GetParams(), "continuous_plans_enabled", false),
		planLimit:         boundedParam(cfg.GetParams(), "continuous_plan_limit", 1, 5, 2),
		minPlanDurationMS: floatParam(cfg.GetParams(), "continuous_plan_min_duration_ms", 0, 300000, 0),
		tags:              tags, pool: pool, previous: make(map[string]postgresQueryCounter), planRuns: make(map[string]time.Time)}, nil
}

func (c *oracleQueries) ID() string                    { return c.id }
func (c *oracleQueries) Interval() time.Duration       { return c.interval }
func (c *oracleQueries) SampleInterval() time.Duration { return time.Second }
func (c *oracleQueries) Tags() map[string]string       { return c.tags }
func (c *oracleQueries) Close() error                  { return c.pool.Close() }
func (c *oracleQueries) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunQueryStats(ctx)
	return nil, err
}

func (c *oracleQueries) RunQueryStats(ctx context.Context) (*DatabaseQueryStats, error) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := c.pool.Query(qctx, strings.Replace(sqlOracleQueryStats, "ROWNUM<=200", fmt.Sprintf("ROWNUM<=%d", c.queryLimit), 1))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	current := make(map[string]postgresQueryCounter)
	texts := make(map[string]string)
	for rows.Next() {
		var id, text string
		var calls, elapsedMicroseconds, returned int64
		if err := rows.Scan(&id, &text, &calls, &elapsedMicroseconds, &returned); err != nil {
			return nil, err
		}
		counter := current[id]
		counter.calls += calls
		counter.totalMS += float64(elapsedMicroseconds) / 1000
		counter.rows += returned
		current[id] = counter
		if len(text) > len(texts[id]) {
			texts[id] = text
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := &DatabaseQueryStats{Engine: "oracle", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, WindowSeconds: max(1, int(c.interval/time.Second)),
		Queries: make([]DatabaseQueryStat, 0)}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, value := range current {
		previous, seen := c.previous[id]
		c.previous[id] = value
		if !seen {
			continue
		}
		calls := counterDelta(value.calls, previous.calls)
		if calls <= 0 {
			continue
		}
		totalMS := floatDelta(value.totalMS, previous.totalMS)
		out.Queries = append(out.Queries, DatabaseQueryStat{
			QueryID: id, Text: sanitizeQueryText(texts[id]), Calls: calls,
			TotalMS: totalMS, MeanMS: totalMS / float64(calls), Rows: counterDelta(value.rows, previous.rows),
		})
	}
	return out, nil
}

func (c *oracleQueries) RunQuerySamples(ctx context.Context) (*DatabaseQueryStats, error) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := c.pool.Query(qctx, strings.Replace(sqlOracleQuerySamples, "ROWNUM<=20", fmt.Sprintf("ROWNUM<=%d", c.sampleLimit), 1))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &DatabaseQueryStats{Engine: "oracle", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, WindowSeconds: 1, Samples: make([]DatabaseQuerySample, 0)}
	plansCollected := 0
	for rows.Next() {
		var sid, childNumber, lastCallSeconds int64
		var id, text, user, application, client, state, event string
		if err := rows.Scan(&sid, &id, &childNumber, &text, &user, &application, &client, &state, &event, &lastCallSeconds); err != nil {
			return nil, err
		}
		sample := DatabaseQuerySample{
			SampleID: fmt.Sprintf("%d:%d", sid, time.Now().UnixNano()), QueryID: id,
			Text: sanitizeQueryText(text), User: user, Application: application, Client: client,
			State: state, WaitEvent: event, DurationMS: float64(lastCallSeconds) * 1000,
			SampledAt: time.Now().UTC().Format(time.RFC3339Nano),
		}
		switch {
		case !c.continuousPlans:
			sample.PlanStatus = "disabled"
		case sample.DurationMS < c.minPlanDurationMS:
			sample.PlanStatus = "below_threshold"
		case plansCollected >= c.planLimit || !c.allowPlan(id):
			sample.PlanStatus = "rate_limited"
		default:
			plansCollected++
			sample.PlanJSON, sample.PlanStatus = c.cachedPlan(ctx, id, childNumber)
		}
		out.Samples = append(out.Samples, sample)
	}
	return out, rows.Err()
}

func (c *oracleQueries) allowPlan(id string) bool {
	if id == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if last, ok := c.planRuns[id]; ok && now.Sub(last) < 15*time.Minute {
		return false
	}
	for key, last := range c.planRuns {
		if now.Sub(last) > time.Hour {
			delete(c.planRuns, key)
		}
	}
	if len(c.planRuns) >= 60 {
		return false
	}
	c.planRuns[id] = now
	return true
}

func (c *oracleQueries) cachedPlan(ctx context.Context, id string, child int64) (json.RawMessage, string) {
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := c.pool.Query(qctx, `SELECT OPERATION, OPTIONS, OBJECT_NAME, COST, CARDINALITY FROM
		(SELECT OPERATION, OPTIONS, OBJECT_NAME, COST, CARDINALITY FROM V$SQL_PLAN
		WHERE SQL_ID=:1 AND CHILD_NUMBER=:2 ORDER BY ID) WHERE ROWNUM<=100`, id, child)
	if err != nil {
		return nil, "unavailable"
	}
	defer rows.Close()
	nodes := make([]map[string]any, 0)
	for rows.Next() {
		var operation, options, object sql.NullString
		var cost, cardinality sql.NullFloat64
		if rows.Scan(&operation, &options, &object, &cost, &cardinality) != nil {
			return nil, "unavailable"
		}
		node := map[string]any{"Node Type": strings.TrimSpace(operation.String + " " + options.String)}
		if object.Valid {
			node["Relation Name"] = object.String
		}
		if cost.Valid {
			node["Total Cost"] = cost.Float64
		}
		if cardinality.Valid {
			node["Plan Rows"] = cardinality.Float64
		}
		nodes = append(nodes, node)
	}
	if rows.Err() != nil || len(nodes) == 0 {
		return nil, "unavailable"
	}
	plan, err := json.Marshal(map[string]any{"Plan": nodes})
	if err != nil {
		return nil, "unavailable"
	}
	return plan, "ready"
}

func init() { Default.Register("oracle.queries", newOracleQueriesCheck) }
