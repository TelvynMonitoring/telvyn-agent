package checks

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const sqlMSSQLQueryStats = `SELECT TOP (200) CONVERT(varchar(34), q.query_hash, 1),
	COALESCE(SUBSTRING(t.text, q.statement_start_offset / 2 + 1,
		(CASE WHEN q.statement_end_offset = -1 THEN DATALENGTH(t.text)
		ELSE q.statement_end_offset END - q.statement_start_offset) / 2 + 1), ''),
	q.execution_count, q.total_elapsed_time, COALESCE(q.total_rows,0)
FROM sys.dm_exec_query_stats q
CROSS APPLY sys.dm_exec_sql_text(q.sql_handle) t
CROSS APPLY sys.dm_exec_plan_attributes(q.plan_handle) a
WHERE a.attribute = 'dbid' AND TRY_CONVERT(int, a.value) = DB_ID()
	AND q.query_hash IS NOT NULL
ORDER BY q.total_elapsed_time DESC`

const sqlMSSQLQuerySamples = `SELECT TOP (20) r.session_id, r.request_id,
	CONVERT(varchar(34), r.query_hash, 1),
	COALESCE(SUBSTRING(t.text, r.statement_start_offset / 2 + 1,
		(CASE WHEN r.statement_end_offset = -1 THEN DATALENGTH(t.text)
		ELSE r.statement_end_offset END - r.statement_start_offset) / 2 + 1), ''),
	COALESCE(s.login_name,''), COALESCE(s.program_name,''), COALESCE(s.host_name,''),
	COALESCE(r.status,''), COALESCE(r.wait_type,''), r.total_elapsed_time,
	r.plan_handle, r.statement_start_offset, r.statement_end_offset
FROM sys.dm_exec_requests r
JOIN sys.dm_exec_sessions s ON s.session_id=r.session_id
CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE r.database_id=DB_ID() AND r.session_id<>@@SPID AND s.is_user_process=1
	AND r.query_hash IS NOT NULL
ORDER BY r.total_elapsed_time DESC`

type mssqlQueries struct {
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

func newMSSQLQueriesCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newMSSQLQueriesCheckWithFactory(cfg, defaultMSSQLPoolFactory)
}

func newMSSQLQueriesCheckWithFactory(cfg *collectorv1.CheckConfig, factory sqlDatabasePoolFactory) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" {
		return nil, fmt.Errorf("mssql.queries: installation_id e database_id obrigatórios")
	}
	pool, err := openSQLDatabasePool(cfg, factory, "mssql.queries")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = time.Minute
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}
	return &mssqlQueries{
		id: cfg.GetCheckId(), installationID: installationID, databaseID: databaseID,
		server: strings.TrimSpace(tags["db_server"]), database: strings.TrimSpace(tags["db_name"]),
		interval: interval, queryLimit: boundedParam(cfg.GetParams(), "query_limit", 1, 200, 200),
		sampleLimit:       boundedParam(cfg.GetParams(), "sample_limit", 1, 50, 20),
		continuousPlans:   boolParam(cfg.GetParams(), "continuous_plans_enabled", false),
		planLimit:         boundedParam(cfg.GetParams(), "continuous_plan_limit", 1, 5, 2),
		minPlanDurationMS: floatParam(cfg.GetParams(), "continuous_plan_min_duration_ms", 0, 300000, 0),
		tags:              tags, pool: pool, previous: make(map[string]postgresQueryCounter), planRuns: make(map[string]time.Time),
	}, nil
}

func (c *mssqlQueries) ID() string                    { return c.id }
func (c *mssqlQueries) Interval() time.Duration       { return c.interval }
func (c *mssqlQueries) SampleInterval() time.Duration { return time.Second }
func (c *mssqlQueries) Tags() map[string]string       { return c.tags }
func (c *mssqlQueries) Close() error                  { return c.pool.Close() }
func (c *mssqlQueries) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunQueryStats(ctx)
	return nil, err
}

func (c *mssqlQueries) RunQueryStats(ctx context.Context) (*DatabaseQueryStats, error) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := c.pool.Query(qctx, strings.Replace(sqlMSSQLQueryStats, "TOP (200)", fmt.Sprintf("TOP (%d)", c.queryLimit), 1))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	current := make(map[string]postgresQueryCounter)
	texts := make(map[string]string)
	for rows.Next() {
		var hash, text string
		var calls, totalMicroseconds, totalRows int64
		if err := rows.Scan(&hash, &text, &calls, &totalMicroseconds, &totalRows); err != nil {
			return nil, err
		}
		if hash == "" {
			continue
		}
		entry := current[hash]
		entry.calls += calls
		entry.totalMS += float64(totalMicroseconds) / 1000
		entry.rows += totalRows
		current[hash] = entry
		if len(text) > len(texts[hash]) {
			texts[hash] = text
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := &DatabaseQueryStats{
		Engine: "mssql", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, WindowSeconds: max(1, int(c.interval/time.Second)),
		Queries: make([]DatabaseQueryStat, 0),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for hash, value := range current {
		previous, seen := c.previous[hash]
		c.previous[hash] = value
		if !seen {
			continue
		}
		calls := counterDelta(value.calls, previous.calls)
		if calls <= 0 {
			continue
		}
		totalMS := floatDelta(value.totalMS, previous.totalMS)
		out.Queries = append(out.Queries, DatabaseQueryStat{
			QueryID: hash, Text: sanitizeQueryText(texts[hash]), Calls: calls,
			TotalMS: totalMS, MeanMS: totalMS / float64(calls),
			Rows: counterDelta(value.rows, previous.rows),
		})
	}
	return out, nil
}

func (c *mssqlQueries) RunQuerySamples(ctx context.Context) (*DatabaseQueryStats, error) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := c.pool.Query(qctx, strings.Replace(sqlMSSQLQuerySamples, "TOP (20)", fmt.Sprintf("TOP (%d)", c.sampleLimit), 1))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &DatabaseQueryStats{
		Engine: "mssql", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, WindowSeconds: 1,
		Samples: make([]DatabaseQuerySample, 0),
	}
	plansCollected := 0
	for rows.Next() {
		var sessionID, requestID, duration int64
		var startOffset, endOffset int64
		var planHandle []byte
		var hash, text, user, application, client, state, wait string
		if err := rows.Scan(&sessionID, &requestID, &hash, &text, &user, &application,
			&client, &state, &wait, &duration, &planHandle, &startOffset, &endOffset); err != nil {
			return nil, err
		}
		sample := DatabaseQuerySample{
			SampleID: fmt.Sprintf("%d:%d:%d", sessionID, requestID, time.Now().UnixNano()),
			QueryID:  hash, Text: sanitizeQueryText(text), User: user, Application: application,
			Client: client, State: state, WaitType: wait, DurationMS: float64(duration),
			SampledAt: time.Now().UTC().Format(time.RFC3339Nano),
		}
		switch {
		case !c.continuousPlans:
			sample.PlanStatus = "disabled"
		case sample.DurationMS < c.minPlanDurationMS:
			sample.PlanStatus = "below_threshold"
		case plansCollected >= c.planLimit || !c.allowPlan(hash):
			sample.PlanStatus = "rate_limited"
		default:
			plansCollected++
			sample.PlanJSON, sample.PlanStatus = c.cachedPlan(ctx, planHandle, startOffset, endOffset)
		}
		out.Samples = append(out.Samples, sample)
	}
	return out, rows.Err()
}

func (c *mssqlQueries) allowPlan(hash string) bool {
	if hash == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if last, ok := c.planRuns[hash]; ok && now.Sub(last) < 15*time.Minute {
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
	c.planRuns[hash] = now
	return true
}

func (c *mssqlQueries) cachedPlan(ctx context.Context, handle []byte, start, end int64) (json.RawMessage, string) {
	if len(handle) == 0 {
		return nil, "unavailable"
	}
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var raw string
	err := c.pool.QueryRow(qctx, `SELECT query_plan FROM sys.dm_exec_text_query_plan(@p1,@p2,@p3)`, handle, start, end).Scan(&raw)
	if err != nil || len(raw) > 1<<20 {
		return nil, "unavailable"
	}
	plan, err := sanitizedMSSQLPlan(raw)
	if err != nil {
		return nil, "unavailable"
	}
	return plan, "ready"
}

func sanitizedMSSQLPlan(raw string) (json.RawMessage, error) {
	decoder := xml.NewDecoder(strings.NewReader(raw))
	nodes := make([]map[string]any, 0)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "RelOp" {
			continue
		}
		node := make(map[string]any)
		for _, attr := range start.Attr {
			switch attr.Name.Local {
			case "PhysicalOp":
				node["Node Type"] = attr.Value
			case "LogicalOp":
				node["Join Type"] = attr.Value
			case "EstimateRows":
				if n, e := strconv.ParseFloat(attr.Value, 64); e == nil {
					node["Plan Rows"] = n
				}
			case "EstimatedTotalSubtreeCost":
				if n, e := strconv.ParseFloat(attr.Value, 64); e == nil {
					node["Total Cost"] = n
				}
			}
		}
		if len(node) > 0 && len(nodes) < 100 {
			nodes = append(nodes, node)
		}
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("empty SQL Server plan")
	}
	return json.Marshal(map[string]any{"Plan": nodes})
}

func init() { Default.Register("mssql.queries", newMSSQLQueriesCheck) }
