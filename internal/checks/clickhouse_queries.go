package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const sqlClickHouseQueryLog = `SELECT query_id,toString(normalized_query_hash) AS query_hash,
	left(normalizeQuery(query),4000) AS text,query AS raw_query,query_duration_ms,result_rows,
	user,client_name,toString(address) AS address,
	toString(toUnixTimestamp64Micro(event_time_microseconds)) AS observed_us
	FROM system.query_log WHERE type='QueryFinish'
	AND event_time>=now()-INTERVAL 5 MINUTE AND has(databases,currentDatabase())
	AND is_initial_query=1 ORDER BY event_time_microseconds DESC LIMIT 10001`

type clickhouseQueries struct {
	id, installationID, databaseID, server, database string
	interval                                         time.Duration
	queryLimit, sampleLimit                          int
	continuousPlans                                  bool
	planLimit                                        int
	minPlanDurationMS                                float64
	tags                                             map[string]string
	client                                           *clickhouseClient
	mu                                               sync.Mutex
	seenStats, seenSamples                           map[string]time.Time
	planRuns                                         map[string]time.Time
}

func newClickHouseQueriesCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" {
		return nil, fmt.Errorf("clickhouse.queries: installation_id e database_id obrigatórios")
	}
	client, err := openClickHouseClient(cfg)
	if err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(client.url)
	options := parsed.Query()
	options.Set("readonly", "1")
	parsed.RawQuery = options.Encode()
	client.url = parsed.String()
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = time.Minute
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	return &clickhouseQueries{id: cfg.GetCheckId(), installationID: installationID, databaseID: databaseID,
		server: strings.TrimSpace(tags["db_server"]), database: strings.TrimSpace(tags["db_name"]),
		interval: interval, queryLimit: boundedParam(cfg.GetParams(), "query_limit", 1, 200, 200),
		sampleLimit:       boundedParam(cfg.GetParams(), "sample_limit", 1, 50, 20),
		continuousPlans:   boolParam(cfg.GetParams(), "continuous_plans_enabled", false),
		planLimit:         boundedParam(cfg.GetParams(), "continuous_plan_limit", 1, 5, 2),
		minPlanDurationMS: floatParam(cfg.GetParams(), "continuous_plan_min_duration_ms", 0, 300000, 0),
		tags:              tags, client: client, seenStats: make(map[string]time.Time), seenSamples: make(map[string]time.Time),
		planRuns: make(map[string]time.Time)}, nil
}

func (c *clickhouseQueries) ID() string                    { return c.id }
func (c *clickhouseQueries) Interval() time.Duration       { return c.interval }
func (c *clickhouseQueries) SampleInterval() time.Duration { return time.Second }
func (c *clickhouseQueries) Tags() map[string]string       { return c.tags }
func (c *clickhouseQueries) Close() error                  { c.client.http.CloseIdleConnections(); return nil }
func (c *clickhouseQueries) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunQueryStats(ctx)
	return nil, err
}

func (c *clickhouseQueries) recent(ctx context.Context) ([]map[string]any, error) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var rows []map[string]any
	if err := c.client.query(qctx, sqlClickHouseQueryLog, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (c *clickhouseQueries) fresh(rows []map[string]any, samples bool) []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := c.seenStats
	if samples {
		seen = c.seenSamples
	}
	now := time.Now()
	for id, observed := range seen {
		if now.Sub(observed) > 6*time.Minute {
			delete(seen, id)
		}
	}
	fresh := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if samples && len(fresh) >= c.sampleLimit {
			break
		}
		id, _ := row["query_id"].(string)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = now
		fresh = append(fresh, row)
	}
	return fresh
}

func (c *clickhouseQueries) RunQueryStats(ctx context.Context) (*DatabaseQueryStats, error) {
	rows, err := c.recent(ctx)
	if err != nil {
		return nil, err
	}
	rows = c.fresh(rows, false)
	byHash := make(map[string]*DatabaseQueryStat)
	for _, row := range rows {
		hash, _ := row["query_hash"].(string)
		if hash == "" {
			continue
		}
		entry := byHash[hash]
		if entry == nil {
			entry = &DatabaseQueryStat{QueryID: hash}
			byHash[hash] = entry
		}
		text, _ := row["text"].(string)
		if len(text) > len(entry.Text) {
			entry.Text = sanitizeQueryText(text)
		}
		entry.Calls++
		if elapsed, ok := row["query_duration_ms"].(float64); ok {
			entry.TotalMS += elapsed
		}
		if returned, ok := row["result_rows"].(float64); ok {
			entry.Rows += int64(returned)
		}
	}
	stats := make([]DatabaseQueryStat, 0, len(byHash))
	for _, entry := range byHash {
		entry.MeanMS = entry.TotalMS / float64(entry.Calls)
		stats = append(stats, *entry)
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].TotalMS > stats[j].TotalMS })
	if len(stats) > c.queryLimit {
		stats = stats[:c.queryLimit]
	}
	return &DatabaseQueryStats{Engine: "clickhouse", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, WindowSeconds: max(1, int(c.interval/time.Second)), Queries: stats}, nil
}

func (c *clickhouseQueries) RunQuerySamples(ctx context.Context) (*DatabaseQueryStats, error) {
	rows, err := c.recent(ctx)
	if err != nil {
		return nil, err
	}
	rows = c.fresh(rows, true)
	samples := make([]DatabaseQuerySample, 0, c.sampleLimit)
	plansCollected := 0
	for _, row := range rows {
		id, _ := row["query_id"].(string)
		hash, _ := row["query_hash"].(string)
		text, _ := row["text"].(string)
		rawQuery, _ := row["raw_query"].(string)
		user, _ := row["user"].(string)
		application, _ := row["client_name"].(string)
		client, _ := row["address"].(string)
		observedUS, _ := row["observed_us"].(string)
		microseconds, _ := strconv.ParseInt(observedUS, 10, 64)
		duration, _ := row["query_duration_ms"].(float64)
		sample := DatabaseQuerySample{SampleID: id, QueryID: hash, Text: sanitizeQueryText(text),
			User: user, Application: application, Client: client, State: "finished", DurationMS: duration,
			SampledAt: time.UnixMicro(microseconds).UTC().Format(time.RFC3339Nano)}
		switch {
		case !c.continuousPlans:
			sample.PlanStatus = "disabled"
		case duration < c.minPlanDurationMS:
			sample.PlanStatus = "below_threshold"
		case len(rawQuery) > postgresQueryTextLimit || validateReadOnlyQuery(rawQuery) != nil:
			sample.PlanStatus = "ineligible"
		case plansCollected >= c.planLimit || !c.allowPlan(hash):
			sample.PlanStatus = "rate_limited"
		default:
			plansCollected++
			sample.PlanJSON, sample.PlanStatus = c.explainPlan(ctx, rawQuery)
		}
		samples = append(samples, sample)
	}
	return &DatabaseQueryStats{Engine: "clickhouse", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, WindowSeconds: 1, Samples: samples}, nil
}

func (c *clickhouseQueries) allowPlan(hash string) bool {
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

func (c *clickhouseQueries) explainPlan(ctx context.Context, query string) (json.RawMessage, string) {
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var rows []map[string]any
	if c.client.query(qctx, "EXPLAIN PLAN "+strings.TrimSuffix(strings.TrimSpace(query), ";"), &rows) != nil {
		return nil, "unavailable"
	}
	nodes := make([]map[string]any, 0)
	for _, row := range rows {
		line, _ := row["explain"].(string)
		name := strings.Fields(strings.TrimSpace(line))
		if len(name) == 0 {
			continue
		}
		switch name[0] {
		case "Expression", "Filter", "ReadFromStorage", "Join", "Aggregating", "Sorting", "Limit", "Union", "Distinct", "Window", "ReadFromMergeTree":
			nodes = append(nodes, map[string]any{"Node Type": name[0]})
		}
		if len(nodes) >= 100 {
			break
		}
	}
	if len(nodes) == 0 {
		return nil, "unavailable"
	}
	plan, err := json.Marshal(map[string]any{"Plan": nodes})
	if err != nil {
		return nil, "unavailable"
	}
	return plan, "ready"
}

func init() { Default.Register("clickhouse.queries", newClickHouseQueriesCheck) }
