package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type clickhouseServer struct {
	id, hostID, database string
	interval             time.Duration
	tags                 map[string]string
	client               *clickhouseClient
}

func newClickHouseServerCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	database := strings.TrimSpace(cfg.GetStaticTags()["db_name"])
	if database == "" {
		return nil, fmt.Errorf("clickhouse.server: db_name obrigatório")
	}
	client, err := openClickHouseClient(cfg)
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
	return &clickhouseServer{cfg.GetCheckId(), cfg.GetHostId(), database, interval, tags, client}, nil
}

func (c *clickhouseServer) ID() string              { return c.id }
func (c *clickhouseServer) Interval() time.Duration { return c.interval }
func (c *clickhouseServer) Tags() map[string]string { return c.tags }
func (c *clickhouseServer) Close() error            { c.client.http.CloseIdleConnections(); return nil }

func (c *clickhouseServer) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	now := timestamppb.Now()
	metrics := make([]*collectorv1.Metric, 0, 8)
	add := func(name string, value float64) {
		metrics = append(metrics, &collectorv1.Metric{Time: now, HostId: c.hostID, MetricName: "clickhouse." + name,
			Value: value, Tags: c.tags, Source: "clickhouse.server"})
	}
	var gauges []map[string]any
	if err := c.client.query(qctx, `SELECT name,value FROM system.metrics
		WHERE name IN ('Query','TCPConnection','HTTPConnection')`, &gauges); err != nil {
		return nil, err
	}
	connections := float64(0)
	hasConnections := false
	for _, row := range gauges {
		name, _ := row["name"].(string)
		value, ok := row["value"].(float64)
		if !ok {
			continue
		}
		switch name {
		case "Query":
			add("active_queries", value)
		case "TCPConnection", "HTTPConnection":
			connections += value
			hasConnections = true
		}
	}
	if hasConnections {
		add("total_connections", connections)
	}
	var queryCount []map[string]any
	if err := c.client.query(qctx, `SELECT count() AS value FROM system.query_log
		WHERE type='QueryFinish' AND event_time>=now()-INTERVAL 5 MINUTE
		AND has(databases,currentDatabase()) AND is_initial_query=1`, &queryCount); err == nil && len(queryCount) == 1 {
		if value, ok := queryCount[0]["value"].(float64); ok {
			add("query_count_5m", value)
		}
	}
	var sizes []map[string]any
	if err := c.client.query(qctx, `SELECT sum(bytes_on_disk) AS bytes FROM system.parts
		WHERE active AND database=currentDatabase()`, &sizes); err != nil {
		return nil, err
	}
	if len(sizes) == 1 {
		if value, ok := sizes[0]["bytes"].(float64); ok {
			add("database_size_bytes", value)
		}
	}
	if len(metrics) == 0 {
		return nil, fmt.Errorf("clickhouse.server: nenhuma métrica disponível")
	}
	return metrics, nil
}

func init() { Default.Register("clickhouse.server", newClickHouseServerCheck) }
