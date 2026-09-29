package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mysqlCustom struct {
	id, hostID, metricName, queryName, query string
	interval                                 time.Duration
	columns                                  []postgresCustomColumn
	rowLimit                                 int
	tags                                     map[string]string
	pool                                     sqlDatabasePool
}

func newMySQLCustomCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newMySQLCustomCheckWithFactory(cfg, defaultMySQLPoolFactory)
}

func newMySQLCustomCheckWithFactory(cfg *collectorv1.CheckConfig, factory sqlDatabasePoolFactory) (Check, error) {
	params := cfg.GetParams()
	query := strings.TrimSpace(params["query"])
	metricName := strings.TrimSpace(params["metric_name"])
	if err := validateReadOnlyQuery(query); err != nil {
		return nil, fmt.Errorf("mysql.custom: %w", err)
	}
	if !postgresCustomMetricName.MatchString(metricName) {
		return nil, fmt.Errorf("mysql.custom: metric_name inválido")
	}
	columns, err := parsePostgresCustomColumns(params["columns_json"])
	if err != nil {
		return nil, fmt.Errorf("mysql.custom: %w", err)
	}
	pool, err := openSQLDatabasePool(cfg, factory, "mysql.custom")
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
	normalizeDatabaseMetricTags(params, tags)
	id := cfg.GetCheckId()
	if id == "" {
		id = "mysql.custom-" + cfg.GetHostId()
	}
	return &mysqlCustom{id: id, hostID: cfg.GetHostId(), interval: interval,
		metricName: metricName, queryName: tags["custom_name"], query: query,
		columns: columns, rowLimit: boundedParam(params, "row_limit", 1, postgresCustomMaxRows, 10),
		tags: tags, pool: pool}, nil
}

func (c *mysqlCustom) ID() string              { return c.id }
func (c *mysqlCustom) Interval() time.Duration { return c.interval }
func (c *mysqlCustom) Tags() map[string]string { return c.tags }
func (c *mysqlCustom) Close() error            { return c.pool.Close() }

func (c *mysqlCustom) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresCustomQueryTimeout)
	defer cancel()
	if len(c.columns) == 0 {
		var raw any
		if err := c.pool.QueryRow(qctx, c.query).Scan(&raw); err != nil {
			return nil, err
		}
		value, err := numericValue(raw)
		if err != nil {
			return nil, fmt.Errorf("mysql.custom: resultado não numérico: %w", err)
		}
		return []*collectorv1.Metric{c.metric("mysql.custom."+c.metricName, value, "", c.tags)}, nil
	}

	fields := make([]string, 0, len(c.columns)*2)
	for _, column := range c.columns {
		fields = append(fields, "'"+column.Name+"'", "t.`"+column.Name+"`")
	}
	wrapped := fmt.Sprintf("SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(%s)), JSON_ARRAY()) FROM (SELECT * FROM (%s) telvyn_custom LIMIT %d) t",
		strings.Join(fields, ","), c.query, c.rowLimit)
	var raw string
	if err := c.pool.QueryRow(qctx, wrapped).Scan(&raw); err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil, fmt.Errorf("mysql.custom: resultado inválido: %w", err)
	}
	out := make([]*collectorv1.Metric, 0, len(rows)*len(c.columns))
	for _, row := range rows {
		tags := make(map[string]string, len(c.tags)+postgresCustomMaxTags+1)
		for key, value := range c.tags {
			tags[key] = value
		}
		for _, column := range c.columns {
			if column.Type == "tag" && row[column.Name] != nil {
				tags["custom."+column.Name] = limitText(fmt.Sprint(row[column.Name]), postgresCustomMaxTagValue)
			}
		}
		for _, column := range c.columns {
			if column.Type == "tag" {
				continue
			}
			value, err := numericValue(row[column.Name])
			if err != nil {
				return nil, fmt.Errorf("mysql.custom: coluna %s não numérica: %w", column.Name, err)
			}
			out = append(out, c.metric("mysql.custom."+c.metricName+"."+column.Name, value, column.Type, tags))
		}
	}
	return out, nil
}

func (c *mysqlCustom) metric(name string, value float64, metricType string, baseTags map[string]string) *collectorv1.Metric {
	tags := make(map[string]string, len(baseTags)+2)
	for key, tag := range baseTags {
		tags[key] = tag
	}
	if c.queryName != "" {
		tags["custom_query"] = c.queryName
	}
	if metricType != "" {
		tags["custom_metric_type"] = metricType
	}
	return &collectorv1.Metric{Time: timestamppb.Now(), HostId: c.hostID,
		MetricName: name, Value: value, Tags: tags, Source: "mysql.custom"}
}

func init() {
	Default.Register("mysql.custom", newMySQLCustomCheck)
}
