package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SQL Server and Oracle use the same typed metric contract, with bounded reads
// from their native database/sql drivers. The supplied DB user must be read-only.
type sqlCustom struct {
	id, hostID, engine, metricName, query string
	interval                              time.Duration
	columns                               []postgresCustomColumn
	rowLimit                              int
	tags                                  map[string]string
	pool                                  sqlDatabasePool
}

func newSQLCustomCheck(cfg *collectorv1.CheckConfig, engine string, factory sqlDatabasePoolFactory) (Check, error) {
	params := cfg.GetParams()
	query, metricName := strings.TrimSpace(params["query"]), strings.TrimSpace(params["metric_name"])
	if err := validateReadOnlyQuery(query); err != nil {
		return nil, fmt.Errorf("%s.custom: %w", engine, err)
	}
	if !postgresCustomMetricName.MatchString(metricName) {
		return nil, fmt.Errorf("%s.custom: metric_name inválido", engine)
	}
	columns, err := parsePostgresCustomColumns(params["columns_json"])
	if err != nil {
		return nil, err
	}
	pool, err := openSQLDatabasePool(cfg, factory, engine+".custom")
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
	return &sqlCustom{cfg.GetCheckId(), cfg.GetHostId(), engine, metricName, query,
		interval, columns, boundedParam(params, "row_limit", 1, postgresCustomMaxRows, 10), tags, pool}, nil
}

func (c *sqlCustom) ID() string              { return c.id }
func (c *sqlCustom) Interval() time.Duration { return c.interval }
func (c *sqlCustom) Tags() map[string]string { return c.tags }
func (c *sqlCustom) Close() error            { return c.pool.Close() }

func (c *sqlCustom) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresCustomQueryTimeout)
	defer cancel()
	rows, err := c.pool.Query(qctx, c.query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columnReader, ok := rows.(interface{ Columns() ([]string, error) })
	if !ok {
		return nil, fmt.Errorf("%s.custom: colunas indisponíveis", c.engine)
	}
	names, err := columnReader.Columns()
	if err != nil {
		return nil, err
	}
	positions := make(map[string]int, len(names))
	for i, name := range names {
		positions[strings.ToLower(name)] = i
	}
	for _, column := range c.columns {
		if _, ok := positions[strings.ToLower(column.Name)]; !ok {
			return nil, fmt.Errorf("%s.custom: coluna %s ausente", c.engine, column.Name)
		}
	}
	if len(c.columns) == 0 && len(names) != 1 {
		return nil, fmt.Errorf("%s.custom: consulta escalar deve retornar uma coluna", c.engine)
	}
	out := make([]*collectorv1.Metric, 0)
	rowCount := 0
	for rowCount < c.rowLimit && rows.Next() {
		rowCount++
		values := make([]any, len(names))
		dest := make([]any, len(names))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		tags := make(map[string]string, len(c.tags)+len(c.columns))
		for key, value := range c.tags {
			tags[key] = value
		}
		if len(c.columns) == 0 {
			value, err := numericValue(values[0])
			if err != nil {
				return nil, err
			}
			out = append(out, c.metric(c.metricName, value, "", tags))
			break
		}
		for _, column := range c.columns {
			if column.Type != "tag" || values[positions[strings.ToLower(column.Name)]] == nil {
				continue
			}
			raw := values[positions[strings.ToLower(column.Name)]]
			if bytes, ok := raw.([]byte); ok {
				raw = string(bytes)
			}
			tags["custom."+column.Name] = limitText(fmt.Sprint(raw), postgresCustomMaxTagValue)
		}
		for _, column := range c.columns {
			if column.Type == "tag" {
				continue
			}
			value, err := numericValue(values[positions[strings.ToLower(column.Name)]])
			if err != nil {
				return nil, fmt.Errorf("%s.custom: coluna %s não numérica: %w", c.engine, column.Name, err)
			}
			out = append(out, c.metric(c.metricName+"."+column.Name, value, column.Type, tags))
		}
	}
	return out, rows.Err()
}

func (c *sqlCustom) metric(suffix string, value float64, metricType string, baseTags map[string]string) *collectorv1.Metric {
	tags := make(map[string]string, len(baseTags)+2)
	for key, tag := range baseTags {
		tags[key] = tag
	}
	if tags["custom_name"] != "" {
		tags["custom_query"] = tags["custom_name"]
	}
	if metricType != "" {
		tags["custom_metric_type"] = metricType
	}
	return &collectorv1.Metric{Time: timestamppb.Now(), HostId: c.hostID,
		MetricName: c.engine + ".custom." + suffix, Value: value, Tags: tags, Source: c.engine + ".custom"}
}

func init() {
	Default.Register("mssql.custom", func(cfg *collectorv1.CheckConfig) (Check, error) {
		return newSQLCustomCheck(cfg, "mssql", defaultMSSQLPoolFactory)
	})
	Default.Register("oracle.custom", func(cfg *collectorv1.CheckConfig) (Check, error) {
		return newSQLCustomCheck(cfg, "oracle", defaultOraclePoolFactory)
	})
}
