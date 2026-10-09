package checks

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type clickhouseCustom struct {
	id, hostID, metricName, query string
	interval                      time.Duration
	columns                       []postgresCustomColumn
	rowLimit                      int
	tags                          map[string]string
	client                        *clickhouseClient
}

func newClickHouseCustomCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	query, metricName := strings.TrimSpace(params["query"]), strings.TrimSpace(params["metric_name"])
	if err := validateReadOnlyQuery(query); err != nil {
		return nil, fmt.Errorf("clickhouse.custom: %w", err)
	}
	if !postgresCustomMetricName.MatchString(metricName) {
		return nil, fmt.Errorf("clickhouse.custom: metric_name inválido")
	}
	columns, err := parsePostgresCustomColumns(params["columns_json"])
	if err != nil {
		return nil, err
	}
	client, err := openClickHouseClient(cfg)
	if err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(client.url)
	options := parsed.Query()
	options.Set("readonly", "1")
	options.Set("max_result_rows", "100")
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
	normalizeDatabaseMetricTags(params, tags)
	return &clickhouseCustom{cfg.GetCheckId(), cfg.GetHostId(), metricName, query,
		interval, columns, boundedParam(params, "row_limit", 1, postgresCustomMaxRows, 10), tags, client}, nil
}

func (c *clickhouseCustom) ID() string              { return c.id }
func (c *clickhouseCustom) Interval() time.Duration { return c.interval }
func (c *clickhouseCustom) Tags() map[string]string { return c.tags }
func (c *clickhouseCustom) Close() error            { c.client.http.CloseIdleConnections(); return nil }

func (c *clickhouseCustom) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresCustomQueryTimeout)
	defer cancel()
	var rows []map[string]any
	query := fmt.Sprintf("SELECT * FROM (%s) LIMIT %d", c.query, c.rowLimit)
	if err := c.client.query(qctx, query, &rows); err != nil {
		return nil, err
	}
	out := make([]*collectorv1.Metric, 0)
	for _, row := range rows {
		tags := make(map[string]string, len(c.tags)+len(c.columns))
		for key, value := range c.tags {
			tags[key] = value
		}
		columns := c.columns
		if len(columns) == 0 {
			if len(row) != 1 {
				return nil, fmt.Errorf("clickhouse.custom: consulta escalar deve retornar uma coluna")
			}
			for _, value := range row {
				number, err := numericValue(value)
				if err != nil {
					return nil, err
				}
				out = append(out, c.metric(c.metricName, number, "", tags))
			}
			break
		}
		for _, column := range columns {
			value, ok := row[column.Name]
			if !ok {
				return nil, fmt.Errorf("clickhouse.custom: coluna %s ausente", column.Name)
			}
			if column.Type == "tag" && value != nil {
				tags["custom."+column.Name] = limitText(fmt.Sprint(value), postgresCustomMaxTagValue)
			}
		}
		for _, column := range columns {
			if column.Type == "tag" {
				continue
			}
			number, err := numericValue(row[column.Name])
			if err != nil {
				return nil, fmt.Errorf("clickhouse.custom: coluna %s não numérica: %w", column.Name, err)
			}
			out = append(out, c.metric(c.metricName+"."+column.Name, number, column.Type, tags))
		}
	}
	return out, nil
}

func (c *clickhouseCustom) metric(suffix string, value float64, metricType string, baseTags map[string]string) *collectorv1.Metric {
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
		MetricName: "clickhouse.custom." + suffix, Value: value, Tags: tags, Source: "clickhouse.custom"}
}

func init() { Default.Register("clickhouse.custom", newClickHouseCustomCheck) }
