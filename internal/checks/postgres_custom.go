// postgres_custom.go — métrica numérica definida pelo operador.
//
// A consulta é instalada pelo backend no Agent como configuração de leitura.
// Não existe endpoint público de SQL: o Agent executa a consulta no banco que
// o usuário cadastrou e publica somente o valor da primeira linha/coluna.
package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const postgresCustomQueryTimeout = 5 * time.Second

const (
	postgresCustomMaxColumns  = 16
	postgresCustomMaxRows     = 100
	postgresCustomMaxTags     = 8
	postgresCustomMaxTagValue = 200
)

var postgresCustomMetricName = regexp.MustCompile("^[A-Za-z][A-Za-z0-9_.-]{0,99}$")

type postgresCustom struct {
	id         string
	interval   time.Duration
	hostID     string
	metricName string
	queryName  string
	query      string
	columns    []postgresCustomColumn
	rowLimit   int
	staticTags map[string]string
	pool       pgxPool
}

type postgresCustomColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func newPostgresCustomCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newPostgresCustomCheckWithFactory(cfg, defaultPgxPoolFactory)
}

func newPostgresCustomCheckWithFactory(cfg *collectorv1.CheckConfig, factory pgxPoolFactory) (Check, error) {
	params := cfg.GetParams()
	query := strings.TrimSpace(params["query"])
	metricName := strings.TrimSpace(params["metric_name"])
	if err := validateReadOnlyQuery(query); err != nil {
		return nil, fmt.Errorf("postgres.custom: %w", err)
	}
	columns, err := parsePostgresCustomColumns(params["columns_json"])
	if err != nil {
		return nil, fmt.Errorf("postgres.custom: %w", err)
	}
	if metricName == "" {
		return nil, fmt.Errorf("postgres.custom: param 'metric_name' obrigatório")
	}
	if !postgresCustomMetricName.MatchString(metricName) {
		return nil, fmt.Errorf("postgres.custom: metric_name inválido")
	}
	pool, err := openPostgresPool(cfg, factory, "postgres.custom")
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
	// Consultas personalizadas continuam sendo métricas OTLP genéricas. Mantém
	// os IDs canônicos para que o backend valide a instância e o banco lógico
	// antes de aceitar a série.
	normalizeDatabaseMetricTags(cfg.GetParams(), tags)
	id := cfg.GetCheckId()
	if id == "" {
		id = "postgres.custom-" + cfg.GetHostId()
	}
	return &postgresCustom{
		id: id, interval: interval, hostID: cfg.GetHostId(), metricName: metricName,
		queryName: tags["custom_name"], query: query, columns: columns,
		rowLimit:   boundedParam(params, "row_limit", 1, postgresCustomMaxRows, 10),
		staticTags: tags, pool: pool,
	}, nil
}

func (c *postgresCustom) ID() string              { return c.id }
func (c *postgresCustom) Interval() time.Duration { return c.interval }
func (c *postgresCustom) Tags() map[string]string { return c.staticTags }

func (c *postgresCustom) Close() error {
	if c.pool != nil {
		c.pool.Close()
	}
	return nil
}

func (c *postgresCustom) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	if len(c.columns) > 0 {
		return c.runTyped(ctx)
	}
	qctx, cancel := context.WithTimeout(ctx, postgresCustomQueryTimeout)
	defer cancel()
	var raw any
	if err := c.pool.QueryRow(qctx, c.query).Scan(&raw); err != nil {
		log.Printf("postgres.custom[%s]: query failed: %v", c.id, err)
		return nil, err
	}
	value, err := numericValue(raw)
	if err != nil {
		return nil, fmt.Errorf("postgres.custom: resultado não numérico: %w", err)
	}
	name := "postgres.custom." + c.metricName
	tags := make(map[string]string, len(c.staticTags)+1)
	for k, v := range c.staticTags {
		tags[k] = v
	}
	if c.queryName != "" {
		tags["custom_query"] = c.queryName
	}
	return []*collectorv1.Metric{{
		Time: timestamppb.Now(), HostId: c.hostID, MetricName: name,
		Value: value, Tags: tags, Source: "postgres.custom",
	}}, nil
}

func parsePostgresCustomColumns(raw string) ([]postgresCustomColumn, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var columns []postgresCustomColumn
	if err := json.Unmarshal([]byte(raw), &columns); err != nil {
		return nil, fmt.Errorf("columns_json inválido: %w", err)
	}
	if len(columns) == 0 || len(columns) > postgresCustomMaxColumns {
		return nil, fmt.Errorf("columns_json deve ter entre 1 e %d colunas", postgresCustomMaxColumns)
	}
	tags := 0
	seen := make(map[string]struct{}, len(columns))
	for i := range columns {
		columns[i].Name = strings.TrimSpace(columns[i].Name)
		columns[i].Type = strings.ToLower(strings.TrimSpace(columns[i].Type))
		if !postgresCustomMetricName.MatchString(columns[i].Name) {
			return nil, fmt.Errorf("nome de coluna inválido: %s", columns[i].Name)
		}
		if _, exists := seen[columns[i].Name]; exists {
			return nil, fmt.Errorf("coluna duplicada: %s", columns[i].Name)
		}
		seen[columns[i].Name] = struct{}{}
		switch columns[i].Type {
		case "gauge", "count", "rate":
		case "tag":
			tags++
		default:
			return nil, fmt.Errorf("tipo inválido para %s: use gauge, count, rate ou tag", columns[i].Name)
		}
	}
	if tags > postgresCustomMaxTags {
		return nil, fmt.Errorf("máximo de %d colunas tag", postgresCustomMaxTags)
	}
	return columns, nil
}

func (c *postgresCustom) runTyped(ctx context.Context) ([]*collectorv1.Metric, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresCustomQueryTimeout)
	defer cancel()
	wrapped := fmt.Sprintf("SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json)::text FROM (SELECT * FROM (%s) telvyn_custom LIMIT %d) t", c.query, c.rowLimit)
	var raw string
	if err := c.pool.QueryRow(qctx, wrapped).Scan(&raw); err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil, fmt.Errorf("postgres.custom: resultado inválido: %w", err)
	}
	out := make([]*collectorv1.Metric, 0, len(rows)*len(c.columns))
	for _, row := range rows {
		tags := make(map[string]string, len(c.staticTags)+postgresCustomMaxTags+2)
		for key, value := range c.staticTags {
			tags[key] = value
		}
		if c.queryName != "" {
			tags["custom_query"] = c.queryName
		}
		for _, column := range c.columns {
			if column.Type != "tag" {
				continue
			}
			value := limitText(fmt.Sprint(row[column.Name]), postgresCustomMaxTagValue)
			if value != "" && value != "<nil>" {
				tags["custom."+column.Name] = value
			}
		}
		for _, column := range c.columns {
			if column.Type == "tag" {
				continue
			}
			value, err := numericValue(row[column.Name])
			if err != nil {
				return nil, fmt.Errorf("postgres.custom: coluna %s não numérica: %w", column.Name, err)
			}
			metricTags := make(map[string]string, len(tags)+1)
			for key, value := range tags {
				metricTags[key] = value
			}
			metricTags["custom_metric_type"] = column.Type
			out = append(out, &collectorv1.Metric{
				Time: timestamppb.Now(), HostId: c.hostID,
				MetricName: "postgres.custom." + c.metricName + "." + column.Name,
				Value:      value, Tags: metricTags, Source: "postgres.custom",
			})
		}
	}
	return out, nil
}

func numericValue(raw any) (float64, error) {
	switch v := raw.(type) {
	case int:
		return float64(v), nil
	case int8:
		return float64(v), nil
	case int16:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case uint:
		return float64(v), nil
	case uint8:
		return float64(v), nil
	case uint16:
		return float64(v), nil
	case uint32:
		return float64(v), nil
	case uint64:
		return float64(v), nil
	case float32:
		return float64(v), nil
	case float64:
		return v, nil
	case []byte:
		return strconv.ParseFloat(string(v), 64)
	case string:
		return strconv.ParseFloat(strings.TrimSpace(v), 64)
	default:
		return 0, fmt.Errorf("tipo %T", raw)
	}
}

// validateReadOnlyQuery é defesa em profundidade: a API valida antes de
// persistir, mas o Agent também precisa recusar uma configuração adulterada.
func validateReadOnlyQuery(query string) error {
	if query == "" {
		return fmt.Errorf("param 'query' obrigatório")
	}
	lower := strings.ToLower(query)
	normalized := strings.Join(strings.Fields(lower), " ")
	if !(strings.HasPrefix(normalized, "select ") || strings.HasPrefix(normalized, "with ")) {
		return fmt.Errorf("somente SELECT ou WITH é permitido")
	}
	if strings.Contains(query, ";") || strings.Contains(lower, "--") || strings.Contains(lower, "/*") {
		return fmt.Errorf("consulta deve ser uma única leitura")
	}
	for _, fragment := range []string{"select into", "set_config", "dblink_exec", "dblink_connect", "lo_import", "lo_export", "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_sleep", "pg_advisory_lock", "pg_try_advisory_lock", "pg_advisory_unlock", "nextval(", "setval("} {
		if strings.Contains(normalized, fragment) {
			return fmt.Errorf("operação não permitida")
		}
	}
	for _, word := range []string{"insert", "update", "delete", "drop", "alter", "create", "truncate", "grant", "revoke", "copy", "call", "do", "execute", "vacuum", "refresh", "set", "begin", "commit", "rollback"} {
		if containsSQLWord(lower, word) {
			return fmt.Errorf("palavra não permitida: %s", word)
		}
	}
	return nil
}

func containsSQLWord(query, word string) bool {
	for i := 0; ; {
		at := strings.Index(query[i:], word)
		if at < 0 {
			return false
		}
		at += i
		beforeOK := at == 0 || !isSQLWordChar(query[at-1])
		after := at + len(word)
		afterOK := after == len(query) || !isSQLWordChar(query[after])
		if beforeOK && afterOK {
			return true
		}
		i = after
		if i >= len(query) {
			return false
		}
	}
}

func isSQLWordChar(r byte) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_'
}

func init() {
	Default.Register("postgres.custom", newPostgresCustomCheck)
}
