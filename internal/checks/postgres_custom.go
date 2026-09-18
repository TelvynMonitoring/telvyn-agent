// postgres_custom.go — métrica numérica definida pelo operador.
//
// A consulta é instalada pelo backend no Agent como configuração de leitura.
// Não existe endpoint público de SQL: o Agent executa a consulta no banco que
// o usuário cadastrou e publica somente o valor da primeira linha/coluna.
package checks

import (
	"context"
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

var postgresCustomMetricName = regexp.MustCompile("^[A-Za-z][A-Za-z0-9_.-]{0,99}$")

type postgresCustom struct {
	id         string
	interval   time.Duration
	hostID     string
	metricName string
	queryName  string
	query      string
	staticTags map[string]string
	pool       pgxPool
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
		queryName: tags["custom_name"], query: query, staticTags: tags, pool: pool,
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
