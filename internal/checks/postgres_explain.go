// postgres_explain.go — plano de execução pontual e somente leitura.
package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	postgresExplainQueryTimeout = 5 * time.Second
	postgresExplainMaxBytes     = 256 * 1024
)

// DatabaseExplainPlan é o resultado de uma solicitação do portal. O JSON é o
// plano do PostgreSQL; não contém linhas de negócio e não usa ANALYZE.
type DatabaseExplainPlan struct {
	InstallationID string
	DatabaseID     string
	RequestID      string
	CheckID        string
	DBServer       string
	DBName         string
	PlanJSON       string
	Error          string
}

// ExplainCheck é executado pelo scheduler como uma operação pontual. Depois
// que o backend confirma o recebimento, o check não repete a consulta; o
// backend também remove a configuração após receber o resultado.
type ExplainCheck interface {
	Check
	RunExplain(context.Context) (*DatabaseExplainPlan, error)
}

// ExplainPublishAware permite que o check só seja encerrado depois que o
// resultado chegar ao backend. Se o envio falhar, a solicitação continua viva
// e pode ser tentada no próximo ciclo.
type ExplainPublishAware interface {
	MarkExplainPublished()
}

type ExplainFailureProvider interface {
	ExplainFailure(error) DatabaseExplainPlan
}

type postgresExplain struct {
	id             string
	interval       time.Duration
	hostID         string
	requestID      string
	dbServer       string
	dbName         string
	installationID string
	databaseID     string
	query          string
	staticTags     map[string]string
	pool           pgxPool

	mu        sync.Mutex
	completed bool
}

func newPostgresExplainCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newPostgresExplainCheckWithFactory(cfg, defaultPgxPoolFactory)
}

func newPostgresExplainCheckWithFactory(cfg *collectorv1.CheckConfig, factory pgxPoolFactory) (Check, error) {
	params := cfg.GetParams()
	query := strings.TrimSpace(params["query"])
	if err := validateReadOnlyQuery(query); err != nil {
		return nil, fmt.Errorf("postgres.explain: %w", err)
	}
	requestID := strings.TrimSpace(params["request_id"])
	if requestID == "" {
		return nil, fmt.Errorf("postgres.explain: param 'request_id' obrigatório")
	}
	if len(query) > 8000 {
		return nil, fmt.Errorf("postgres.explain: consulta muito longa")
	}

	pool, err := openPostgresPool(cfg, factory, "postgres.explain")
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}
	normalizeDatabaseMetricTags(cfg.GetParams(), tags)
	installationID, databaseID := databaseIdentity(cfg.GetParams(), tags)
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 60 * time.Second
	}
	id := strings.TrimSpace(cfg.GetCheckId())
	if id == "" {
		id = "postgres.explain-" + cfg.GetHostId() + "-" + requestID
	}
	return &postgresExplain{
		id: id, interval: interval, hostID: cfg.GetHostId(), requestID: requestID,
		dbServer: strings.TrimSpace(tags["db_server"]), dbName: strings.TrimSpace(tags["db_name"]),
		installationID: installationID, databaseID: databaseID,
		query: query, staticTags: tags, pool: pool,
	}, nil
}

func (c *postgresExplain) ID() string              { return c.id }
func (c *postgresExplain) Interval() time.Duration { return c.interval }
func (c *postgresExplain) Tags() map[string]string { return c.staticTags }
func (c *postgresExplain) Close() error {
	if c.pool != nil {
		c.pool.Close()
	}
	return nil
}

// Run preserva a interface Check; o scheduler chama RunExplain diretamente.
func (c *postgresExplain) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunExplain(ctx)
	return nil, err
}

func (c *postgresExplain) RunExplain(ctx context.Context) (*DatabaseExplainPlan, error) {
	c.mu.Lock()
	if c.completed {
		c.mu.Unlock()
		return nil, nil
	}
	c.mu.Unlock()

	qctx, cancel := context.WithTimeout(ctx, postgresExplainQueryTimeout)
	defer cancel()
	// Sem ANALYZE: o PostgreSQL apenas planeja a consulta; ela não é executada.
	sql := "EXPLAIN (FORMAT JSON, COSTS true, VERBOSE false, BUFFERS false) " + c.query
	var body string
	if err := c.pool.QueryRow(qctx, sql).Scan(&body); err != nil {
		log.Printf("postgres.explain[%s]: query failed: %v", c.id, err)
		return nil, err
	}
	if len(body) == 0 || len(body) > postgresExplainMaxBytes || !json.Valid([]byte(body)) {
		return nil, fmt.Errorf("postgres.explain: resposta inválida ou acima de %d bytes", postgresExplainMaxBytes)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &DatabaseExplainPlan{
		InstallationID: c.installationID, DatabaseID: c.databaseID,
		RequestID: c.requestID, CheckID: c.id, DBServer: c.dbServer,
		DBName: c.dbName, PlanJSON: body,
	}, nil
}

func (c *postgresExplain) MarkExplainPublished() {
	c.mu.Lock()
	c.completed = true
	c.mu.Unlock()
}

func (c *postgresExplain) ExplainFailure(err error) DatabaseExplainPlan {
	message := "falha ao gerar plano"
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		message = err.Error()
	}
	if len(message) > 1024 {
		message = message[:1024]
	}
	return DatabaseExplainPlan{
		InstallationID: c.installationID, DatabaseID: c.databaseID,
		RequestID: c.requestID, CheckID: c.id, DBServer: c.dbServer,
		DBName: c.dbName, Error: message,
	}
}

func init() {
	Default.Register("postgres.explain", newPostgresExplainCheck)
}
