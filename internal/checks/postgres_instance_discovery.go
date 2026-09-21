// postgres_instance_discovery.go descobre os bancos lógicos de uma única
// instância PostgreSQL. O Agent nunca recebe credenciais extras: parte do DSN
// semente já protegido pelo config-pull e só anuncia bancos aos quais o mesmo
// usuário pode CONNECT.
package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/jackc/pgx/v5"
)

const postgresInstanceDiscoveryTimeout = 10 * time.Second

// DatabaseInstanceDiscovery é enviada uma vez por intervalo ao endpoint
// dedicado. O backend, não o Agent, decide quais filhos lógicos criar/arquivar
// e quais checks entregar depois pelo config-pull.
type DatabaseInstanceDiscovery struct {
	InstallationID      string
	Engine              string
	Server              string
	Port                int
	ServerVersion       string
	Role                string
	PostmasterStartedAt string
	Databases           []string
}

// InstanceDiscoveryCheck marca checks que informam a topologia lógica de uma
// instância sem gerar séries de alta cardinalidade.
type InstanceDiscoveryCheck interface {
	Check
	RunInstanceDiscovery(context.Context) (*DatabaseInstanceDiscovery, error)
}

type postgresInstanceDiscovery struct {
	id             string
	interval       time.Duration
	installationID string
	server         string
	port           int
	staticTags     map[string]string
	pool           pgxPool
}

// current_setting é lido junto da lista para que o backend possa exibir a
// versão sem precisar abrir nova conexão. has_database_privilege garante que a
// lista represente bancos que o Agent realmente consegue monitorar, não só
// metadados visíveis em pg_database.
const sqlPostgresInstanceDiscovery = `SELECT json_build_object(
  'server_version', current_setting('server_version'),
	'role', CASE WHEN pg_is_in_recovery() THEN 'standby' ELSE 'primary' END,
	'postmaster_started_at', pg_postmaster_start_time()::text,
  'databases', COALESCE((
    SELECT json_agg(d.datname ORDER BY d.datname)
      FROM pg_database d
     WHERE d.datallowconn
       AND NOT d.datistemplate
       AND has_database_privilege(d.datname, 'CONNECT')
  ), '[]'::json)
)::text`

func newPostgresInstanceDiscoveryCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newPostgresInstanceDiscoveryCheckWithFactory(cfg, defaultPgxPoolFactory)
}

func newPostgresInstanceDiscoveryCheckWithFactory(cfg *collectorv1.CheckConfig, factory pgxPoolFactory) (Check, error) {
	installationID, _ := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" {
		return nil, fmt.Errorf("postgres.instance_discovery: installation_id obrigatório")
	}

	pool, err := openPostgresPool(cfg, factory, "postgres.instance_discovery")
	if err != nil {
		return nil, err
	}

	server, port, err := postgresInstanceAddress(cfg)
	if err != nil {
		pool.Close()
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	id := strings.TrimSpace(cfg.GetCheckId())
	if id == "" {
		id = "postgres.instance_discovery-" + cfg.GetHostId()
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	normalizeDatabaseMetricTags(cfg.GetParams(), tags)
	return &postgresInstanceDiscovery{
		id: id, interval: interval, installationID: installationID,
		server: server, port: port, staticTags: tags, pool: pool,
	}, nil
}

func postgresInstanceAddress(cfg *collectorv1.CheckConfig) (string, int, error) {
	params := cfg.GetParams()
	tags := cfg.GetStaticTags()
	server := strings.TrimSpace(tags["db_server"])
	if server == "" {
		server = strings.TrimSpace(params["db_server"])
	}
	port := postgresInstancePort(tags["db_port"])
	if port == 0 {
		port = postgresInstancePort(params["db_port"])
	}

	parsed, err := pgx.ParseConfig(params["dsn"])
	if err != nil {
		return "", 0, fmt.Errorf("postgres.instance_discovery: DSN inválido: %w", err)
	}
	if server == "" {
		server = strings.TrimSpace(parsed.Host)
	}
	if port == 0 && parsed.Port > 0 {
		port = int(parsed.Port)
	}
	if server == "" || port <= 0 {
		return "", 0, fmt.Errorf("postgres.instance_discovery: servidor e porta obrigatórios")
	}
	return server, port, nil
}

func postgresInstancePort(raw string) int {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port <= 0 || port > 65535 {
		return 0
	}
	return port
}

func (c *postgresInstanceDiscovery) ID() string              { return c.id }
func (c *postgresInstanceDiscovery) Interval() time.Duration { return c.interval }
func (c *postgresInstanceDiscovery) Tags() map[string]string { return c.staticTags }
func (c *postgresInstanceDiscovery) Close() error {
	if c.pool != nil {
		c.pool.Close()
	}
	return nil
}

func (c *postgresInstanceDiscovery) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunInstanceDiscovery(ctx)
	return nil, err
}

func (c *postgresInstanceDiscovery) RunInstanceDiscovery(ctx context.Context) (*DatabaseInstanceDiscovery, error) {
	queryCtx, cancel := context.WithTimeout(ctx, postgresInstanceDiscoveryTimeout)
	defer cancel()
	var raw string
	if err := c.pool.QueryRow(queryCtx, sqlPostgresInstanceDiscovery).Scan(&raw); err != nil {
		log.Printf("postgres.instance_discovery[%s]: query failed: %v", c.id, err)
		return nil, err
	}
	var result struct {
		ServerVersion       string   `json:"server_version"`
		Role                string   `json:"role"`
		PostmasterStartedAt string   `json:"postmaster_started_at"`
		Databases           []string `json:"databases"`
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("postgres.instance_discovery: resposta inválida: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if result.Databases == nil {
		result.Databases = []string{}
	}
	return &DatabaseInstanceDiscovery{
		InstallationID:      c.installationID,
		Engine:              "postgres",
		Server:              c.server,
		Port:                c.port,
		ServerVersion:       result.ServerVersion,
		Role:                result.Role,
		PostmasterStartedAt: result.PostmasterStartedAt,
		Databases:           result.Databases,
	}, nil
}

func init() {
	Default.Register("postgres.instance_discovery", newPostgresInstanceDiscoveryCheck)
}
