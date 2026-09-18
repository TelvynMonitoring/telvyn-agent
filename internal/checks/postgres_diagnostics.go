// postgres_diagnostics.go envia um retrato limitado de atividade do Postgres.
// Ele não lê linhas de negócio: somente pg_stat_activity, locks, waits e,
// quando explicitamente habilitado, pgstattuple_approx nos maiores objetos.
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
)

const postgresDiagnosticsQueryTimeout = 5 * time.Second

// DatabaseDiagnostics é o retrato operacional entregue ao endpoint dedicado.
// Texto SQL não sai do host do cliente: até um sanitizer parcial poderia deixar
// escapar literais PostgreSQL (por exemplo, dollar-quoted) ou PII.
type DatabaseDiagnostics struct {
	InstallationID string             `json:"installation_id"`
	DatabaseID     string             `json:"database_id"`
	DBServer       string             `json:"db_server"`
	DBName         string             `json:"db_name"`
	BloatEnabled   bool               `json:"bloat_enabled"`
	Capabilities   map[string]string  `json:"capabilities"`
	Sessions       []DatabaseSession  `json:"sessions"`
	Blocking       []DatabaseBlocking `json:"blocking"`
	Waits          []DatabaseWait     `json:"waits"`
	Bloat          []DatabaseBloat    `json:"bloat"`
	Errors         []string           `json:"errors,omitempty"`
}

type DatabaseSession struct {
	PID             int64   `json:"pid"`
	User            string  `json:"user"`
	Application     string  `json:"application"`
	Client          string  `json:"client"`
	State           string  `json:"state"`
	WaitType        string  `json:"wait_type"`
	WaitEvent       string  `json:"wait_event"`
	QueryStart      string  `json:"query_start"`
	DurationSeconds float64 `json:"duration_seconds"`
}

type DatabaseBlocking struct {
	BlockedPID   int64  `json:"blocked_pid"`
	BlockingPID  int64  `json:"blocking_pid"`
	BlockedUser  string `json:"blocked_user"`
	BlockingUser string `json:"blocking_user"`
}

type DatabaseWait struct {
	WaitType  string `json:"wait_type"`
	WaitEvent string `json:"wait_event"`
	Count     int64  `json:"count"`
}

type DatabaseBloat struct {
	SchemaName     string  `json:"schema_name"`
	TableName      string  `json:"table_name"`
	TotalSizeBytes int64   `json:"total_size_bytes"`
	DeadBytes      int64   `json:"dead_bytes"`
	DeadPercent    float64 `json:"dead_percent"`
	FreeBytes      int64   `json:"free_bytes"`
	FreePercent    float64 `json:"free_percent"`
}

// DiagnosticsCheck marca checks que enviam dados estruturados, sem tentar
// colocá-los no VictoriaMetrics como séries de alta cardinalidade.
type DiagnosticsCheck interface {
	Check
	RunDiagnostics(context.Context) (*DatabaseDiagnostics, error)
}

type postgresDiagnostics struct {
	id             string
	interval       time.Duration
	hostID         string
	dbServer       string
	dbName         string
	installationID string
	databaseID     string
	bloatEnabled   bool
	staticTags     map[string]string
	pool           pgxPool
}

const sqlPostgresDiagnosticSessions = `SELECT COALESCE(json_agg(s ORDER BY s.duration_seconds DESC), '[]'::json)::text
  FROM (
    SELECT pid::bigint AS pid,
           COALESCE(usename, '') AS "user",
           COALESCE(application_name, '') AS application,
           COALESCE(client_addr::text, '') AS client,
           COALESCE(state, '') AS state,
           COALESCE(wait_event_type, '') AS wait_type,
           COALESCE(wait_event, '') AS wait_event,
           COALESCE(query_start::text, '') AS query_start,
           COALESCE(EXTRACT(EPOCH FROM now() - query_start), 0)::float8 AS duration_seconds
      FROM pg_stat_activity
     WHERE datname = current_database() AND pid <> pg_backend_pid()
     ORDER BY query_start NULLS LAST
     LIMIT 200
  ) s`

const sqlPostgresDiagnosticBlocking = `SELECT COALESCE(json_agg(b), '[]'::json)::text
  FROM (
    SELECT blocked.pid::bigint AS blocked_pid,
           blocker.pid::bigint AS blocking_pid,
           COALESCE(blocked.usename, '') AS blocked_user,
           COALESCE(blocker.usename, '') AS blocking_user
      FROM pg_stat_activity blocked
      CROSS JOIN LATERAL unnest(pg_blocking_pids(blocked.pid)) AS lock_owner(blocking_pid)
      JOIN pg_stat_activity blocker ON blocker.pid = lock_owner.blocking_pid
     WHERE blocked.datname = current_database()
     ORDER BY blocked.query_start NULLS LAST
     LIMIT 200
  ) b`

const sqlPostgresDiagnosticWaits = `SELECT COALESCE(json_agg(w ORDER BY w.count DESC), '[]'::json)::text
  FROM (
    SELECT COALESCE(wait_event_type, '') AS wait_type,
           COALESCE(wait_event, '') AS wait_event,
           COUNT(*)::bigint AS count
      FROM pg_stat_activity
     WHERE datname = current_database() AND wait_event_type IS NOT NULL
     GROUP BY wait_event_type, wait_event
     ORDER BY count DESC
     LIMIT 200
  ) w`

// pgstattuple_approx só é acionada pelo toggle explícito do portal. A consulta
// limita-se às cinquenta maiores tabelas para não disputar IO com o workload.
const sqlPostgresDiagnosticBloat = `WITH largest AS (
  SELECT c.oid, n.nspname AS schema_name, c.relname AS table_name,
         pg_total_relation_size(c.oid)::bigint AS total_size_bytes
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE c.relkind IN ('r', 'm')
     AND n.nspname NOT IN ('pg_catalog', 'information_schema')
     AND n.nspname NOT LIKE 'pg_toast%'
   ORDER BY pg_total_relation_size(c.oid) DESC
   LIMIT 50
)
SELECT COALESCE(json_agg(b ORDER BY b.total_size_bytes DESC), '[]'::json)::text
  FROM (
    SELECT l.schema_name, l.table_name, l.total_size_bytes,
           stats.dead_tuple_len::bigint AS dead_bytes,
           stats.dead_tuple_percent::float8 AS dead_percent,
           stats.approx_free_space::bigint AS free_bytes,
           stats.approx_free_percent::float8 AS free_percent
      FROM largest l
      CROSS JOIN LATERAL pgstattuple_approx(l.oid) stats
  ) b`

func newPostgresDiagnosticsCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newPostgresDiagnosticsCheckWithFactory(cfg, defaultPgxPoolFactory)
}

func newPostgresDiagnosticsCheckWithFactory(cfg *collectorv1.CheckConfig, factory pgxPoolFactory) (Check, error) {
	pool, err := openPostgresPool(cfg, factory, "postgres.diagnostics")
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	normalizeDatabaseMetricTags(cfg.GetParams(), tags)
	server := strings.TrimSpace(tags["db_server"])
	database := strings.TrimSpace(tags["db_name"])
	installationID, databaseID := databaseIdentity(cfg.GetParams(), tags)
	if server == "" || database == "" {
		pool.Close()
		return nil, fmt.Errorf("postgres.diagnostics: static_tags.db_server e db_name obrigatórios")
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 15 * time.Second
	}
	id := strings.TrimSpace(cfg.GetCheckId())
	if id == "" {
		id = "postgres.diagnostics-" + cfg.GetHostId()
	}
	bloatEnabled, _ := strconv.ParseBool(cfg.GetParams()["bloat_enabled"])
	return &postgresDiagnostics{
		id: id, interval: interval, hostID: cfg.GetHostId(), dbServer: server, dbName: database,
		installationID: installationID, databaseID: databaseID,
		bloatEnabled: bloatEnabled, staticTags: tags, pool: pool,
	}, nil
}

func (c *postgresDiagnostics) ID() string              { return c.id }
func (c *postgresDiagnostics) Interval() time.Duration { return c.interval }
func (c *postgresDiagnostics) Tags() map[string]string { return c.staticTags }

func (c *postgresDiagnostics) Close() error {
	if c.pool != nil {
		c.pool.Close()
	}
	return nil
}

// Run é mantido para consumidores da interface Check. O scheduler identifica
// DiagnosticsCheck e chama RunDiagnostics diretamente, evitando duas leituras.
func (c *postgresDiagnostics) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunDiagnostics(ctx)
	return nil, err
}

func (c *postgresDiagnostics) RunDiagnostics(ctx context.Context) (*DatabaseDiagnostics, error) {
	out := &DatabaseDiagnostics{
		InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.dbServer, DBName: c.dbName, BloatEnabled: c.bloatEnabled,
		Capabilities: map[string]string{}, Sessions: []DatabaseSession{}, Blocking: []DatabaseBlocking{},
		Waits: []DatabaseWait{}, Bloat: []DatabaseBloat{}, Errors: []string{},
	}

	read := func(name, query string, target any) bool {
		qctx, cancel := context.WithTimeout(ctx, postgresDiagnosticsQueryTimeout)
		defer cancel()
		var raw string
		if err := c.pool.QueryRow(qctx, query).Scan(&raw); err != nil {
			log.Printf("postgres.diagnostics[%s]: %s failed: %v", c.id, name, err)
			out.Capabilities[name] = "unavailable"
			out.Errors = append(out.Errors, truncateDiagnosticsError(name+": "+err.Error()))
			return false
		}
		if err := json.Unmarshal([]byte(raw), target); err != nil {
			out.Capabilities[name] = "unavailable"
			out.Errors = append(out.Errors, truncateDiagnosticsError(name+": resposta inválida"))
			return false
		}
		out.Capabilities[name] = "available"
		return true
	}

	read("sessions", sqlPostgresDiagnosticSessions, &out.Sessions)
	read("blocking", sqlPostgresDiagnosticBlocking, &out.Blocking)
	read("waits", sqlPostgresDiagnosticWaits, &out.Waits)
	if c.bloatEnabled {
		read("bloat", sqlPostgresDiagnosticBloat, &out.Bloat)
	} else {
		out.Capabilities["bloat"] = "disabled"
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func truncateDiagnosticsError(value string) string {
	if len(value) > 1024 {
		return value[:1024]
	}
	return value
}

func init() {
	Default.Register("postgres.diagnostics", newPostgresDiagnosticsCheck)
}
