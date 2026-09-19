// postgres_server.go — Check "postgres.server" implementação contínua.
//
// Coleta métricas de saúde de um Postgres local/remoto via libpq (pgx/v5):
//   - postgres.active_connections      — current_database, state='active'
//   - postgres.idle_in_transaction     — state='idle in transaction'
//   - postgres.slow_queries            — active queries com query_start > 1s atrás
//   - postgres.replication_lag_seconds — NOW() - pg_last_xact_replay_timestamp()
//   - postgres.wal_lag_bytes           — pg_wal_lsn_diff(receive_lsn, replay_lsn)
//   - postgres.vacuum_stale_tables     — tabelas sem autovacuum há 24h+
//   - postgres.total_connections       — todas as conexões do database atual
//   - postgres.max_connections         — pg_settings max_connections (saturação)
//   - postgres.cache_hit_ratio         — blks_hit / (blks_hit + blks_read), 0..1
//   - postgres.deadlocks               — pg_stat_database.deadlocks (cumulativo)
//   - postgres.commits                 — pg_stat_database.xact_commit (cumulativo)
//   - postgres.rollbacks               — pg_stat_database.xact_rollback (cumulativo)
//   - postgres.locks_waiting           — pg_locks NOT granted (contenção)
//   - postgres.database_size_bytes     — pg_database_size(current_database())
//
// Tudo via views nativas (pg_stat_*, pg_locks, pg_settings) — não exige a
// extensão pg_stat_statements nem permissões além de leitura.
//
// Pool config (RESEARCH §Pitfall 5 mitigation): MaxConns=2, MinConns=0,
// Ping no factory; falha → pool.Close() + return err (no leak).
//
// Replication lag em primary retorna NULL (Pitfall 3): SQL usa COALESCE
// para coercir 0.
//
// Compatível com framework Phase 2 (checks.Check + Registry + Runtime).
package checks

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shirou/gopsutil/v4/disk"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	postgresQueryTimeout = 5 * time.Second
	postgresPingTimeout  = 3 * time.Second
	postgresMaxConns     = int32(2)
	postgresMinConns     = int32(0)
)

// pgxPool abstrai o subset de *pgxpool.Pool que postgres.server consome.
// Existe pra permitir mock em unit test (mesma técnica do snmpGenericRunner).
type pgxPool interface {
	Ping(ctx context.Context) error
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Close()
}

// pgxPoolFactory constrói um pgxPool a partir de uma DSN. Em prod aponta
// pra defaultPgxPoolFactory (pgxpool.NewWithConfig). Em test, pra stub.
type pgxPoolFactory func(ctx context.Context, dsn string) (pgxPool, error)

// defaultPgxPoolFactory cria um pool real via pgxpool.NewWithConfig.
// Aplica MaxConns=2, MinConns=0. O Ping é responsabilidade do caller
// (newPostgresServerCheckWithFactory) — isso permite que stub factories
// retornem um pool "pronto" sem precisar simular Ping internamente, e
// move o "fechar em fail" para um único site (Pitfall 5).
var defaultPgxPoolFactory pgxPoolFactory = func(ctx context.Context, dsn string) (pgxPool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("DSN inválido: %w", err)
	}
	poolCfg.MaxConns = postgresMaxConns
	poolCfg.MinConns = postgresMinConns

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("pool: %w", err)
	}
	return &realPgxPool{p: pool}, nil
}

// realPgxPool wrap *pgxpool.Pool pra casar com a interface pgxPool.
// (Pool.QueryRow já retorna pgx.Row e Pool.Close já é void — só satisfaz.)
type realPgxPool struct{ p *pgxpool.Pool }

func (r *realPgxPool) Ping(ctx context.Context) error { return r.p.Ping(ctx) }
func (r *realPgxPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return r.p.QueryRow(ctx, sql, args...)
}
func (r *realPgxPool) Close() { r.p.Close() }

// postgresServer é a implementação concreta de Check para "postgres.server".
type postgresServer struct {
	id         string
	interval   time.Duration
	hostID     string
	staticTags map[string]string
	pool       pgxPool
}

// SQL queries (RESEARCH §Pattern 4 — Pitfall 3 mitigation via COALESCE).
const (
	sqlActiveConnections = `SELECT count(*)::BIGINT FROM pg_stat_activity ` +
		`WHERE datname = current_database() AND state = 'active'`

	sqlIdleInTransaction = `SELECT count(*)::BIGINT FROM pg_stat_activity ` +
		`WHERE state = 'idle in transaction' AND datname = current_database()`

	sqlSlowQueries = `SELECT count(*)::BIGINT FROM pg_stat_activity ` +
		`WHERE state = 'active' AND query_start < NOW() - INTERVAL '1 second' ` +
		`AND datname = current_database()`

	sqlReplicationLagSeconds = `SELECT ` +
		`COALESCE(EXTRACT(EPOCH FROM (NOW() - pg_last_xact_replay_timestamp())), 0)::FLOAT8`

	sqlWalLagBytes = `SELECT ` +
		`COALESCE(pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()), 0)::BIGINT`

	sqlVacuumStaleTables = `SELECT count(*)::BIGINT FROM pg_stat_user_tables ` +
		`WHERE last_autovacuum < NOW() - INTERVAL '24 hours' OR last_autovacuum IS NULL`

	sqlTotalConnections = `SELECT count(*)::BIGINT FROM pg_stat_activity ` +
		`WHERE datname = current_database()`

	sqlMaxConnections = `SELECT setting::BIGINT FROM pg_settings WHERE name = 'max_connections'`

	sqlCacheHitRatio = `SELECT ` +
		`COALESCE(sum(blks_hit)::FLOAT8 / NULLIF(sum(blks_hit) + sum(blks_read), 0), 1)::FLOAT8 ` +
		`FROM pg_stat_database WHERE datname = current_database()`

	sqlDeadlocks = `SELECT COALESCE(deadlocks, 0)::BIGINT ` +
		`FROM pg_stat_database WHERE datname = current_database()`

	sqlCommits = `SELECT COALESCE(xact_commit, 0)::BIGINT ` +
		`FROM pg_stat_database WHERE datname = current_database()`

	sqlRollbacks = `SELECT COALESCE(xact_rollback, 0)::BIGINT ` +
		`FROM pg_stat_database WHERE datname = current_database()`

	sqlLocksWaiting = `SELECT count(*)::BIGINT FROM pg_locks WHERE NOT granted`

	sqlDatabaseSize = `SELECT pg_database_size(current_database())::BIGINT`

	// Contadores por database. O backend calcula o aumento na janela e nunca
	// apresenta o valor acumulado desde o último reset como consumo recente.
	sqlTempBytes = `SELECT COALESCE(temp_bytes, 0)::BIGINT ` +
		`FROM pg_stat_database WHERE datname = current_database()`

	sqlTempFiles = `SELECT COALESCE(temp_files, 0)::BIGINT ` +
		`FROM pg_stat_database WHERE datname = current_database()`

	// SHOW data_directory existe em todas as versões PostgreSQL suportadas. O
	// stat do filesystem é local ao Agent: se o collector estiver remoto ou não
	// puder acessar o caminho, as três métricas simplesmente não são emitidas.
	sqlDataDirectory = `SHOW data_directory`

	// Tempo desde o último boot do processo PostgreSQL. É uma medida do
	// servidor, não do banco lógico, mas a mesma instância pode atender vários
	// bancos e a informação é útil para correlacionar resets de contadores.
	sqlUptimeSeconds = `SELECT EXTRACT(EPOCH FROM (now() - pg_postmaster_start_time()))::FLOAT8`
)

// newPostgresServerCheck é a Factory pública registrada em init() para
// "postgres.server". Delega pra ...WithFactory usando defaultPgxPoolFactory.
func newPostgresServerCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newPostgresServerCheckWithFactory(cfg, defaultPgxPoolFactory)
}

// newPostgresServerCheckWithFactory permite injetar um pool factory em test
// (stub que não abre conexão TCP) ou em prod (defaultPgxPoolFactory).
func newPostgresServerCheckWithFactory(cfg *collectorv1.CheckConfig, factory pgxPoolFactory) (Check, error) {
	pool, err := openPostgresPool(cfg, factory, "postgres.server")
	if err != nil {
		return nil, err
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 60 * time.Second
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "postgres.server-" + cfg.GetHostId()
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}
	// O backend fornece IDs imutáveis para o Agent de Banco por instância. Eles
	// seguem nas séries OTLP para que a ingestão valide o filho lógico, sem
	// confiar em db_server/db_name fornecidos pelo processo.
	normalizeDatabaseMetricTags(cfg.GetParams(), tags)

	return &postgresServer{
		id:         id,
		interval:   interval,
		hostID:     cfg.GetHostId(),
		staticTags: tags,
		pool:       pool,
	}, nil
}

// openPostgresPool centraliza a validação do DSN e do reachability para os
// checks PostgreSQL. Cada check recebe o próprio pool: uma extensão ausente
// não derruba o check de saúde.
func openPostgresPool(cfg *collectorv1.CheckConfig, factory pgxPoolFactory, kind string) (pgxPool, error) {
	dsn := cfg.GetParams()["dsn"]
	if dsn == "" {
		return nil, fmt.Errorf("%s: param 'dsn' obrigatório", kind)
	}
	pool, err := factory(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), postgresPingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("%s: unreachable: %w", kind, err)
	}
	return pool, nil
}

func (c *postgresServer) ID() string              { return c.id }
func (c *postgresServer) Interval() time.Duration { return c.interval }
func (c *postgresServer) Tags() map[string]string { return c.staticTags }

// Close libera o pool pgx. Idempotente — chamadas redundantes são absorvidas
// por pgxpool.Pool.Close (no panic em double-close); a guarda extra fica no
// stubPgxPool dos tests.
func (c *postgresServer) Close() error {
	if c.pool != nil {
		c.pool.Close()
	}
	return nil
}

// Run executa as queries sequencialmente (pra preservar pool MaxConns=2 sem
// contenção) e emite até 15 métricas. Best-effort: erro em uma query
// individual loga e segue — outras métricas ainda são emitidas. Erro só é
// retornado se ctx cancelar.
func (c *postgresServer) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	now := timestamppb.Now()
	out := make([]*collectorv1.Metric, 0, 20)

	queryInt64 := func(sql string) (int64, bool) {
		qctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
		defer cancel()
		var v int64
		if err := c.pool.QueryRow(qctx, sql).Scan(&v); err != nil {
			log.Printf("postgres.server[%s]: query failed: %v", c.id, err)
			return 0, false
		}
		return v, true
	}
	queryFloat64 := func(sql string) (float64, bool) {
		qctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
		defer cancel()
		var v float64
		if err := c.pool.QueryRow(qctx, sql).Scan(&v); err != nil {
			log.Printf("postgres.server[%s]: query failed: %v", c.id, err)
			return 0, false
		}
		return v, true
	}

	if v, ok := queryInt64(sqlActiveConnections); ok {
		out = append(out, c.metric(now, "postgres.active_connections", float64(v)))
	}
	if v, ok := queryInt64(sqlIdleInTransaction); ok {
		out = append(out, c.metric(now, "postgres.idle_in_transaction", float64(v)))
	}
	if v, ok := queryInt64(sqlSlowQueries); ok {
		out = append(out, c.metric(now, "postgres.slow_queries", float64(v)))
	}
	if v, ok := queryFloat64(sqlReplicationLagSeconds); ok {
		out = append(out, c.metric(now, "postgres.replication_lag_seconds", v))
	}
	if v, ok := queryInt64(sqlWalLagBytes); ok {
		out = append(out, c.metric(now, "postgres.wal_lag_bytes", float64(v)))
	}
	if v, ok := queryInt64(sqlVacuumStaleTables); ok {
		out = append(out, c.metric(now, "postgres.vacuum_stale_tables", float64(v)))
	}
	if v, ok := queryInt64(sqlTotalConnections); ok {
		out = append(out, c.metric(now, "postgres.total_connections", float64(v)))
	}
	if v, ok := queryInt64(sqlMaxConnections); ok {
		out = append(out, c.metric(now, "postgres.max_connections", float64(v)))
	}
	if v, ok := queryFloat64(sqlCacheHitRatio); ok {
		out = append(out, c.metric(now, "postgres.cache_hit_ratio", v))
	}
	if v, ok := queryInt64(sqlDeadlocks); ok {
		out = append(out, c.metric(now, "postgres.deadlocks", float64(v)))
	}
	if v, ok := queryInt64(sqlCommits); ok {
		out = append(out, c.metric(now, "postgres.commits", float64(v)))
	}
	if v, ok := queryInt64(sqlRollbacks); ok {
		out = append(out, c.metric(now, "postgres.rollbacks", float64(v)))
	}
	if v, ok := queryInt64(sqlLocksWaiting); ok {
		out = append(out, c.metric(now, "postgres.locks_waiting", float64(v)))
	}
	if v, ok := queryInt64(sqlDatabaseSize); ok {
		out = append(out, c.metric(now, "postgres.database_size_bytes", float64(v)))
	}
	if v, ok := queryInt64(sqlTempBytes); ok {
		out = append(out, c.metric(now, "postgres.temp_bytes", float64(v)))
	}
	if v, ok := queryInt64(sqlTempFiles); ok {
		out = append(out, c.metric(now, "postgres.temp_files", float64(v)))
	}
	if dataDirectory, ok := queryString(c.pool, ctx, sqlDataDirectory); ok {
		if usage, err := disk.UsageWithContext(ctx, strings.TrimSpace(dataDirectory)); err == nil && usage.Total > 0 {
			out = append(out,
				c.metric(now, "postgres.storage_used_bytes", float64(usage.Used)),
				c.metric(now, "postgres.storage_total_bytes", float64(usage.Total)),
				c.metric(now, "postgres.storage_used_percent", usage.UsedPercent),
			)
		} else if err != nil {
			log.Printf("postgres.server[%s]: data directory filesystem unavailable: %v", c.id, err)
		}
	}
	if v, ok := queryFloat64(sqlUptimeSeconds); ok {
		out = append(out, c.metric(now, "postgres.uptime_seconds", v))
	}

	if err := ctx.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func queryString(pool pgxPool, ctx context.Context, sql string) (string, bool) {
	qctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()
	var value string
	if err := pool.QueryRow(qctx, sql).Scan(&value); err != nil {
		return "", false
	}
	return value, strings.TrimSpace(value) != ""
}

// metric constrói um Metric com staticTags do CheckConfig + Source fixo.
// (Sem extra per-metric tags — nome da métrica já carrega a dimensão.)
func (c *postgresServer) metric(t *timestamppb.Timestamp, name string, value float64) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags))
	for k, v := range c.staticTags {
		tags[k] = v
	}
	return &collectorv1.Metric{
		Time:       t,
		HostId:     c.hostID,
		MetricName: name,
		Value:      value,
		Tags:       tags,
		Source:     "postgres.server",
	}
}

// init auto-registra o factory em Default (mesmo pattern de icmp_ping e
// linux_system; ordering entre init()s não é determinístico em Go, mas o
// Registry usa last-wins semantics — ver check.go).
func init() {
	Default.Register("postgres.server", newPostgresServerCheck)
}
