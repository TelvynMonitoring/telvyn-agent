// mysql_server.go coleta a saúde operacional de uma instância MySQL 8+.
//
// Métricas comuns aos engines do portal: conexões, cache, queries lentas,
// locks, volume, réplica e contadores de transação. Consultas que dependem de
// performance_schema são best-effort: uma permissão ausente não derruba as
// métricas básicas nem cria valores fictícios.
package checks

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	sqlMySQLActiveConnections = `SELECT CAST(VARIABLE_VALUE AS SIGNED)
  FROM performance_schema.global_status WHERE VARIABLE_NAME = 'Threads_running'`
	sqlMySQLTotalConnections = `SELECT CAST(VARIABLE_VALUE AS SIGNED)
  FROM performance_schema.global_status WHERE VARIABLE_NAME = 'Threads_connected'`
	sqlMySQLMaxConnections = `SELECT @@GLOBAL.max_connections`
	sqlMySQLCacheHitRatio  = `SELECT 1 -
  (CAST(MAX(CASE WHEN VARIABLE_NAME = 'Innodb_buffer_pool_reads' THEN VARIABLE_VALUE END) AS DECIMAL(30,6)) /
   NULLIF(CAST(MAX(CASE WHEN VARIABLE_NAME = 'Innodb_buffer_pool_read_requests' THEN VARIABLE_VALUE END) AS DECIMAL(30,6)), 0))
  FROM performance_schema.global_status
 WHERE VARIABLE_NAME IN ('Innodb_buffer_pool_reads', 'Innodb_buffer_pool_read_requests')`
	sqlMySQLSlowQueries = `SELECT COUNT(*) FROM information_schema.processlist
 WHERE COMMAND <> 'Sleep' AND TIME >= 1`
	sqlMySQLCommits = `SELECT CAST(VARIABLE_VALUE AS SIGNED)
  FROM performance_schema.global_status WHERE VARIABLE_NAME = 'Com_commit'`
	sqlMySQLRollbacks = `SELECT CAST(VARIABLE_VALUE AS SIGNED)
  FROM performance_schema.global_status WHERE VARIABLE_NAME = 'Com_rollback'`
	sqlMySQLLocksWaiting = `SELECT COUNT(*) FROM performance_schema.data_lock_waits`
	sqlMySQLDatabaseSize = `SELECT COALESCE(SUM(data_length + index_length), 0)
  FROM information_schema.tables WHERE table_schema = DATABASE()`
	// Em primary ou em instância sem replication workers, a expressão retorna
	// NULL. Isso vira ausência de métrica, e não o ambíguo "lag zero".
	sqlMySQLReplicationLag = `SELECT MAX(GREATEST(TIMESTAMPDIFF(SECOND,
  LAST_APPLIED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP, NOW()), 0))
  FROM performance_schema.replication_applier_status_by_worker
 WHERE SERVICE_STATE = 'ON'`
)

var defaultMySQLPoolFactory = defaultSQLDatabasePoolFactory("mysql")

type mysqlServer struct {
	id         string
	interval   time.Duration
	hostID     string
	staticTags map[string]string
	pool       sqlDatabasePool
}

func newMySQLServerCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newMySQLServerCheckWithFactory(cfg, defaultMySQLPoolFactory)
}

func newMySQLServerCheckWithFactory(cfg *collectorv1.CheckConfig, factory sqlDatabasePoolFactory) (Check, error) {
	pool, err := openSQLDatabasePool(cfg, factory, "mysql.server")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 60 * time.Second
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "mysql.server-" + cfg.GetHostId()
	}
	tags := make(map[string]string, len(cfg.GetStaticTags())+1)
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	if tags["db_engine"] == "" {
		tags["db_engine"] = "mysql"
	}
	return &mysqlServer{id: id, interval: interval, hostID: cfg.GetHostId(), staticTags: tags, pool: pool}, nil
}

func (c *mysqlServer) ID() string              { return c.id }
func (c *mysqlServer) Interval() time.Duration { return c.interval }
func (c *mysqlServer) Tags() map[string]string { return c.staticTags }

func (c *mysqlServer) Close() error {
	if c.pool == nil {
		return nil
	}
	return c.pool.Close()
}

func (c *mysqlServer) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	now := timestamppb.Now()
	out := make([]*collectorv1.Metric, 0, 10)
	succeeded := 0

	queryInt64 := func(query string) (int64, bool) {
		qctx, cancel := context.WithTimeout(ctx, sqlDatabaseQueryTimeout)
		defer cancel()
		var value int64
		if err := c.pool.QueryRow(qctx, query).Scan(&value); err != nil {
			log.Printf("mysql.server[%s]: query failed: %v", c.id, err)
			return 0, false
		}
		succeeded++
		return value, true
	}
	queryFloat64 := func(query string) (float64, bool) {
		qctx, cancel := context.WithTimeout(ctx, sqlDatabaseQueryTimeout)
		defer cancel()
		var value sql.NullFloat64
		if err := c.pool.QueryRow(qctx, query).Scan(&value); err != nil {
			log.Printf("mysql.server[%s]: query failed: %v", c.id, err)
			return 0, false
		}
		if !value.Valid {
			return 0, false
		}
		succeeded++
		return value.Float64, true
	}

	if value, ok := queryInt64(sqlMySQLActiveConnections); ok {
		out = append(out, c.metric(now, "mysql.active_connections", float64(value)))
	}
	if value, ok := queryInt64(sqlMySQLTotalConnections); ok {
		out = append(out, c.metric(now, "mysql.total_connections", float64(value)))
	}
	if value, ok := queryInt64(sqlMySQLMaxConnections); ok {
		out = append(out, c.metric(now, "mysql.max_connections", float64(value)))
	}
	if value, ok := queryFloat64(sqlMySQLCacheHitRatio); ok {
		out = append(out, c.metric(now, "mysql.cache_hit_ratio", value))
	}
	if value, ok := queryInt64(sqlMySQLSlowQueries); ok {
		out = append(out, c.metric(now, "mysql.slow_queries", float64(value)))
	}
	if value, ok := queryInt64(sqlMySQLCommits); ok {
		out = append(out, c.metric(now, "mysql.commits", float64(value)))
	}
	if value, ok := queryInt64(sqlMySQLRollbacks); ok {
		out = append(out, c.metric(now, "mysql.rollbacks", float64(value)))
	}
	if value, ok := queryInt64(sqlMySQLLocksWaiting); ok {
		out = append(out, c.metric(now, "mysql.locks_waiting", float64(value)))
	}
	if value, ok := queryInt64(sqlMySQLDatabaseSize); ok {
		out = append(out, c.metric(now, "mysql.database_size_bytes", float64(value)))
	}
	if value, ok := queryFloat64(sqlMySQLReplicationLag); ok {
		out = append(out, c.metric(now, "mysql.replication_lag_seconds", value))
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if succeeded == 0 {
		return nil, fmt.Errorf("mysql.server: nenhuma métrica pôde ser coletada")
	}
	return out, nil
}

func (c *mysqlServer) metric(timestamp *timestamppb.Timestamp, name string, value float64) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags))
	for key, tagValue := range c.staticTags {
		tags[key] = tagValue
	}
	return &collectorv1.Metric{
		Time: timestamp, HostId: c.hostID, MetricName: name, Value: value, Tags: tags, Source: "mysql.server",
	}
}

func init() {
	Default.Register("mysql.server", newMySQLServerCheck)
}
