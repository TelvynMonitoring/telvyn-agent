// mssql_server.go coleta a saúde operacional de Microsoft SQL Server.
//
// As DMVs de atividade exigem VIEW SERVER STATE. Quando essa permissão não é
// concedida, o check preserva os indicadores que o login ainda consegue ler e
// não substitui a ausência por zero. Isso deixa o portal distinguir "sem
// telemetria" de "não há problema".
package checks

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/microsoft/go-mssqldb"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	sqlMSSQLActiveConnections = `SELECT COUNT_BIG(*) FROM sys.dm_exec_requests WHERE session_id <> @@SPID`
	sqlMSSQLTotalConnections  = `SELECT COUNT_BIG(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1`
	sqlMSSQLMaxConnections    = `SELECT CAST(@@MAX_CONNECTIONS AS bigint)`
	sqlMSSQLCacheHitRatio     = `SELECT TOP (1)
  CAST(hit.cntr_value AS float) / NULLIF(CAST(base.cntr_value AS float), 0)
  FROM sys.dm_os_performance_counters hit
  JOIN sys.dm_os_performance_counters base
    ON base.object_name = hit.object_name
   AND base.counter_name = 'Buffer cache hit ratio base'
 WHERE hit.counter_name = 'Buffer cache hit ratio'
 ORDER BY hit.object_name`
	sqlMSSQLSlowQueries = `SELECT COUNT_BIG(*) FROM sys.dm_exec_requests
 WHERE session_id <> @@SPID AND total_elapsed_time >= 1000`
	// Batch Requests/sec já é uma taxa calculada pelo SQL Server. Não a
	// chamamos de commit/rollback cumulativo, porque isso faria rate() no
	// backend produzir um segundo derivado incorreto.
	sqlMSSQLBatchRequestsPerSecond = `SELECT TOP (1) CAST(cntr_value AS float)
  FROM sys.dm_os_performance_counters
 WHERE counter_name = 'Batch Requests/sec'
 ORDER BY object_name`
	sqlMSSQLLocksWaiting = `SELECT COUNT_BIG(*) FROM sys.dm_os_waiting_tasks
 WHERE wait_type LIKE 'LCK[_]%'`
	sqlMSSQLDatabaseSize = `SELECT COALESCE(SUM(CAST(size AS bigint)) * 8192, 0)
  FROM sys.database_files`
	// A réplica primária normalmente não devolve linha útil. NULL é mantido
	// como ausência, para não apresentar "0 s" como se fosse uma medição.
	sqlMSSQLReplicationLag = `SELECT MAX(CASE
  WHEN synchronization_state_desc = 'SYNCHRONIZED' THEN CAST(0 AS bigint)
  WHEN last_hardened_time IS NULL THEN NULL
  ELSE DATEDIFF_BIG(SECOND, last_hardened_time, SYSUTCDATETIME())
 END)
 FROM sys.dm_hadr_database_replica_states
 WHERE is_local = 1`
)

var defaultMSSQLPoolFactory = defaultSQLDatabasePoolFactory("sqlserver")

type mssqlServer struct {
	id         string
	interval   time.Duration
	hostID     string
	staticTags map[string]string
	pool       sqlDatabasePool
}

func newMSSQLServerCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newMSSQLServerCheckWithFactory(cfg, defaultMSSQLPoolFactory)
}

func newMSSQLServerCheckWithFactory(cfg *collectorv1.CheckConfig, factory sqlDatabasePoolFactory) (Check, error) {
	pool, err := openSQLDatabasePool(cfg, factory, "mssql.server")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 60 * time.Second
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "mssql.server-" + cfg.GetHostId()
	}
	tags := make(map[string]string, len(cfg.GetStaticTags())+1)
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	if tags["db_engine"] == "" {
		tags["db_engine"] = "mssql"
	}
	return &mssqlServer{id: id, interval: interval, hostID: cfg.GetHostId(), staticTags: tags, pool: pool}, nil
}

func (c *mssqlServer) ID() string              { return c.id }
func (c *mssqlServer) Interval() time.Duration { return c.interval }
func (c *mssqlServer) Tags() map[string]string { return c.staticTags }

func (c *mssqlServer) Close() error {
	if c.pool == nil {
		return nil
	}
	return c.pool.Close()
}

func (c *mssqlServer) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	now := timestamppb.Now()
	out := make([]*collectorv1.Metric, 0, 9)
	succeeded := 0

	queryInt64 := func(query string) (int64, bool) {
		qctx, cancel := context.WithTimeout(ctx, sqlDatabaseQueryTimeout)
		defer cancel()
		var value int64
		if err := c.pool.QueryRow(qctx, query).Scan(&value); err != nil {
			log.Printf("mssql.server[%s]: query failed: %v", c.id, err)
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
			log.Printf("mssql.server[%s]: query failed: %v", c.id, err)
			return 0, false
		}
		if !value.Valid {
			return 0, false
		}
		succeeded++
		return value.Float64, true
	}

	if value, ok := queryInt64(sqlMSSQLActiveConnections); ok {
		out = append(out, c.metric(now, "mssql.active_connections", float64(value)))
	}
	if value, ok := queryInt64(sqlMSSQLTotalConnections); ok {
		out = append(out, c.metric(now, "mssql.total_connections", float64(value)))
	}
	if value, ok := queryInt64(sqlMSSQLMaxConnections); ok {
		out = append(out, c.metric(now, "mssql.max_connections", float64(value)))
	}
	if value, ok := queryFloat64(sqlMSSQLCacheHitRatio); ok {
		out = append(out, c.metric(now, "mssql.cache_hit_ratio", value))
	}
	if value, ok := queryInt64(sqlMSSQLSlowQueries); ok {
		out = append(out, c.metric(now, "mssql.slow_queries", float64(value)))
	}
	if value, ok := queryFloat64(sqlMSSQLBatchRequestsPerSecond); ok {
		out = append(out, c.metric(now, "mssql.batch_requests_per_second", value))
	}
	if value, ok := queryInt64(sqlMSSQLLocksWaiting); ok {
		out = append(out, c.metric(now, "mssql.locks_waiting", float64(value)))
	}
	if value, ok := queryInt64(sqlMSSQLDatabaseSize); ok {
		out = append(out, c.metric(now, "mssql.database_size_bytes", float64(value)))
	}
	if value, ok := queryFloat64(sqlMSSQLReplicationLag); ok {
		out = append(out, c.metric(now, "mssql.replication_lag_seconds", value))
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if succeeded == 0 {
		return nil, fmt.Errorf("mssql.server: nenhuma métrica pôde ser coletada")
	}
	return out, nil
}

func (c *mssqlServer) metric(timestamp *timestamppb.Timestamp, name string, value float64) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags))
	for key, tagValue := range c.staticTags {
		tags[key] = tagValue
	}
	return &collectorv1.Metric{
		Time: timestamp, HostId: c.hostID, MetricName: name, Value: value, Tags: tags, Source: "mssql.server",
	}
}

func init() {
	Default.Register("mssql.server", newMSSQLServerCheck)
}
