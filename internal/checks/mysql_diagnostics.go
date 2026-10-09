package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const sqlMySQLDiagnosticSessions = `SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
 'pid', ID, 'user', COALESCE(USER,''), 'application', '',
 'client', COALESCE(HOST,''), 'state', CASE WHEN COMMAND='Sleep' THEN 'idle' ELSE 'active' END,
 'wait_type', '', 'wait_event', COALESCE(STATE,''),
 'duration_seconds', TIME)), JSON_ARRAY())
 FROM (SELECT ID, USER, HOST, COMMAND, STATE, TIME
       FROM information_schema.PROCESSLIST WHERE ID <> CONNECTION_ID()
       ORDER BY TIME DESC LIMIT 200) p`

const sqlMySQLDiagnosticWaits = `SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
 'wait_type', 'server', 'wait_event', wait_event, 'count', total)), JSON_ARRAY())
 FROM (SELECT COALESCE(STATE,'running') AS wait_event, COUNT(*) AS total
       FROM information_schema.PROCESSLIST WHERE ID <> CONNECTION_ID() AND COMMAND <> 'Sleep'
       GROUP BY STATE ORDER BY total DESC LIMIT 200) w`

const sqlMySQLDiagnosticBlocking = `SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
 'blocked_pid', COALESCE(requested.PROCESSLIST_ID,0), 'blocking_pid', COALESCE(blocker.PROCESSLIST_ID,0),
 'blocked_user', '', 'blocking_user', '')), JSON_ARRAY())
 FROM (SELECT REQUESTING_THREAD_ID, BLOCKING_THREAD_ID
       FROM performance_schema.data_lock_waits LIMIT 200) b
 LEFT JOIN performance_schema.threads requested ON requested.THREAD_ID=b.REQUESTING_THREAD_ID
 LEFT JOIN performance_schema.threads blocker ON blocker.THREAD_ID=b.BLOCKING_THREAD_ID`

const sqlMariaDBDiagnosticBlocking = `SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
 'blocked_pid', requested.trx_mysql_thread_id, 'blocking_pid', blocker.trx_mysql_thread_id,
 'blocked_user', '', 'blocking_user', '')), JSON_ARRAY())
 FROM (SELECT requesting_trx_id, blocking_trx_id
       FROM information_schema.INNODB_LOCK_WAITS LIMIT 200) b
 JOIN information_schema.INNODB_TRX requested ON requested.trx_id=b.requesting_trx_id
 JOIN information_schema.INNODB_TRX blocker ON blocker.trx_id=b.blocking_trx_id`

const sqlMySQLDiagnosticReplicas = `SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
 'identity', CHANNEL_NAME, 'user', '', 'client', '',
 'state', SERVICE_STATE, 'mode', 'async',
 'sent_lsn', '', 'write_lsn', '', 'flush_lsn', '', 'replay_lsn', '')), JSON_ARRAY())
 FROM (SELECT CHANNEL_NAME, SERVICE_STATE
       FROM performance_schema.replication_connection_status LIMIT 200) r`

type mysqlDiagnostics struct {
	id, installationID, databaseID, server, database string
	interval                                         time.Duration
	tags                                             map[string]string
	pool                                             sqlDatabasePool
}

func newMySQLDiagnosticsCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newMySQLDiagnosticsCheckWithFactory(cfg, defaultMySQLPoolFactory)
}

func newMySQLDiagnosticsCheckWithFactory(cfg *collectorv1.CheckConfig, factory sqlDatabasePoolFactory) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" {
		return nil, fmt.Errorf("mysql.diagnostics: installation_id e database_id obrigatórios")
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	server, database := strings.TrimSpace(tags["db_server"]), strings.TrimSpace(tags["db_name"])
	if server == "" || database == "" {
		return nil, fmt.Errorf("mysql.diagnostics: db_server e db_name obrigatórios")
	}
	pool, err := openSQLDatabasePool(cfg, factory, "mysql.diagnostics")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &mysqlDiagnostics{cfg.GetCheckId(), installationID, databaseID, server, database, interval, tags, pool}, nil
}

func (c *mysqlDiagnostics) ID() string              { return c.id }
func (c *mysqlDiagnostics) Interval() time.Duration { return c.interval }
func (c *mysqlDiagnostics) Tags() map[string]string { return c.tags }
func (c *mysqlDiagnostics) Close() error            { return c.pool.Close() }
func (c *mysqlDiagnostics) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunDiagnostics(ctx)
	return nil, err
}

func (c *mysqlDiagnostics) RunDiagnostics(ctx context.Context) (*DatabaseDiagnostics, error) {
	out := &DatabaseDiagnostics{
		Engine: "mysql", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, Capabilities: map[string]string{},
		Sessions: []DatabaseSession{}, Blocking: []DatabaseBlocking{}, Waits: []DatabaseWait{},
		Replicas: []DatabaseReplica{}, Bloat: []DatabaseBloat{},
		ReplicationSlots: []DatabaseReplicationSlot{}, MaintenanceOperations: []DatabaseMaintenanceOperation{},
		Errors: []string{},
	}
	read := func(name, query string, target any) {
		qctx, cancel := context.WithTimeout(ctx, sqlDatabaseQueryTimeout)
		defer cancel()
		var raw string
		if err := c.pool.QueryRow(qctx, query).Scan(&raw); err != nil {
			out.Capabilities[name] = "unavailable"
			out.Errors = append(out.Errors, truncateDiagnosticsError(name+": "+err.Error()))
			return
		}
		if err := json.Unmarshal([]byte(raw), target); err != nil {
			out.Capabilities[name] = "unavailable"
			out.Errors = append(out.Errors, name+": resposta inválida")
			return
		}
		out.Capabilities[name] = "available"
	}
	read("sessions", sqlMySQLDiagnosticSessions, &out.Sessions)
	read("waits", sqlMySQLDiagnosticWaits, &out.Waits)
	var version string
	versionCtx, cancel := context.WithTimeout(ctx, sqlDatabaseQueryTimeout)
	_ = c.pool.QueryRow(versionCtx, "SELECT VERSION()").Scan(&version)
	cancel()
	if strings.Contains(strings.ToLower(version), "mariadb") {
		read("blocking", sqlMariaDBDiagnosticBlocking, &out.Blocking)
		replicas, err := mariaDBReplicaStatuses(ctx, c.pool)
		if err != nil {
			out.Capabilities["replication"] = "unavailable"
			out.Errors = append(out.Errors, truncateDiagnosticsError("replication: "+err.Error()))
		} else {
			out.Capabilities["replication"] = "available"
			out.Replicas = append(out.Replicas, replicas...)
		}
	} else {
		read("blocking", sqlMySQLDiagnosticBlocking, &out.Blocking)
		read("replication", sqlMySQLDiagnosticReplicas, &out.Replicas)
	}
	out.Capabilities["bloat"] = "unsupported"
	out.Capabilities["wraparound"] = "unsupported"
	out.Capabilities["wal"] = "unsupported"
	if out.Capabilities["sessions"] != "available" && out.Capabilities["waits"] != "available" {
		return nil, fmt.Errorf("mysql.diagnostics: sessões e esperas indisponíveis")
	}
	return out, nil
}

func init() { Default.Register("mysql.diagnostics", newMySQLDiagnosticsCheck) }
