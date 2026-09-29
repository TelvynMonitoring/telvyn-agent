package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const sqlMSSQLDiagnosticSessions = `SELECT TOP (200) s.session_id, COALESCE(s.login_name,''),
 COALESCE(s.program_name,''), COALESCE(s.host_name,''),
 CASE WHEN s.status='sleeping' THEN 'idle' ELSE 'active' END,
 COALESCE(r.wait_type,''), COALESCE(r.last_wait_type,''),
 COALESCE(r.total_elapsed_time,0)
 FROM sys.dm_exec_sessions s LEFT JOIN sys.dm_exec_requests r ON r.session_id=s.session_id
 WHERE s.is_user_process=1 AND s.session_id<>@@SPID
 ORDER BY s.session_id`

const sqlMSSQLDiagnosticBlocking = `SELECT TOP (200) r.session_id, r.blocking_session_id,
 COALESCE(s.login_name,''), COALESCE(b.login_name,'')
 FROM sys.dm_exec_requests r
 LEFT JOIN sys.dm_exec_sessions s ON s.session_id=r.session_id
 LEFT JOIN sys.dm_exec_sessions b ON b.session_id=r.blocking_session_id
 WHERE r.database_id=DB_ID() AND r.blocking_session_id>0
 ORDER BY r.total_elapsed_time DESC`

const sqlMSSQLDiagnosticWaits = `SELECT TOP (200) COALESCE(wait_type,'running'), COUNT_BIG(*)
 FROM sys.dm_exec_requests WHERE database_id=DB_ID() AND session_id<>@@SPID
 GROUP BY wait_type ORDER BY COUNT_BIG(*) DESC`

const sqlMSSQLDiagnosticReplicas = `SELECT TOP (200) ar.replica_server_name,
 COALESCE(drs.synchronization_state_desc,''), COALESCE(ar.availability_mode_desc,''),
 COALESCE(DATEDIFF(second,drs.last_commit_time,primary_replica.last_commit_time),-1)
 FROM sys.dm_hadr_database_replica_states drs
 JOIN sys.availability_replicas ar ON ar.replica_id=drs.replica_id
 LEFT JOIN sys.dm_hadr_database_replica_states primary_replica
   ON primary_replica.group_database_id=drs.group_database_id AND primary_replica.is_primary_replica=1
 WHERE drs.database_id=DB_ID() AND drs.is_primary_replica=0
 ORDER BY ar.replica_server_name`

type mssqlDiagnostics struct {
	id, installationID, databaseID, server, database string
	interval                                         time.Duration
	tags                                             map[string]string
	pool                                             sqlDatabasePool
}

func newMSSQLDiagnosticsCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" {
		return nil, fmt.Errorf("mssql.diagnostics: installation_id e database_id obrigatórios")
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	server, database := strings.TrimSpace(tags["db_server"]), strings.TrimSpace(tags["db_name"])
	if server == "" || database == "" {
		return nil, fmt.Errorf("mssql.diagnostics: db_server e db_name obrigatórios")
	}
	pool, err := openSQLDatabasePool(cfg, defaultMSSQLPoolFactory, "mssql.diagnostics")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &mssqlDiagnostics{cfg.GetCheckId(), installationID, databaseID, server, database, interval, tags, pool}, nil
}

func (c *mssqlDiagnostics) ID() string              { return c.id }
func (c *mssqlDiagnostics) Interval() time.Duration { return c.interval }
func (c *mssqlDiagnostics) Tags() map[string]string { return c.tags }
func (c *mssqlDiagnostics) Close() error            { return c.pool.Close() }
func (c *mssqlDiagnostics) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunDiagnostics(ctx)
	return nil, err
}

func (c *mssqlDiagnostics) RunDiagnostics(ctx context.Context) (*DatabaseDiagnostics, error) {
	out := &DatabaseDiagnostics{
		Engine: "mssql", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, Capabilities: map[string]string{},
		Sessions: []DatabaseSession{}, Blocking: []DatabaseBlocking{}, Waits: []DatabaseWait{},
		Replicas: []DatabaseReplica{}, Bloat: []DatabaseBloat{},
		ReplicationSlots: []DatabaseReplicationSlot{}, MaintenanceOperations: []DatabaseMaintenanceOperation{},
		Errors: []string{},
	}
	read := func(name, query string, scan func(sqlDatabaseRows) error) {
		qctx, cancel := context.WithTimeout(ctx, sqlDatabaseQueryTimeout)
		defer cancel()
		rows, err := c.pool.Query(qctx, query)
		if err == nil {
			for rows.Next() {
				if err = scan(rows); err != nil {
					break
				}
			}
			if err == nil {
				err = rows.Err()
			}
			rows.Close()
		}
		if err != nil {
			out.Capabilities[name] = "unavailable"
			out.Errors = append(out.Errors, truncateDiagnosticsError(name+": "+err.Error()))
		} else {
			out.Capabilities[name] = "available"
		}
	}
	read("sessions", sqlMSSQLDiagnosticSessions, func(rows sqlDatabaseRows) error {
		var item DatabaseSession
		var elapsedMS int64
		if err := rows.Scan(&item.PID, &item.User, &item.Application, &item.Client,
			&item.State, &item.WaitType, &item.WaitEvent, &elapsedMS); err != nil {
			return err
		}
		item.DurationSeconds = float64(elapsedMS) / 1000
		out.Sessions = append(out.Sessions, item)
		return nil
	})
	read("blocking", sqlMSSQLDiagnosticBlocking, func(rows sqlDatabaseRows) error {
		var item DatabaseBlocking
		if err := rows.Scan(&item.BlockedPID, &item.BlockingPID, &item.BlockedUser, &item.BlockingUser); err != nil {
			return err
		}
		out.Blocking = append(out.Blocking, item)
		return nil
	})
	read("waits", sqlMSSQLDiagnosticWaits, func(rows sqlDatabaseRows) error {
		var item DatabaseWait
		item.WaitType = "request"
		if err := rows.Scan(&item.WaitEvent, &item.Count); err != nil {
			return err
		}
		out.Waits = append(out.Waits, item)
		return nil
	})
	read("replication", sqlMSSQLDiagnosticReplicas, func(rows sqlDatabaseRows) error {
		var item DatabaseReplica
		var lag int64
		if err := rows.Scan(&item.Identity, &item.State, &item.Mode, &lag); err != nil {
			return err
		}
		if lag >= 0 {
			value := float64(lag)
			item.ReplayLagSeconds = &value
		}
		out.Replicas = append(out.Replicas, item)
		return nil
	})
	for _, name := range []string{"bloat", "wraparound", "wal", "replication_slots"} {
		out.Capabilities[name] = "unsupported"
	}
	if out.Capabilities["sessions"] != "available" && out.Capabilities["waits"] != "available" {
		return nil, fmt.Errorf("mssql.diagnostics: sessões e esperas indisponíveis")
	}
	return out, nil
}

func init() { Default.Register("mssql.diagnostics", newMSSQLDiagnosticsCheck) }
