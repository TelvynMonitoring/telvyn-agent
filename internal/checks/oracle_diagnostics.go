package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const sqlOracleDiagnosticSessions = `SELECT SID, NVL(USERNAME,' '), NVL(MODULE,' '),
 NVL(MACHINE,' '), NVL(STATUS,' '), NVL(WAIT_CLASS,' '), NVL(EVENT,' '),
 CASE WHEN STATUS='ACTIVE' THEN LAST_CALL_ET ELSE 0 END
 FROM V$SESSION WHERE TYPE='USER' AND ROWNUM<=200`

const sqlOracleDiagnosticBlocking = `SELECT SID, BLOCKING_SESSION,
 NVL(USERNAME,' '), NVL((SELECT USERNAME FROM V$SESSION b WHERE b.SID=s.BLOCKING_SESSION AND ROWNUM=1),' ')
 FROM V$SESSION s WHERE TYPE='USER' AND BLOCKING_SESSION>0 AND ROWNUM<=200`

const sqlOracleDiagnosticWaits = `SELECT WAIT_CLASS, EVENT, TOTAL FROM (
 SELECT WAIT_CLASS, EVENT, COUNT(*) AS TOTAL
 FROM V$SESSION WHERE TYPE='USER' AND STATUS='ACTIVE' AND WAIT_CLASS<>'Idle'
 GROUP BY WAIT_CLASS, EVENT ORDER BY TOTAL DESC) WHERE ROWNUM<=200`

const sqlOracleDiagnosticReplication = `SELECT NVL(SOURCE_DB_UNIQUE_NAME,'Data Guard'),NAME,VALUE
 FROM V$DATAGUARD_STATS WHERE NAME IN ('apply lag','transport lag') AND ROWNUM<=200`

type oracleDiagnostics struct {
	id, installationID, databaseID, server, database string
	interval                                         time.Duration
	tags                                             map[string]string
	pool                                             sqlDatabasePool
}

func newOracleDiagnosticsCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" {
		return nil, fmt.Errorf("oracle.diagnostics: installation_id e database_id obrigatórios")
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	server, database := strings.TrimSpace(tags["db_server"]), strings.TrimSpace(tags["db_name"])
	if server == "" || database == "" {
		return nil, fmt.Errorf("oracle.diagnostics: db_server e db_name obrigatórios")
	}
	pool, err := openSQLDatabasePool(cfg, defaultOraclePoolFactory, "oracle.diagnostics")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &oracleDiagnostics{cfg.GetCheckId(), installationID, databaseID, server, database, interval, tags, pool}, nil
}

func (c *oracleDiagnostics) ID() string              { return c.id }
func (c *oracleDiagnostics) Interval() time.Duration { return c.interval }
func (c *oracleDiagnostics) Tags() map[string]string { return c.tags }
func (c *oracleDiagnostics) Close() error            { return c.pool.Close() }
func (c *oracleDiagnostics) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunDiagnostics(ctx)
	return nil, err
}

func (c *oracleDiagnostics) RunDiagnostics(ctx context.Context) (*DatabaseDiagnostics, error) {
	out := &DatabaseDiagnostics{
		Engine: "oracle", InstallationID: c.installationID, DatabaseID: c.databaseID,
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
	read("sessions", sqlOracleDiagnosticSessions, func(rows sqlDatabaseRows) error {
		var item DatabaseSession
		var seconds int64
		if err := rows.Scan(&item.PID, &item.User, &item.Application, &item.Client,
			&item.State, &item.WaitType, &item.WaitEvent, &seconds); err != nil {
			return err
		}
		item.DurationSeconds = float64(seconds)
		out.Sessions = append(out.Sessions, item)
		return nil
	})
	read("blocking", sqlOracleDiagnosticBlocking, func(rows sqlDatabaseRows) error {
		var item DatabaseBlocking
		if err := rows.Scan(&item.BlockedPID, &item.BlockingPID, &item.BlockedUser, &item.BlockingUser); err != nil {
			return err
		}
		out.Blocking = append(out.Blocking, item)
		return nil
	})
	read("waits", sqlOracleDiagnosticWaits, func(rows sqlDatabaseRows) error {
		var item DatabaseWait
		if err := rows.Scan(&item.WaitType, &item.WaitEvent, &item.Count); err != nil {
			return err
		}
		out.Waits = append(out.Waits, item)
		return nil
	})
	replicas := map[string]*DatabaseReplica{}
	read("replication", sqlOracleDiagnosticReplication, func(rows sqlDatabaseRows) error {
		var source, name, value string
		if err := rows.Scan(&source, &name, &value); err != nil {
			return err
		}
		replica := replicas[source]
		if replica == nil {
			replica = &DatabaseReplica{Identity: source, State: "standby", Mode: "data_guard"}
			replicas[source] = replica
		}
		if seconds, ok := oracleLagSeconds(value); ok {
			if name == "apply lag" {
				replica.ReplayLagSeconds = &seconds
			} else if name == "transport lag" {
				replica.WriteLagSeconds = &seconds
			}
		}
		return nil
	})
	for _, replica := range replicas {
		out.Replicas = append(out.Replicas, *replica)
	}
	for _, name := range []string{"bloat", "wraparound", "wal", "replication_slots"} {
		out.Capabilities[name] = "unsupported"
	}
	if out.Capabilities["sessions"] != "available" && out.Capabilities["waits"] != "available" {
		return nil, fmt.Errorf("oracle.diagnostics: sessões e esperas indisponíveis")
	}
	return out, nil
}

func oracleLagSeconds(value string) (float64, bool) {
	var days, hours, minutes, seconds int
	if _, err := fmt.Sscanf(strings.TrimSpace(value), "+%d %d:%d:%d", &days, &hours, &minutes, &seconds); err != nil ||
		days < 0 || hours < 0 || hours >= 24 || minutes < 0 || minutes >= 60 || seconds < 0 || seconds >= 60 {
		return 0, false
	}
	return float64(days*86400 + hours*3600 + minutes*60 + seconds), true
}

func init() { Default.Register("oracle.diagnostics", newOracleDiagnosticsCheck) }
