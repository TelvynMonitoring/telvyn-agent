package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type clickhouseDiagnostics struct {
	id, installationID, databaseID, server, database string
	interval                                         time.Duration
	tags                                             map[string]string
	client                                           *clickhouseClient
}

func newClickHouseDiagnosticsCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" {
		return nil, fmt.Errorf("clickhouse.diagnostics: installation_id e database_id obrigatórios")
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	server, database := strings.TrimSpace(tags["db_server"]), strings.TrimSpace(tags["db_name"])
	if server == "" || database == "" {
		return nil, fmt.Errorf("clickhouse.diagnostics: db_server e db_name obrigatórios")
	}
	client, err := openClickHouseClient(cfg)
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &clickhouseDiagnostics{cfg.GetCheckId(), installationID, databaseID, server, database, interval, tags, client}, nil
}

func (c *clickhouseDiagnostics) ID() string              { return c.id }
func (c *clickhouseDiagnostics) Interval() time.Duration { return c.interval }
func (c *clickhouseDiagnostics) Tags() map[string]string { return c.tags }
func (c *clickhouseDiagnostics) Close() error            { c.client.http.CloseIdleConnections(); return nil }
func (c *clickhouseDiagnostics) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunDiagnostics(ctx)
	return nil, err
}

func (c *clickhouseDiagnostics) RunDiagnostics(ctx context.Context) (*DatabaseDiagnostics, error) {
	out := &DatabaseDiagnostics{
		Engine: "clickhouse", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, Capabilities: map[string]string{},
		Sessions: []DatabaseSession{}, Blocking: []DatabaseBlocking{}, Waits: []DatabaseWait{},
		Replicas: []DatabaseReplica{}, Bloat: []DatabaseBloat{},
		ReplicationSlots: []DatabaseReplicationSlot{}, MaintenanceOperations: []DatabaseMaintenanceOperation{},
		Errors: []string{},
	}
	read := func(name, statement string) []map[string]any {
		qctx, cancel := context.WithTimeout(ctx, sqlDatabaseQueryTimeout)
		defer cancel()
		var rows []map[string]any
		if err := c.client.query(qctx, statement, &rows); err != nil {
			out.Capabilities[name] = "unavailable"
			out.Errors = append(out.Errors, truncateDiagnosticsError(name+": "+err.Error()))
			return nil
		}
		out.Capabilities[name] = "available"
		return rows
	}
	for _, row := range read("sessions", `SELECT query_id,user,client_name,toString(address) AS client,elapsed
 FROM system.processes WHERE current_database=currentDatabase() AND is_initial_query=1 LIMIT 200`) {
		id, _ := row["query_id"].(string)
		user, _ := row["user"].(string)
		application, _ := row["client_name"].(string)
		client, _ := row["client"].(string)
		elapsed, _ := row["elapsed"].(float64)
		out.Sessions = append(out.Sessions, DatabaseSession{Identity: id, User: user,
			Application: application, Client: client, State: "active", DurationSeconds: elapsed})
	}
	for _, row := range read("replication", `SELECT database,table,is_readonly,absolute_delay
 FROM system.replicas WHERE database=currentDatabase() LIMIT 200`) {
		database, _ := row["database"].(string)
		table, _ := row["table"].(string)
		readonly, _ := row["is_readonly"].(float64)
		delay, _ := row["absolute_delay"].(float64)
		state := "active"
		if readonly != 0 {
			state = "readonly"
		}
		out.Replicas = append(out.Replicas, DatabaseReplica{Identity: database + "." + table,
			State: state, Mode: "replicated_table", ReplayLagSeconds: &delay})
	}
	for _, row := range read("maintenance", `SELECT database,table,progress
 FROM system.merges WHERE database=currentDatabase() LIMIT 200`) {
		database, _ := row["database"].(string)
		table, _ := row["table"].(string)
		progress, _ := row["progress"].(float64)
		out.MaintenanceOperations = append(out.MaintenanceOperations, DatabaseMaintenanceOperation{
			Operation: "merge", SchemaName: database, TableName: table,
			Phase: "running", ProgressPercent: progress * 100})
	}
	for _, name := range []string{"blocking", "waits", "bloat", "wraparound", "wal", "replication_slots"} {
		out.Capabilities[name] = "unsupported"
	}
	if out.Capabilities["sessions"] != "available" && out.Capabilities["replication"] != "available" {
		return nil, fmt.Errorf("clickhouse.diagnostics: processos e réplicas indisponíveis")
	}
	return out, nil
}

func init() { Default.Register("clickhouse.diagnostics", newClickHouseDiagnosticsCheck) }
