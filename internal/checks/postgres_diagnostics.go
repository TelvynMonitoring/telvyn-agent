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
	"sync"
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
	Replicas       []DatabaseReplica  `json:"replicas"`
	ReplicationSlots []DatabaseReplicationSlot `json:"replication_slots"`
	MaintenanceOperations []DatabaseMaintenanceOperation `json:"maintenance_operations"`
	Checkpoints    *DatabaseCheckpoints `json:"checkpoints,omitempty"`
	Wraparound     *DatabaseWraparound  `json:"wraparound,omitempty"`
	WAL            *DatabaseWAL         `json:"wal,omitempty"`
	Errors         []string           `json:"errors,omitempty"`
}

type DatabaseReplica struct {
	Identity         string   `json:"identity"`
	User             string   `json:"user"`
	Client           string   `json:"client"`
	State            string   `json:"state"`
	Mode             string   `json:"mode"`
	WriteLagSeconds  *float64 `json:"write_lag_seconds,omitempty"`
	FlushLagSeconds  *float64 `json:"flush_lag_seconds,omitempty"`
	ReplayLagSeconds *float64 `json:"replay_lag_seconds,omitempty"`
	SentLSN          string   `json:"sent_lsn"`
	WriteLSN         string   `json:"write_lsn"`
	FlushLSN         string   `json:"flush_lsn"`
	ReplayLSN        string   `json:"replay_lsn"`
}

type DatabaseReplicationSlot struct {
	SlotName     string `json:"slot_name"`
	Plugin       string `json:"plugin"`
	SlotType     string `json:"slot_type"`
	Database     string `json:"database"`
	Active       bool   `json:"active"`
	RestartLSN   string `json:"restart_lsn"`
	ConfirmedLSN string `json:"confirmed_lsn"`
	RetainedBytes int64 `json:"retained_bytes"`
}

type DatabaseMaintenanceOperation struct {
	Operation       string  `json:"operation"`
	SchemaName      string  `json:"schema_name"`
	TableName       string  `json:"table_name"`
	Phase           string  `json:"phase"`
	ProcessedBlocks int64   `json:"processed_blocks"`
	TotalBlocks     int64   `json:"total_blocks"`
	ProgressPercent float64 `json:"progress_percent"`
}

type DatabaseCheckpoints struct {
	Timed          int64   `json:"timed"`
	Requested      int64   `json:"requested"`
	WriteTimeMS    float64 `json:"write_time_ms"`
	SyncTimeMS     float64 `json:"sync_time_ms"`
	BuffersWritten int64   `json:"buffers_written"`
	StatsReset     string  `json:"stats_reset"`
}

type DatabaseWraparound struct {
	DatabaseAge   int64  `json:"database_age"`
	FreezeMaxAge  int64  `json:"freeze_max_age"`
	OldestTableAge int64 `json:"oldest_table_age"`
	OldestTable   string `json:"oldest_table"`
}

type DatabaseWAL struct {
	Records          int64   `json:"records"`
	FullPageImages   int64   `json:"full_page_images"`
	Bytes            int64   `json:"bytes"`
	GeneratedBytes   int64   `json:"generated_bytes"`
	BytesPerSecond   float64 `json:"bytes_per_second"`
	SampleSeconds    float64 `json:"sample_seconds"`
	ArchivedCount    int64   `json:"archived_count"`
	FailedCount      int64   `json:"failed_count"`
	LastArchivedWAL  string  `json:"last_archived_wal"`
	LastArchivedTime string  `json:"last_archived_time"`
	LastFailedWAL    string  `json:"last_failed_wal"`
	LastFailedTime   string  `json:"last_failed_time"`
	StatsReset       string  `json:"stats_reset"`
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
	walMu          sync.Mutex
	lastWalBytes   int64
	lastWalAt      time.Time
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

const sqlPostgresDiagnosticWraparound = `SELECT json_build_object(
    'database_age', age(d.datfrozenxid)::bigint,
    'freeze_max_age', current_setting('autovacuum_freeze_max_age')::bigint,
    'oldest_table_age', COALESCE((SELECT max(age(c.relfrozenxid))::bigint FROM pg_class c WHERE c.relkind IN ('r','m')), 0),
    'oldest_table', COALESCE((SELECT quote_ident(n.nspname) || '.' || quote_ident(c.relname)
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE c.relkind IN ('r','m') AND n.nspname NOT IN ('pg_catalog','information_schema')
     ORDER BY age(c.relfrozenxid) DESC LIMIT 1), '')
  )::text
  FROM pg_database d WHERE d.datname=current_database()`

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

func diagnosticColumn(caps postgresRelationCapabilities, column, fallback string) string {
	if caps.hasColumn(column) {
		return "r." + column
	}
	return fallback
}

func diagnosticTextColumn(caps postgresRelationCapabilities, column string) string {
	return "COALESCE((" + diagnosticColumn(caps, column, "NULL") + ")::text, '')"
}

func diagnosticLagColumn(caps postgresRelationCapabilities, column string) string {
	if caps.hasColumn(column) {
		return "EXTRACT(EPOCH FROM r." + column + ")::float8"
	}
	return "NULL::float8"
}

func postgresReplicationQuery(caps postgresRelationCapabilities) string {
	sent := "sent_lsn"
	write := "write_lsn"
	flush := "flush_lsn"
	replay := "replay_lsn"
	if !caps.hasColumn(sent) {
		sent = "sent_location"
		write = "write_location"
		flush = "flush_location"
		replay = "replay_location"
	}
	return `SELECT COALESCE(json_agg(x ORDER BY x.identity), '[]'::json)::text FROM (` +
		`SELECT COALESCE(r.application_name, '') AS identity, COALESCE(r.usename, '') AS "user", ` +
		`COALESCE(r.client_addr::text, '') AS client, COALESCE(r.state, '') AS state, ` +
		`COALESCE(r.sync_state, '') AS mode, ` + diagnosticLagColumn(caps, "write_lag") + ` AS write_lag_seconds, ` +
		diagnosticLagColumn(caps, "flush_lag") + ` AS flush_lag_seconds, ` +
		diagnosticLagColumn(caps, "replay_lag") + ` AS replay_lag_seconds, ` +
		diagnosticTextColumn(caps, sent) + ` AS sent_lsn, ` + diagnosticTextColumn(caps, write) + ` AS write_lsn, ` +
		diagnosticTextColumn(caps, flush) + ` AS flush_lsn, ` + diagnosticTextColumn(caps, replay) + ` AS replay_lsn ` +
		`FROM ` + caps.qualifiedName + ` r LIMIT 200) x`
}

func postgresReplicationSlotsQuery(caps postgresRelationCapabilities, walFunctions postgresWALFunctions) string {
	confirmed := diagnosticTextColumn(caps, "confirmed_flush_lsn")
	retained := "0"
	if caps.hasColumn("restart_lsn") && walFunctions.difference != "" && walFunctions.current != "" {
		retained = "GREATEST(pg_catalog." + walFunctions.difference + "(pg_catalog." + walFunctions.current + "(), r.restart_lsn), 0)::bigint"
	}
	return `SELECT COALESCE(json_agg(x ORDER BY x.slot_name), '[]'::json)::text FROM (` +
		`SELECT COALESCE(r.slot_name, '') AS slot_name, COALESCE(r.plugin, '') AS plugin, ` +
		`COALESCE(r.slot_type, '') AS slot_type, COALESCE(r.database, '') AS database, ` +
		`COALESCE(r.active, false) AS active, ` + diagnosticTextColumn(caps, "restart_lsn") + ` AS restart_lsn, ` +
		confirmed + ` AS confirmed_lsn, ` + retained + ` AS retained_bytes FROM ` + caps.qualifiedName + ` r LIMIT 200) x`
}

func postgresCheckpointQuery(caps postgresRelationCapabilities) string {
	field := func(preferred, legacy, fallback string) string {
		if caps.hasColumn(preferred) {
			return "COALESCE(r." + preferred + ", 0)"
		}
		if legacy != "" && caps.hasColumn(legacy) {
			return "COALESCE(r." + legacy + ", 0)"
		}
		return fallback
	}
	return `SELECT json_build_object(` +
		`'timed', ` + field("num_timed", "checkpoints_timed", "0") + `::bigint, ` +
		`'requested', ` + field("num_requested", "checkpoints_req", "0") + `::bigint, ` +
		`'write_time_ms', ` + field("write_time", "checkpoint_write_time", "0") + `::float8, ` +
		`'sync_time_ms', ` + field("sync_time", "checkpoint_sync_time", "0") + `::float8, ` +
		`'buffers_written', ` + field("buffers_written", "buffers_checkpoint", "0") + `::bigint, ` +
		`'stats_reset', ` + diagnosticTextColumn(caps, "stats_reset") + `)::text FROM ` + caps.qualifiedName + ` r`
}

func postgresWALQuery(caps postgresRelationCapabilities) string {
	return `SELECT json_build_object(` +
		`'records', ` + diagnosticColumn(caps, "wal_records", "0") + `::bigint, ` +
		`'full_page_images', ` + diagnosticColumn(caps, "wal_fpi", "0") + `::bigint, ` +
		`'bytes', ` + diagnosticColumn(caps, "wal_bytes", "0") + `::numeric::bigint, ` +
		`'stats_reset', ` + diagnosticTextColumn(caps, "stats_reset") + `)::text FROM ` + caps.qualifiedName + ` r`
}

func postgresArchiverQuery(caps postgresRelationCapabilities) string {
	return `SELECT json_build_object(` +
		`'archived_count', ` + diagnosticColumn(caps, "archived_count", "0") + `::bigint, ` +
		`'failed_count', ` + diagnosticColumn(caps, "failed_count", "0") + `::bigint, ` +
		`'last_archived_wal', ` + diagnosticTextColumn(caps, "last_archived_wal") + `, ` +
		`'last_archived_time', ` + diagnosticTextColumn(caps, "last_archived_time") + `, ` +
		`'last_failed_wal', ` + diagnosticTextColumn(caps, "last_failed_wal") + `, ` +
		`'last_failed_time', ` + diagnosticTextColumn(caps, "last_failed_time") + `, ` +
		`'stats_reset', ` + diagnosticTextColumn(caps, "stats_reset") + `)::text FROM ` + caps.qualifiedName + ` r`
}

func postgresProgressQuery(caps postgresRelationCapabilities, operation string) string {
	processedColumn, totalColumn := "", ""
	for _, pair := range [][2]string{{"heap_blks_scanned", "heap_blks_total"}, {"blocks_done", "blocks_total"}, {"sample_blks_scanned", "sample_blks_total"}} {
		if caps.hasColumn(pair[0]) && caps.hasColumn(pair[1]) {
			processedColumn, totalColumn = pair[0], pair[1]
			break
		}
	}
	processed, total := "0", "0"
	if processedColumn != "" {
		processed, total = "COALESCE(r."+processedColumn+",0)", "COALESCE(r."+totalColumn+",0)"
	}
	phase := diagnosticTextColumn(caps, "phase")
	operationExpression := "'" + operation + "'"
	if caps.hasColumn("command") {
		// pg_stat_progress_create_index also reports REINDEX. Preserve the
		// operation exposed by PostgreSQL instead of labelling every row as a
		// CREATE INDEX operation.
		operationExpression = "lower(replace(COALESCE(r.command, ''), ' ', '_'))"
	}
	return `SELECT COALESCE(json_agg(x), '[]'::json)::text FROM (` +
		`SELECT ` + operationExpression + ` AS operation, COALESCE(n.nspname, '') AS schema_name, ` +
		`COALESCE(c.relname, '') AS table_name, ` + phase + ` AS phase, ` +
		processed + `::bigint AS processed_blocks, ` + total + `::bigint AS total_blocks, ` +
		`CASE WHEN ` + total + ` > 0 THEN (` + processed + `::float8 / ` + total + `::float8) * 100 ELSE 0 END AS progress_percent ` +
		`FROM ` + caps.qualifiedName + ` r LEFT JOIN pg_class c ON c.oid=r.relid LEFT JOIN pg_namespace n ON n.oid=c.relnamespace LIMIT 200) x`
}

func (c *postgresDiagnostics) RunDiagnostics(ctx context.Context) (*DatabaseDiagnostics, error) {
	out := &DatabaseDiagnostics{
		InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.dbServer, DBName: c.dbName, BloatEnabled: c.bloatEnabled,
		Capabilities: map[string]string{}, Sessions: []DatabaseSession{}, Blocking: []DatabaseBlocking{},
		Waits: []DatabaseWait{}, Bloat: []DatabaseBloat{}, Replicas: []DatabaseReplica{},
		ReplicationSlots: []DatabaseReplicationSlot{}, MaintenanceOperations: []DatabaseMaintenanceOperation{},
		Errors: []string{},
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
	read("wraparound", sqlPostgresDiagnosticWraparound, &out.Wraparound)

	discover := func(name string) postgresRelationCapabilities {
		caps, err := discoverPostgresRelationCapabilities(ctx, c.pool, "pg_catalog", name)
		if err != nil {
			out.Capabilities[name] = "unavailable"
			out.Errors = append(out.Errors, truncateDiagnosticsError(name+": "+err.Error()))
			return postgresRelationCapabilities{}
		}
		return caps
	}

	if caps := discover("pg_stat_replication"); caps.available() {
		read("replication", postgresReplicationQuery(caps), &out.Replicas)
	} else {
		out.Capabilities["replication"] = "unavailable"
	}
	if caps := discover("pg_replication_slots"); caps.available() {
		walFunctions, err := discoverPostgresWALFunctions(ctx, c.pool)
		if err != nil {
			out.Capabilities["replication_slot_retention"] = "unavailable"
			out.Errors = append(out.Errors, truncateDiagnosticsError("replication_slot_retention: "+err.Error()))
		} else if walFunctions.difference == "" || walFunctions.current == "" {
			out.Capabilities["replication_slot_retention"] = "unavailable"
		} else {
			out.Capabilities["replication_slot_retention"] = "available"
		}
		read("replication_slots", postgresReplicationSlotsQuery(caps, walFunctions), &out.ReplicationSlots)
	} else {
		out.Capabilities["replication_slots"] = "unavailable"
	}

	checkpointCaps := discover("pg_stat_checkpointer")
	if !checkpointCaps.available() {
		checkpointCaps = discover("pg_stat_bgwriter")
	}
	if checkpointCaps.available() {
		read("checkpoints", postgresCheckpointQuery(checkpointCaps), &out.Checkpoints)
	} else {
		out.Capabilities["checkpoints"] = "unavailable"
	}

	if caps := discover("pg_stat_wal"); caps.available() {
		if read("wal", postgresWALQuery(caps), &out.WAL) && out.WAL != nil {
			now := time.Now()
			c.walMu.Lock()
			if !c.lastWalAt.IsZero() && out.WAL.Bytes >= c.lastWalBytes {
				out.WAL.SampleSeconds = now.Sub(c.lastWalAt).Seconds()
				out.WAL.GeneratedBytes = out.WAL.Bytes - c.lastWalBytes
				if out.WAL.SampleSeconds > 0 {
					out.WAL.BytesPerSecond = float64(out.WAL.GeneratedBytes) / out.WAL.SampleSeconds
				}
			}
			c.lastWalBytes, c.lastWalAt = out.WAL.Bytes, now
			c.walMu.Unlock()
		}
	} else {
		out.Capabilities["wal"] = "unavailable"
	}
	if caps := discover("pg_stat_archiver"); caps.available() {
		read("archiver", postgresArchiverQuery(caps), &out.WAL)
	} else {
		out.Capabilities["archiver"] = "unavailable"
	}

	for relation, operation := range map[string]string{
		"pg_stat_progress_vacuum": "vacuum",
		"pg_stat_progress_analyze": "analyze",
		"pg_stat_progress_create_index": "create_index",
	} {
		caps := discover(relation)
		if !caps.available() {
			continue
		}
		var operations []DatabaseMaintenanceOperation
		if read("progress_"+operation, postgresProgressQuery(caps, operation), &operations) {
			out.MaintenanceOperations = append(out.MaintenanceOperations, operations...)
		}
	}
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
