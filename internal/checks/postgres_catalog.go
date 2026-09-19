// postgres_catalog.go — catálogo estrutural e estatísticas agregadas do Postgres.
//
// O check nunca lê linhas de negócio. Ele consulta apenas os catálogos nativos
// e pg_stat_user_tables, entregando schemas, tabelas, colunas, índices,
// constraints e estatísticas de uso para o endpoint dedicado de catálogo.
package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	postgresCatalogQueryTimeout = 15 * time.Second
	postgresCatalogTableLimit   = 10000
)

// DatabaseCatalog é um snapshot de metadados. O fingerprint permite ao
// backend reconhecer que a estrutura não mudou sem comparar cada item.
type DatabaseCatalog struct {
	InstallationID     string                 `json:"installation_id"`
	DatabaseID         string                 `json:"database_id"`
	DBServer           string                 `json:"db_server"`
	DBName             string                 `json:"db_name"`
	ServerVersion     string                 `json:"server_version"`
	DatabaseSizeBytes int64                  `json:"database_size_bytes"`
	Fingerprint       string                 `json:"fingerprint"`
	Truncated          bool                      `json:"truncated"`
	FunctionsTruncated bool                      `json:"functions_truncated"`
	Tables             []DatabaseCatalogTable    `json:"tables"`
	Functions          []DatabaseCatalogFunction `json:"functions"`
	Settings           []DatabaseCatalogSetting   `json:"settings"`
	Extensions         []DatabaseCatalogExtension `json:"extensions"`
}

type DatabaseCatalogTable struct {
	SchemaName      string                      `json:"schema_name"`
	TableName       string                      `json:"table_name"`
	TableKind       string                      `json:"table_kind"`
	OwnerName       string                      `json:"owner_name"`
	CacheHitRatio   *float64                    `json:"cache_hit_ratio,omitempty"`
	TotalSizeBytes  int64                       `json:"total_size_bytes"`
	TableSizeBytes  int64                       `json:"table_size_bytes"`
	IndexSizeBytes  int64                       `json:"index_size_bytes"`
	EstimatedRows   int64                       `json:"estimated_rows"`
	SeqScans        int64                       `json:"seq_scans"`
	IndexScans      int64                       `json:"index_scans"`
	DeadRows        int64                       `json:"dead_rows"`
	LastVacuum      string                      `json:"last_vacuum"`
	LastAutoVacuum  string                      `json:"last_autovacuum"`
	LastAnalyze     string                      `json:"last_analyze"`
	LastAutoAnalyze string                      `json:"last_autoanalyze"`
	Columns         []DatabaseCatalogColumn     `json:"columns"`
	Indexes         []DatabaseCatalogIndex      `json:"indexes"`
	Constraints     []DatabaseCatalogConstraint `json:"constraints"`
}

type DatabaseCatalogFunction struct {
	SchemaName   string `json:"schema_name"`
	FunctionName string `json:"function_name"`
	OwnerName    string `json:"owner_name"`
	Language     string `json:"language"`
}

type DatabaseCatalogSetting struct {
	Name        string `json:"name"`
	Setting     string `json:"setting"`
	Unit        string `json:"unit"`
	Context     string `json:"context"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

type DatabaseCatalogExtension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type DatabaseCatalogColumn struct {
	Name       string `json:"name"`
	Ordinal    int    `json:"ordinal"`
	DataType   string `json:"data_type"`
	Nullable   bool   `json:"nullable"`
	HasDefault bool   `json:"has_default"`
}

type DatabaseCatalogIndex struct {
	Name          string `json:"name"`
	Definition    string `json:"definition"`
	Unique        bool   `json:"unique"`
	Primary       bool   `json:"primary"`
	Scans         int64  `json:"scans"`
	TuplesRead    int64  `json:"tuples_read"`
	TuplesFetched int64  `json:"tuples_fetched"`
	SizeBytes     int64  `json:"size_bytes"`
}

type DatabaseCatalogConstraint struct {
	Name           string `json:"name"`
	ConstraintType string `json:"type"`
	Definition     string `json:"definition"`
}

// CatalogCheck é o canal agregado de metadados estruturais do banco.
type CatalogCheck interface {
	Check
	RunCatalog(context.Context) (*DatabaseCatalog, error)
}

type postgresCatalog struct {
	id             string
	interval       time.Duration
	hostID         string
	dbServer       string
	installationID string
	databaseID     string
	staticTags     map[string]string
	pool           pgxPool
}

// A consulta fica em uma única linha JSON para manter o contrato pgxPool
// pequeno e para que o limite de tabelas seja aplicado antes de sair do banco.
// Schemas internos e pg_toast são deliberadamente excluídos.
const sqlPostgresCatalog = `WITH table_catalog AS (
  SELECT n.nspname AS schema_name,
         c.relname AS table_name,
         CASE c.relkind
           WHEN 'r' THEN 'table'
           WHEN 'p' THEN 'partitioned_table'
           WHEN 'v' THEN 'view'
           WHEN 'm' THEN 'materialized_view'
           WHEN 'f' THEN 'foreign_table'
           ELSE c.relkind::text
         END AS table_kind,
         pg_get_userbyid(c.relowner) AS owner_name,
         CASE WHEN COALESCE(io.heap_blks_hit, 0) + COALESCE(io.heap_blks_read, 0) > 0
              THEN io.heap_blks_hit::float8 / (io.heap_blks_hit + io.heap_blks_read)::float8
              ELSE NULL END AS cache_hit_ratio,
         pg_total_relation_size(c.oid)::bigint AS total_size_bytes,
         pg_table_size(c.oid)::bigint AS table_size_bytes,
         pg_indexes_size(c.oid)::bigint AS index_size_bytes,
         COALESCE(st.n_live_tup, 0)::bigint AS estimated_rows,
         COALESCE(st.seq_scan, 0)::bigint AS seq_scans,
         COALESCE(st.idx_scan, 0)::bigint AS index_scans,
         COALESCE(st.n_dead_tup, 0)::bigint AS dead_rows,
         COALESCE(st.last_vacuum::text, '') AS last_vacuum,
         COALESCE(st.last_autovacuum::text, '') AS last_autovacuum,
         COALESCE(st.last_analyze::text, '') AS last_analyze,
         COALESCE(st.last_autoanalyze::text, '') AS last_autoanalyze,
         COALESCE((SELECT json_agg(json_build_object(
           'name', a.attname,
           'ordinal', a.attnum,
           'data_type', format_type(a.atttypid, a.atttypmod),
           'nullable', NOT a.attnotnull,
           'has_default', ad.adbin IS NOT NULL
         ) ORDER BY a.attnum)
         FROM pg_attribute a
         LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
         WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped), '[]'::json) AS columns,
         COALESCE((SELECT json_agg(json_build_object(
           'name', ic.relname,
           'definition', pg_get_indexdef(i.indexrelid),
           'unique', i.indisunique,
           'primary', i.indisprimary,
           'scans', COALESCE(si.idx_scan, 0)::bigint,
           'tuples_read', COALESCE(si.idx_tup_read, 0)::bigint,
           'tuples_fetched', COALESCE(si.idx_tup_fetch, 0)::bigint,
           'size_bytes', pg_relation_size(i.indexrelid)::bigint
         ) ORDER BY ic.relname)
         FROM pg_index i
         JOIN pg_class ic ON ic.oid = i.indexrelid
         LEFT JOIN pg_stat_user_indexes si ON si.indexrelid = i.indexrelid
         WHERE i.indrelid = c.oid), '[]'::json) AS indexes,
         COALESCE((SELECT json_agg(json_build_object(
           'name', con.conname,
           'type', CASE con.contype
             WHEN 'p' THEN 'primary_key'
             WHEN 'f' THEN 'foreign_key'
             WHEN 'u' THEN 'unique'
             WHEN 'c' THEN 'check'
             WHEN 'x' THEN 'exclusion'
             ELSE con.contype::text
           END,
           'definition', pg_get_constraintdef(con.oid)
         ) ORDER BY con.conname)
         FROM pg_constraint con
         WHERE con.conrelid = c.oid), '[]'::json) AS constraints
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_stat_user_tables st ON st.relid = c.oid
    LEFT JOIN pg_statio_user_tables io ON io.relid = c.oid
   WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
     AND n.nspname NOT IN ('pg_catalog', 'information_schema')
     AND n.nspname NOT LIKE 'pg_toast%'
     AND n.nspname NOT LIKE 'pg_temp_%'
   ORDER BY n.nspname, c.relname
   LIMIT 10001
), function_catalog AS (
  SELECT n.nspname AS schema_name,
         p.proname AS function_name,
         pg_get_userbyid(p.proowner) AS owner_name,
         l.lanname AS language
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_language l ON l.oid = p.prolang
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
     AND n.nspname NOT LIKE 'pg_toast%'
     AND n.nspname NOT LIKE 'pg_temp_%'
   ORDER BY n.nspname, p.proname, p.oid
   LIMIT 10001
), safe_settings AS (
  SELECT name, setting, COALESCE(unit, '') AS unit, context, source, short_desc AS description
    FROM pg_settings
   WHERE name IN (
     'max_connections', 'shared_buffers', 'effective_cache_size', 'work_mem',
     'maintenance_work_mem', 'wal_level', 'max_wal_size', 'min_wal_size',
     'checkpoint_timeout', 'autovacuum', 'autovacuum_max_workers',
     'autovacuum_vacuum_scale_factor', 'track_io_timing',
     'shared_preload_libraries', 'logging_collector'
   )
   ORDER BY name
), installed_extensions AS (
  SELECT extname AS name, extversion AS version
    FROM pg_extension
   ORDER BY extname
)
SELECT json_build_object(
  'db_name', current_database(),
  'server_version', current_setting('server_version'),
  'database_size_bytes', pg_database_size(current_database())::bigint,
  'tables', COALESCE((SELECT json_agg(t ORDER BY t.schema_name, t.table_name)
                      FROM table_catalog t), '[]'::json),
  'functions', COALESCE((SELECT json_agg(f ORDER BY f.schema_name, f.function_name)
						 FROM function_catalog f), '[]'::json),
	'settings', COALESCE((SELECT json_agg(s ORDER BY s.name) FROM safe_settings s), '[]'::json),
	'extensions', COALESCE((SELECT json_agg(e ORDER BY e.name) FROM installed_extensions e), '[]'::json)
)::text`

func newPostgresCatalogCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newPostgresCatalogCheckWithFactory(cfg, defaultPgxPoolFactory)
}

func newPostgresCatalogCheckWithFactory(cfg *collectorv1.CheckConfig, factory pgxPoolFactory) (Check, error) {
	pool, err := openPostgresPool(cfg, factory, "postgres.catalog")
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}
	normalizeDatabaseMetricTags(cfg.GetParams(), tags)
	installationID, databaseID := databaseIdentity(cfg.GetParams(), tags)
	server := strings.TrimSpace(tags["db_server"])
	if server == "" {
		pool.Close()
		return nil, fmt.Errorf("postgres.catalog: static_tags.db_server obrigatório")
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "postgres.catalog-" + cfg.GetHostId()
	}
	return &postgresCatalog{
		id: id, interval: interval, hostID: cfg.GetHostId(), dbServer: server,
		installationID: installationID, databaseID: databaseID,
		staticTags: tags, pool: pool,
	}, nil
}

func (c *postgresCatalog) ID() string              { return c.id }
func (c *postgresCatalog) Interval() time.Duration { return c.interval }
func (c *postgresCatalog) Tags() map[string]string { return c.staticTags }

func (c *postgresCatalog) Close() error {
	if c.pool != nil {
		c.pool.Close()
	}
	return nil
}

// Run mantém a interface Check. O scheduler detecta CatalogCheck e envia o
// snapshot no sinal db/catalog, sem transformar cada tabela em série métrica.
func (c *postgresCatalog) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunCatalog(ctx)
	return nil, err
}

func (c *postgresCatalog) RunCatalog(ctx context.Context) (*DatabaseCatalog, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresCatalogQueryTimeout)
	defer cancel()
	var body string
	if err := c.pool.QueryRow(qctx, sqlPostgresCatalog).Scan(&body); err != nil {
		log.Printf("postgres.catalog[%s]: query failed: %v", c.id, err)
		return nil, err
	}
	var catalog DatabaseCatalog
	if err := json.Unmarshal([]byte(body), &catalog); err != nil {
		return nil, fmt.Errorf("postgres.catalog: resposta inválida: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(catalog.Tables) > postgresCatalogTableLimit {
		catalog.Tables = catalog.Tables[:postgresCatalogTableLimit]
		catalog.Truncated = true
	}
	if len(catalog.Functions) > postgresCatalogTableLimit {
		catalog.Functions = catalog.Functions[:postgresCatalogTableLimit]
		catalog.FunctionsTruncated = true
	}
	catalog.DBServer = c.dbServer
	catalog.InstallationID = c.installationID
	catalog.DatabaseID = c.databaseID
	if catalog.DBName == "" {
		catalog.DBName = strings.TrimSpace(c.staticTags["db_name"])
	}
	catalog.Fingerprint = structuralCatalogFingerprint(catalog)
	return &catalog, nil
}

func structuralCatalogFingerprint(catalog DatabaseCatalog) string {
	hash := sha256.New()
	write := func(values ...any) {
		for _, value := range values {
			fmt.Fprint(hash, value, "\x1f")
		}
		fmt.Fprint(hash, "\x1e")
	}
	for _, table := range catalog.Tables {
		write("table", table.SchemaName, table.TableName, table.TableKind, table.OwnerName)
		for _, column := range table.Columns {
			write("column", column.Name, column.Ordinal, column.DataType, column.Nullable, column.HasDefault)
		}
		for _, index := range table.Indexes {
			write("index", index.Name, index.Definition, index.Unique, index.Primary)
		}
		for _, constraint := range table.Constraints {
			write("constraint", constraint.Name, constraint.ConstraintType, constraint.Definition)
		}
	}
	for _, function := range catalog.Functions {
		write("function", function.SchemaName, function.FunctionName, function.OwnerName, function.Language)
	}
	for _, setting := range catalog.Settings {
		write("setting", setting.Name, setting.Setting, setting.Unit, setting.Context, setting.Source)
	}
	for _, extension := range catalog.Extensions {
		write("extension", extension.Name, extension.Version)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func init() {
	Default.Register("postgres.catalog", newPostgresCatalogCheck)
}
