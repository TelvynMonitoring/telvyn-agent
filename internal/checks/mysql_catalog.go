package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type mysqlCatalog struct {
	id, installationID, databaseID, server, database string
	interval time.Duration
	tags map[string]string
	pool sqlDatabasePool
}

func newMySQLCatalogCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newMySQLCatalogCheckWithFactory(cfg, defaultMySQLPoolFactory)
}

func newMySQLCatalogCheckWithFactory(cfg *collectorv1.CheckConfig, factory sqlDatabasePoolFactory) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" {
		return nil, fmt.Errorf("mysql.catalog: installation_id e database_id obrigatórios")
	}
	pool, err := openSQLDatabasePool(cfg, factory, "mysql.catalog")
	if err != nil { return nil, err }
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 { interval = 10 * time.Minute }
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() { tags[k] = v }
	return &mysqlCatalog{
		id: cfg.GetCheckId(), installationID: installationID, databaseID: databaseID,
		server: strings.TrimSpace(tags["db_server"]), database: strings.TrimSpace(tags["db_name"]),
		interval: interval, tags: tags, pool: pool,
	}, nil
}

func (c *mysqlCatalog) ID() string { return c.id }
func (c *mysqlCatalog) Interval() time.Duration { return c.interval }
func (c *mysqlCatalog) Tags() map[string]string { return c.tags }
func (c *mysqlCatalog) Close() error { return c.pool.Close() }
func (c *mysqlCatalog) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunCatalog(ctx)
	return nil, err
}

func (c *mysqlCatalog) RunCatalog(ctx context.Context) (*DatabaseCatalog, error) {
	qctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	result := &DatabaseCatalog{
		Engine: "mysql", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, Tables: make([]DatabaseCatalogTable, 0),
		Schemas: []DatabaseCatalogSchema{{Name: c.database}},
	}
	if err := c.pool.QueryRow(qctx, "SELECT VERSION()").Scan(&result.ServerVersion); err != nil { return nil, err }
	rows, err := c.pool.Query(qctx, `SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE,
		COALESCE(DATA_LENGTH,0), COALESCE(INDEX_LENGTH,0), COALESCE(TABLE_ROWS,0)
		FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()
		ORDER BY TABLE_NAME LIMIT 10001`)
	if err != nil { return nil, err }
	tableByName := make(map[string]int)
	for rows.Next() {
		var schema, name, kind string
		var dataBytes, indexBytes, estimatedRows int64
		if err := rows.Scan(&schema, &name, &kind, &dataBytes, &indexBytes, &estimatedRows); err != nil { rows.Close(); return nil, err }
		if len(result.Tables) == 10000 { result.Truncated = true; break }
		tableByName[name] = len(result.Tables)
		result.Tables = append(result.Tables, DatabaseCatalogTable{
			SchemaName: schema, TableName: name, TableKind: kind,
			TotalSizeBytes: dataBytes + indexBytes, TableSizeBytes: dataBytes,
			IndexSizeBytes: indexBytes, EstimatedRows: estimatedRows,
			Columns: []DatabaseCatalogColumn{}, Indexes: []DatabaseCatalogIndex{},
			Constraints: []DatabaseCatalogConstraint{},
		})
		result.DatabaseSizeBytes += dataBytes + indexBytes
	}
	if err := rows.Err(); err != nil { rows.Close(); return nil, err }
	rows.Close()

	rows, err = c.pool.Query(qctx, `SELECT TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, COLUMN_TYPE,
		IS_NULLABLE, COLUMN_DEFAULT IS NOT NULL
		FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
		ORDER BY TABLE_NAME, ORDINAL_POSITION LIMIT 200001`)
	if err != nil { return nil, err }
	count := 0
	for rows.Next() {
		var table, name, dataType, nullable string
		var ordinal int
		var hasDefault bool
		if err := rows.Scan(&table, &name, &ordinal, &dataType, &nullable, &hasDefault); err != nil { rows.Close(); return nil, err }
		count++
		if count > 200000 { result.Truncated = true; break }
		if index, ok := tableByName[table]; ok && len(result.Tables[index].Columns) < 2000 {
			result.Tables[index].Columns = append(result.Tables[index].Columns, DatabaseCatalogColumn{
				Name: name, Ordinal: ordinal, DataType: dataType,
				Nullable: nullable == "YES", HasDefault: hasDefault,
			})
		} else if ok { result.Truncated = true }
	}
	if err := rows.Err(); err != nil { rows.Close(); return nil, err }
	rows.Close()

	rows, err = c.pool.Query(qctx, `SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, COLUMN_NAME
		FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE()
		ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX LIMIT 200001`)
	if err != nil { return nil, err }
	count = 0
	for rows.Next() {
		var table, name, column string
		var nonUnique int
		if err := rows.Scan(&table, &name, &nonUnique, &column); err != nil { rows.Close(); return nil, err }
		count++
		if count > 200000 { result.Truncated = true; break }
		index, ok := tableByName[table]
		if !ok { continue }
		indexes := &result.Tables[index].Indexes
		if len(*indexes) > 0 && (*indexes)[len(*indexes)-1].Name == name {
			(*indexes)[len(*indexes)-1].Definition += ", " + column
		} else if len(*indexes) < 2000 {
			*indexes = append(*indexes, DatabaseCatalogIndex{
				Name: name, Definition: column, Unique: nonUnique == 0, Primary: name == "PRIMARY",
			})
		} else { result.Truncated = true }
	}
	if err := rows.Err(); err != nil { rows.Close(); return nil, err }
	rows.Close()
	result.Fingerprint = structuralCatalogFingerprint(*result)
	return result, nil
}

func init() { Default.Register("mysql.catalog", newMySQLCatalogCheck) }
