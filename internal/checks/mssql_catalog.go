package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const sqlMSSQLCatalogTables = `SELECT TOP (10001) s.name, o.name, o.type_desc,
	COALESCE(SUM(CASE WHEN p.index_id IN (0,1) THEN p.row_count ELSE 0 END),0),
	COALESCE(SUM(p.reserved_page_count),0)*8192,
	COALESCE(SUM(CASE WHEN p.index_id IN (0,1) THEN p.reserved_page_count ELSE 0 END),0)*8192
FROM sys.objects o
JOIN sys.schemas s ON s.schema_id=o.schema_id
LEFT JOIN sys.dm_db_partition_stats p ON p.object_id=o.object_id
WHERE o.type IN ('U','V') AND o.is_ms_shipped=0
GROUP BY s.name,o.name,o.type_desc ORDER BY s.name,o.name`

const sqlMSSQLCatalogColumns = `SELECT TOP (200001) s.name, o.name, c.name, c.column_id,
	t.name, c.is_nullable, CONVERT(bit,CASE WHEN c.default_object_id=0 THEN 0 ELSE 1 END)
FROM sys.columns c JOIN sys.objects o ON o.object_id=c.object_id
JOIN sys.schemas s ON s.schema_id=o.schema_id
JOIN sys.types t ON t.user_type_id=c.user_type_id
WHERE o.type IN ('U','V') AND o.is_ms_shipped=0
ORDER BY s.name,o.name,c.column_id`

const sqlMSSQLCatalogIndexes = `SELECT TOP (200001) s.name,o.name,i.name,i.is_unique,i.is_primary_key,c.name
FROM sys.indexes i JOIN sys.objects o ON o.object_id=i.object_id
JOIN sys.schemas s ON s.schema_id=o.schema_id
JOIN sys.index_columns ic ON ic.object_id=i.object_id AND ic.index_id=i.index_id
JOIN sys.columns c ON c.object_id=ic.object_id AND c.column_id=ic.column_id
WHERE o.type='U' AND o.is_ms_shipped=0 AND i.name IS NOT NULL
ORDER BY s.name,o.name,i.name,ic.key_ordinal,ic.index_column_id`

type mssqlCatalog struct {
	id, installationID, databaseID, server, database string
	interval time.Duration
	tags map[string]string
	pool sqlDatabasePool
}

func newMSSQLCatalogCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newMSSQLCatalogCheckWithFactory(cfg, defaultMSSQLPoolFactory)
}

func newMSSQLCatalogCheckWithFactory(cfg *collectorv1.CheckConfig, factory sqlDatabasePoolFactory) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" { return nil, fmt.Errorf("mssql.catalog: installation_id e database_id obrigatórios") }
	pool, err := openSQLDatabasePool(cfg, factory, "mssql.catalog")
	if err != nil { return nil, err }
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 { interval = 10*time.Minute }
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k,v := range cfg.GetStaticTags() { tags[k] = v }
	return &mssqlCatalog{
		id: cfg.GetCheckId(), installationID: installationID, databaseID: databaseID,
		server: strings.TrimSpace(tags["db_server"]), database: strings.TrimSpace(tags["db_name"]),
		interval: interval, tags: tags, pool: pool,
	}, nil
}

func (c *mssqlCatalog) ID() string { return c.id }
func (c *mssqlCatalog) Interval() time.Duration { return c.interval }
func (c *mssqlCatalog) Tags() map[string]string { return c.tags }
func (c *mssqlCatalog) Close() error { return c.pool.Close() }
func (c *mssqlCatalog) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunCatalog(ctx)
	return nil, err
}

func (c *mssqlCatalog) RunCatalog(ctx context.Context) (*DatabaseCatalog, error) {
	qctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	result := &DatabaseCatalog{
		Engine: "mssql", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, Tables: make([]DatabaseCatalogTable,0),
		Schemas: make([]DatabaseCatalogSchema,0),
	}
	if err := c.pool.QueryRow(qctx, "SELECT CONVERT(varchar(128), SERVERPROPERTY('ProductVersion'))").Scan(&result.ServerVersion); err != nil { return nil, err }
	rows, err := c.pool.Query(qctx, sqlMSSQLCatalogTables)
	if err != nil { return nil, err }
	tableByName := make(map[string]int)
	schemaSeen := make(map[string]bool)
	for rows.Next() {
		var schema, name, kind string
		var estimatedRows, totalBytes, tableBytes int64
		if err := rows.Scan(&schema,&name,&kind,&estimatedRows,&totalBytes,&tableBytes); err != nil { rows.Close(); return nil, err }
		if len(result.Tables)==10000 { result.Truncated=true; break }
		if !schemaSeen[schema] { result.Schemas=append(result.Schemas,DatabaseCatalogSchema{Name:schema}); schemaSeen[schema]=true }
		tableByName[schema+"."+name]=len(result.Tables)
		result.Tables=append(result.Tables,DatabaseCatalogTable{
			SchemaName:schema,TableName:name,TableKind:kind,EstimatedRows:estimatedRows,
			TotalSizeBytes:totalBytes,TableSizeBytes:tableBytes,IndexSizeBytes:totalBytes-tableBytes,
			Columns:[]DatabaseCatalogColumn{},Indexes:[]DatabaseCatalogIndex{},Constraints:[]DatabaseCatalogConstraint{},
		})
		result.DatabaseSizeBytes+=totalBytes
	}
	if err := rows.Err(); err != nil { rows.Close(); return nil, err }
	rows.Close()
	rows,err=c.pool.Query(qctx,sqlMSSQLCatalogColumns)
	if err != nil { return nil, err }
	count:=0
	for rows.Next() {
		var schema,table,name,dataType string
		var ordinal int
		var nullable,hasDefault bool
		if err:=rows.Scan(&schema,&table,&name,&ordinal,&dataType,&nullable,&hasDefault); err!=nil { rows.Close(); return nil, err }
		count++
		if count>200000 { result.Truncated=true; break }
		if index,ok:=tableByName[schema+"."+table]; ok && len(result.Tables[index].Columns)<2000 {
			result.Tables[index].Columns=append(result.Tables[index].Columns,DatabaseCatalogColumn{
				Name:name,Ordinal:ordinal,DataType:dataType,Nullable:nullable,HasDefault:hasDefault,
			})
		} else if ok { result.Truncated=true }
	}
	if err:=rows.Err(); err!=nil { rows.Close(); return nil, err }
	rows.Close()
	rows,err=c.pool.Query(qctx,sqlMSSQLCatalogIndexes)
	if err!=nil { return nil, err }
	count=0
	for rows.Next() {
		var schema,table,name,column string
		var unique,primary bool
		if err:=rows.Scan(&schema,&table,&name,&unique,&primary,&column); err!=nil { rows.Close(); return nil, err }
		count++
		if count>200000 { result.Truncated=true; break }
		index,ok:=tableByName[schema+"."+table]
		if !ok { continue }
		indexes:=&result.Tables[index].Indexes
		if len(*indexes)>0 && (*indexes)[len(*indexes)-1].Name==name {
			(*indexes)[len(*indexes)-1].Definition+=", "+column
		} else if len(*indexes)<2000 {
			*indexes=append(*indexes,DatabaseCatalogIndex{Name:name,Definition:column,Unique:unique,Primary:primary})
		} else { result.Truncated=true }
	}
	if err:=rows.Err(); err!=nil { rows.Close(); return nil, err }
	rows.Close()
	result.Fingerprint=structuralCatalogFingerprint(*result)
	return result,nil
}

func init() { Default.Register("mssql.catalog", newMSSQLCatalogCheck) }
