package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const oracleApplicationOwners = `SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='N'`

type oracleCatalog struct {
	id, installationID, databaseID, server, database string
	interval                                         time.Duration
	tags                                             map[string]string
	pool                                             sqlDatabasePool
}

func newOracleCatalogCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" {
		return nil, fmt.Errorf("oracle.catalog: installation_id e database_id obrigatórios")
	}
	pool, err := openSQLDatabasePool(cfg, defaultOraclePoolFactory, "oracle.catalog")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	return &oracleCatalog{cfg.GetCheckId(), installationID, databaseID,
		strings.TrimSpace(tags["db_server"]), strings.TrimSpace(tags["db_name"]), interval, tags, pool}, nil
}

func (c *oracleCatalog) ID() string              { return c.id }
func (c *oracleCatalog) Interval() time.Duration { return c.interval }
func (c *oracleCatalog) Tags() map[string]string { return c.tags }
func (c *oracleCatalog) Close() error            { return c.pool.Close() }
func (c *oracleCatalog) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunCatalog(ctx)
	return nil, err
}

func (c *oracleCatalog) RunCatalog(ctx context.Context) (*DatabaseCatalog, error) {
	qctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	result := &DatabaseCatalog{Engine: "oracle", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, Tables: make([]DatabaseCatalogTable, 0), Schemas: make([]DatabaseCatalogSchema, 0)}
	if err := c.pool.QueryRow(qctx, "SELECT BANNER FROM V$VERSION WHERE ROWNUM=1").Scan(&result.ServerVersion); err != nil {
		return nil, err
	}
	rows, err := c.pool.Query(qctx, `SELECT OWNER,TABLE_NAME,NVL(NUM_ROWS,0) FROM (
		SELECT OWNER,TABLE_NAME,NUM_ROWS FROM DBA_TABLES
		WHERE OWNER IN (`+oracleApplicationOwners+`) ORDER BY OWNER,TABLE_NAME) WHERE ROWNUM<=10001`)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]int)
	seenSchema := make(map[string]bool)
	for rows.Next() {
		var owner, name string
		var estimated int64
		if err := rows.Scan(&owner, &name, &estimated); err != nil {
			rows.Close()
			return nil, err
		}
		if len(result.Tables) == 10000 {
			result.Truncated = true
			break
		}
		byName[owner+"\x00"+name] = len(result.Tables)
		result.Tables = append(result.Tables, DatabaseCatalogTable{SchemaName: owner, TableName: name,
			TableKind: "TABLE", EstimatedRows: estimated, Columns: []DatabaseCatalogColumn{},
			Indexes: []DatabaseCatalogIndex{}, Constraints: []DatabaseCatalogConstraint{}})
		if !seenSchema[owner] {
			result.Schemas = append(result.Schemas, DatabaseCatalogSchema{Name: owner})
			seenSchema[owner] = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	rows, err = c.pool.Query(qctx, `SELECT OWNER,TABLE_NAME,COLUMN_NAME,COLUMN_ID,DATA_TYPE,NULLABLE,
		CASE WHEN DEFAULT_LENGTH IS NULL THEN 0 ELSE 1 END
		FROM DBA_TAB_COLUMNS WHERE OWNER IN (`+oracleApplicationOwners+`)
		AND ROWNUM<=200001 ORDER BY OWNER,TABLE_NAME,COLUMN_ID`)
	if err != nil {
		return nil, err
	}
	count := 0
	for rows.Next() {
		var owner, table, name, dataType, nullable string
		var ordinal, hasDefault int64
		if err := rows.Scan(&owner, &table, &name, &ordinal, &dataType, &nullable, &hasDefault); err != nil {
			rows.Close()
			return nil, err
		}
		count++
		if count > 200000 {
			result.Truncated = true
			break
		}
		if index, ok := byName[owner+"\x00"+table]; ok {
			columns := &result.Tables[index].Columns
			if len(*columns) < 2000 {
				*columns = append(*columns, DatabaseCatalogColumn{
					Name: name, Ordinal: int(ordinal), DataType: dataType, Nullable: nullable == "Y", HasDefault: hasDefault == 1,
				})
			} else {
				result.Truncated = true
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	rows, err = c.pool.Query(qctx, `SELECT I.TABLE_OWNER,I.TABLE_NAME,I.INDEX_NAME,I.UNIQUENESS,
		C.COLUMN_NAME FROM DBA_INDEXES I JOIN DBA_IND_COLUMNS C
		ON C.INDEX_OWNER=I.OWNER AND C.INDEX_NAME=I.INDEX_NAME
		WHERE I.TABLE_OWNER IN (`+oracleApplicationOwners+`) AND ROWNUM<=200001
		ORDER BY I.TABLE_OWNER,I.TABLE_NAME,I.INDEX_NAME,C.COLUMN_POSITION`)
	if err != nil {
		return nil, err
	}
	count = 0
	for rows.Next() {
		var owner, table, name, uniqueness, column string
		if err := rows.Scan(&owner, &table, &name, &uniqueness, &column); err != nil {
			rows.Close()
			return nil, err
		}
		count++
		if count > 200000 {
			result.Truncated = true
			break
		}
		index, ok := byName[owner+"\x00"+table]
		if !ok {
			continue
		}
		indexes := &result.Tables[index].Indexes
		if len(*indexes) > 0 && (*indexes)[len(*indexes)-1].Name == name {
			(*indexes)[len(*indexes)-1].Definition += ", " + column
		} else if len(*indexes) < 2000 {
			*indexes = append(*indexes, DatabaseCatalogIndex{Name: name, Definition: column, Unique: uniqueness == "UNIQUE"})
		} else {
			result.Truncated = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	result.Fingerprint = structuralCatalogFingerprint(*result)
	return result, nil
}

func init() { Default.Register("oracle.catalog", newOracleCatalogCheck) }
