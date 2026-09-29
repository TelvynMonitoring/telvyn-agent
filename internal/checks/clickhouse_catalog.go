package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type clickhouseCatalog struct {
	id, installationID, databaseID, server, database string
	interval                                         time.Duration
	tags                                             map[string]string
	client                                           *clickhouseClient
}

func newClickHouseCatalogCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	database := strings.TrimSpace(cfg.GetStaticTags()["db_name"])
	if installationID == "" || databaseID == "" || database == "" {
		return nil, fmt.Errorf("clickhouse.catalog: identidade incompleta")
	}
	client, err := openClickHouseClient(cfg)
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
	return &clickhouseCatalog{cfg.GetCheckId(), installationID, databaseID,
		strings.TrimSpace(tags["db_server"]), database, interval, tags, client}, nil
}

func (c *clickhouseCatalog) ID() string              { return c.id }
func (c *clickhouseCatalog) Interval() time.Duration { return c.interval }
func (c *clickhouseCatalog) Tags() map[string]string { return c.tags }
func (c *clickhouseCatalog) Close() error            { c.client.http.CloseIdleConnections(); return nil }
func (c *clickhouseCatalog) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunCatalog(ctx)
	return nil, err
}

func (c *clickhouseCatalog) RunCatalog(ctx context.Context) (*DatabaseCatalog, error) {
	qctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	result := &DatabaseCatalog{Engine: "clickhouse", InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, Schemas: []DatabaseCatalogSchema{{Name: c.database}},
		Tables: make([]DatabaseCatalogTable, 0)}
	var version []map[string]any
	if err := c.client.query(qctx, "SELECT version() AS version", &version); err != nil {
		return nil, err
	}
	if len(version) != 1 {
		return nil, fmt.Errorf("clickhouse.catalog: versão indisponível")
	}
	result.ServerVersion, _ = version[0]["version"].(string)
	var tables []map[string]any
	if err := c.client.query(qctx, `SELECT name,engine,total_bytes,total_rows,primary_key
		FROM system.tables WHERE database=currentDatabase() ORDER BY name LIMIT 10001`, &tables); err != nil {
		return nil, err
	}
	byName := make(map[string]int)
	for _, row := range tables {
		if len(result.Tables) == 10000 {
			result.Truncated = true
			break
		}
		name, _ := row["name"].(string)
		kind, _ := row["engine"].(string)
		table := DatabaseCatalogTable{SchemaName: c.database, TableName: name, TableKind: kind,
			Columns: []DatabaseCatalogColumn{}, Indexes: []DatabaseCatalogIndex{}, Constraints: []DatabaseCatalogConstraint{}}
		if bytes, ok := row["total_bytes"].(float64); ok {
			table.TotalSizeBytes = int64(bytes)
			table.TableSizeBytes = int64(bytes)
			result.DatabaseSizeBytes += int64(bytes)
		}
		if count, ok := row["total_rows"].(float64); ok {
			table.EstimatedRows = int64(count)
		}
		if key, ok := row["primary_key"].(string); ok && key != "" {
			table.Indexes = append(table.Indexes, DatabaseCatalogIndex{Name: "primary_key", Definition: key, Primary: true})
		}
		byName[name] = len(result.Tables)
		result.Tables = append(result.Tables, table)
	}
	var columns []map[string]any
	if err := c.client.query(qctx, `SELECT table,name,type,position,default_kind FROM system.columns
		WHERE database=currentDatabase() ORDER BY table,position LIMIT 10001`, &columns); err != nil {
		return nil, err
	}
	for _, row := range columns {
		tableName, _ := row["table"].(string)
		index, ok := byName[tableName]
		if !ok {
			continue
		}
		if len(result.Tables[index].Columns) >= 2000 {
			result.Truncated = true
			continue
		}
		name, _ := row["name"].(string)
		dataType, _ := row["type"].(string)
		ordinal, _ := row["position"].(float64)
		defaultKind, _ := row["default_kind"].(string)
		result.Tables[index].Columns = append(result.Tables[index].Columns, DatabaseCatalogColumn{
			Name: name, Ordinal: int(ordinal), DataType: dataType, Nullable: strings.HasPrefix(dataType, "Nullable("),
			HasDefault: defaultKind != "",
		})
	}
	if len(columns) == 10001 {
		result.Truncated = true
	}
	result.Fingerprint = structuralCatalogFingerprint(*result)
	return result, nil
}

func init() { Default.Register("clickhouse.catalog", newClickHouseCatalogCheck) }
