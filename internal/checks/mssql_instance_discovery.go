package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const sqlMSSQLDiscoverDatabases = `SELECT name FROM sys.databases
WHERE database_id > 4 AND state_desc='ONLINE' AND HAS_DBACCESS(name)=1 ORDER BY name`

type mssqlInstanceDiscovery struct {
	id, installationID, server string
	port int
	interval time.Duration
	tags map[string]string
	pool sqlDatabasePool
}

func newMSSQLInstanceDiscoveryCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newMSSQLInstanceDiscoveryCheckWithFactory(cfg, defaultMSSQLPoolFactory)
}

func newMSSQLInstanceDiscoveryCheckWithFactory(cfg *collectorv1.CheckConfig, factory sqlDatabasePoolFactory) (Check, error) {
	installationID, _ := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	server := strings.TrimSpace(cfg.GetStaticTags()["db_server"])
	port := postgresInstancePort(cfg.GetStaticTags()["db_port"])
	if installationID == "" || server == "" || port == 0 {
		return nil, fmt.Errorf("mssql.instance_discovery: installation_id, servidor e porta obrigatórios")
	}
	pool, err := openSQLDatabasePool(cfg, factory, "mssql.instance_discovery")
	if err != nil { return nil, err }
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 { interval = 5*time.Minute }
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() { tags[k] = v }
	return &mssqlInstanceDiscovery{cfg.GetCheckId(), installationID, server, port, interval, tags, pool}, nil
}

func (c *mssqlInstanceDiscovery) ID() string { return c.id }
func (c *mssqlInstanceDiscovery) Interval() time.Duration { return c.interval }
func (c *mssqlInstanceDiscovery) Tags() map[string]string { return c.tags }
func (c *mssqlInstanceDiscovery) Close() error { return c.pool.Close() }
func (c *mssqlInstanceDiscovery) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunInstanceDiscovery(ctx)
	return nil, err
}

func (c *mssqlInstanceDiscovery) RunInstanceDiscovery(ctx context.Context) (*DatabaseInstanceDiscovery, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresInstanceDiscoveryTimeout)
	defer cancel()
	var version string
	if err := c.pool.QueryRow(qctx, "SELECT CONVERT(varchar(128), SERVERPROPERTY('ProductVersion'))").Scan(&version); err != nil {
		return nil, err
	}
	rows, err := c.pool.Query(qctx, sqlMSSQLDiscoverDatabases)
	if err != nil { return nil, err }
	defer rows.Close()
	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil { return nil, err }
		names = append(names, name)
	}
	if err := rows.Err(); err != nil { return nil, err }
	return &DatabaseInstanceDiscovery{
		InstallationID: c.installationID, Engine: "mssql", Server: c.server,
		Port: c.port, ServerVersion: version, Databases: names,
	}, nil
}

func init() { Default.Register("mssql.instance_discovery", newMSSQLInstanceDiscoveryCheck) }
