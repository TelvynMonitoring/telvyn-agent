package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const sqlMySQLDiscoverDatabases = `SELECT SCHEMA_NAME FROM information_schema.SCHEMATA
WHERE SCHEMA_NAME NOT IN ('information_schema', 'performance_schema', 'mysql', 'sys')
ORDER BY SCHEMA_NAME`

type mysqlInstanceDiscovery struct {
	id             string
	interval       time.Duration
	installationID string
	server         string
	port           int
	tags           map[string]string
	pool           sqlDatabasePool
}

func newMySQLInstanceDiscoveryCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newMySQLInstanceDiscoveryCheckWithFactory(cfg, defaultMySQLPoolFactory)
}

func newMySQLInstanceDiscoveryCheckWithFactory(cfg *collectorv1.CheckConfig, factory sqlDatabasePoolFactory) (Check, error) {
	installationID, _ := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" {
		return nil, fmt.Errorf("mysql.instance_discovery: installation_id obrigatório")
	}
	server := strings.TrimSpace(cfg.GetStaticTags()["db_server"])
	port := postgresInstancePort(cfg.GetStaticTags()["db_port"])
	if server == "" || port == 0 {
		return nil, fmt.Errorf("mysql.instance_discovery: servidor e porta obrigatórios")
	}
	pool, err := openSQLDatabasePool(cfg, factory, "mysql.instance_discovery")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	return &mysqlInstanceDiscovery{cfg.GetCheckId(), interval, installationID, server, port, tags, pool}, nil
}

func (c *mysqlInstanceDiscovery) ID() string              { return c.id }
func (c *mysqlInstanceDiscovery) Interval() time.Duration { return c.interval }
func (c *mysqlInstanceDiscovery) Tags() map[string]string { return c.tags }
func (c *mysqlInstanceDiscovery) Close() error            { return c.pool.Close() }
func (c *mysqlInstanceDiscovery) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunInstanceDiscovery(ctx)
	return nil, err
}

func (c *mysqlInstanceDiscovery) RunInstanceDiscovery(ctx context.Context) (*DatabaseInstanceDiscovery, error) {
	queryCtx, cancel := context.WithTimeout(ctx, postgresInstanceDiscoveryTimeout)
	defer cancel()
	var version string
	if err := c.pool.QueryRow(queryCtx, "SELECT VERSION()").Scan(&version); err != nil {
		return nil, fmt.Errorf("mysql.instance_discovery: version: %w", err)
	}
	rows, err := c.pool.Query(queryCtx, sqlMySQLDiscoverDatabases)
	if err != nil {
		return nil, fmt.Errorf("mysql.instance_discovery: databases: %w", err)
	}
	defer rows.Close()
	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &DatabaseInstanceDiscovery{
		InstallationID: c.installationID, Engine: "mysql", Server: c.server, Port: c.port,
		ServerVersion: version, Databases: names,
	}, nil
}

func init() {
	Default.Register("mysql.instance_discovery", newMySQLInstanceDiscoveryCheck)
}
