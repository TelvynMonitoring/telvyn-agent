package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	_ "github.com/sijms/go-ora/v2"
)

var defaultOraclePoolFactory = defaultSQLDatabasePoolFactory("oracle")

type oracleInstanceDiscovery struct {
	id, installationID, server string
	port                       int
	interval                   time.Duration
	tags                       map[string]string
	pool                       sqlDatabasePool
}

func newOracleInstanceDiscoveryCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, _ := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	server := strings.TrimSpace(cfg.GetStaticTags()["db_server"])
	port := postgresInstancePort(cfg.GetStaticTags()["db_port"])
	if installationID == "" || server == "" || port == 0 {
		return nil, fmt.Errorf("oracle.instance_discovery: installation_id, servidor e porta obrigatórios")
	}
	pool, err := openSQLDatabasePool(cfg, defaultOraclePoolFactory, "oracle.instance_discovery")
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
	return &oracleInstanceDiscovery{cfg.GetCheckId(), installationID, server, port, interval, tags, pool}, nil
}

func (c *oracleInstanceDiscovery) ID() string              { return c.id }
func (c *oracleInstanceDiscovery) Interval() time.Duration { return c.interval }
func (c *oracleInstanceDiscovery) Tags() map[string]string { return c.tags }
func (c *oracleInstanceDiscovery) Close() error            { return c.pool.Close() }
func (c *oracleInstanceDiscovery) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunInstanceDiscovery(ctx)
	return nil, err
}

func (c *oracleInstanceDiscovery) RunInstanceDiscovery(ctx context.Context) (*DatabaseInstanceDiscovery, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresInstanceDiscoveryTimeout)
	defer cancel()
	var service string
	if err := c.pool.QueryRow(qctx, "SELECT SYS_CONTEXT('USERENV','SERVICE_NAME') FROM DUAL").Scan(&service); err != nil {
		return nil, err
	}
	if service == "" {
		return nil, fmt.Errorf("oracle.instance_discovery: serviço não identificado")
	}
	var version string
	if err := c.pool.QueryRow(qctx, "SELECT BANNER FROM V$VERSION WHERE ROWNUM=1").Scan(&version); err != nil {
		return nil, err
	}
	return &DatabaseInstanceDiscovery{
		InstallationID: c.installationID, Engine: "oracle", Server: c.server, Port: c.port,
		ServerVersion: version, Databases: []string{service},
	}, nil
}

func init() { Default.Register("oracle.instance_discovery", newOracleInstanceDiscoveryCheck) }
