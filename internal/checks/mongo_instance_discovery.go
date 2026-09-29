package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type mongoInstanceDiscovery struct {
	id, installationID, engine, server string
	port                               int
	interval                           time.Duration
	tags                               map[string]string
	client                             *mongo.Client
}

func openMongoClient(cfg *collectorv1.CheckConfig, kind string) (*mongo.Client, error) {
	uri := cfg.GetParams()["dsn"]
	if uri == "" {
		return nil, fmt.Errorf("%s: param 'dsn' obrigatório", kind)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri).SetMaxPoolSize(2).SetMinPoolSize(0))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, readpref.PrimaryPreferred()); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("%s: unreachable: %w", kind, err)
	}
	return client, nil
}

func newMongoInstanceDiscoveryCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, _ := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	engine := strings.TrimSpace(cfg.GetStaticTags()["db_engine"])
	if engine != "mongodb" && engine != "documentdb" {
		return nil, fmt.Errorf("mongo.instance_discovery: motor inválido")
	}
	server := strings.TrimSpace(cfg.GetStaticTags()["db_server"])
	port := postgresInstancePort(cfg.GetStaticTags()["db_port"])
	if installationID == "" || server == "" || port == 0 {
		return nil, fmt.Errorf("mongo.instance_discovery: installation_id, servidor e porta obrigatórios")
	}
	client, err := openMongoClient(cfg, "mongo.instance_discovery")
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
	return &mongoInstanceDiscovery{cfg.GetCheckId(), installationID, engine, server, port, interval, tags, client}, nil
}

func (c *mongoInstanceDiscovery) ID() string              { return c.id }
func (c *mongoInstanceDiscovery) Interval() time.Duration { return c.interval }
func (c *mongoInstanceDiscovery) Tags() map[string]string { return c.tags }
func (c *mongoInstanceDiscovery) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.client.Disconnect(ctx)
}
func (c *mongoInstanceDiscovery) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunInstanceDiscovery(ctx)
	return nil, err
}

func (c *mongoInstanceDiscovery) RunInstanceDiscovery(ctx context.Context) (*DatabaseInstanceDiscovery, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresInstanceDiscoveryTimeout)
	defer cancel()
	var version struct {
		Version string `bson:"version"`
	}
	if err := c.client.Database("admin").RunCommand(qctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&version); err != nil {
		return nil, err
	}
	var result struct {
		Databases []struct {
			Name string `bson:"name"`
		} `bson:"databases"`
	}
	if err := c.client.Database("admin").RunCommand(qctx, bson.D{
		{Key: "listDatabases", Value: 1}, {Key: "nameOnly", Value: true},
		{Key: "authorizedDatabases", Value: true},
	}).Decode(&result); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(result.Databases))
	for _, db := range result.Databases {
		if db.Name != "admin" && db.Name != "config" && db.Name != "local" {
			names = append(names, db.Name)
		}
	}
	return &DatabaseInstanceDiscovery{
		InstallationID: c.installationID, Engine: c.engine, Server: c.server, Port: c.port,
		ServerVersion: version.Version, Databases: names,
	}, nil
}

func init() { Default.Register("mongo.instance_discovery", newMongoInstanceDiscoveryCheck) }
