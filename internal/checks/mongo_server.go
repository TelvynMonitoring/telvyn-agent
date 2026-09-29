package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mongoServer struct {
	id, hostID, engine, database string
	interval                     time.Duration
	tags                         map[string]string
	client                       *mongo.Client
}

func newMongoServerCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	engine := strings.TrimSpace(cfg.GetStaticTags()["db_engine"])
	if engine != "mongodb" && engine != "documentdb" {
		return nil, fmt.Errorf("mongo.server: motor inválido")
	}
	database := strings.TrimSpace(cfg.GetStaticTags()["db_name"])
	if database == "" {
		return nil, fmt.Errorf("mongo.server: db_name obrigatório")
	}
	client, err := openMongoClient(cfg, "mongo.server")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = time.Minute
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	return &mongoServer{cfg.GetCheckId(), cfg.GetHostId(), engine, database, interval, tags, client}, nil
}

func (c *mongoServer) ID() string              { return c.id }
func (c *mongoServer) Interval() time.Duration { return c.interval }
func (c *mongoServer) Tags() map[string]string { return c.tags }
func (c *mongoServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.client.Disconnect(ctx)
}

func mongoMetricNumber(document bson.M, path ...string) (float64, bool) {
	var current any = document
	for _, key := range path {
		object, ok := current.(bson.M)
		if !ok {
			return 0, false
		}
		current, ok = object[key]
		if !ok {
			return 0, false
		}
	}
	switch value := current.(type) {
	case int32:
		return float64(value), true
	case int64:
		return float64(value), true
	case float64:
		return value, true
	default:
		return 0, false
	}
}

func (c *mongoServer) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var status bson.M
	if err := c.client.Database("admin").RunCommand(qctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&status); err != nil {
		return nil, err
	}
	var stats bson.M
	if err := c.client.Database(c.database).RunCommand(qctx, bson.D{{Key: "dbStats", Value: 1}, {Key: "scale", Value: 1}}).Decode(&stats); err != nil {
		return nil, err
	}
	now := timestamppb.Now()
	metrics := make([]*collectorv1.Metric, 0, 8)
	appendMetric := func(name string, document bson.M, path ...string) {
		if value, ok := mongoMetricNumber(document, path...); ok {
			metrics = append(metrics, &collectorv1.Metric{
				Time: now, HostId: c.hostID, MetricName: c.engine + "." + name,
				Value: value, Tags: c.tags, Source: "mongo.server",
			})
		}
	}
	appendMetric("total_connections", status, "connections", "current")
	appendMetric("available_connections", status, "connections", "available")
	appendMetric("query_operations", status, "opcounters", "query")
	appendMetric("insert_operations", status, "opcounters", "insert")
	appendMetric("update_operations", status, "opcounters", "update")
	appendMetric("delete_operations", status, "opcounters", "delete")
	appendMetric("database_size_bytes", stats, "dataSize")
	appendMetric("storage_size_bytes", stats, "storageSize")
	appendMetric("index_size_bytes", stats, "indexSize")
	if len(metrics) == 0 {
		return nil, fmt.Errorf("mongo.server: nenhuma métrica disponível")
	}
	return metrics, nil
}

func init() { Default.Register("mongo.server", newMongoServerCheck) }
