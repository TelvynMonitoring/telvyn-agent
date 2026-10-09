package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type mongoCatalog struct {
	id, installationID, databaseID, engine, server, database string
	interval                                                 time.Duration
	tags                                                     map[string]string
	client                                                   *mongo.Client
}

func newMongoCatalogCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	engine := strings.TrimSpace(cfg.GetStaticTags()["db_engine"])
	database := strings.TrimSpace(cfg.GetStaticTags()["db_name"])
	if installationID == "" || databaseID == "" || database == "" || (engine != "mongodb" && engine != "documentdb") {
		return nil, fmt.Errorf("mongo.catalog: identidade incompleta")
	}
	client, err := openMongoClient(cfg, "mongo.catalog")
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
	return &mongoCatalog{cfg.GetCheckId(), installationID, databaseID, engine,
		strings.TrimSpace(tags["db_server"]), database, interval, tags, client}, nil
}

func (c *mongoCatalog) ID() string              { return c.id }
func (c *mongoCatalog) Interval() time.Duration { return c.interval }
func (c *mongoCatalog) Tags() map[string]string { return c.tags }
func (c *mongoCatalog) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.client.Disconnect(ctx)
}
func (c *mongoCatalog) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunCatalog(ctx)
	return nil, err
}

func (c *mongoCatalog) RunCatalog(ctx context.Context) (*DatabaseCatalog, error) {
	qctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	db := c.client.Database(c.database)
	result := &DatabaseCatalog{
		Engine: c.engine, InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, Schemas: []DatabaseCatalogSchema{{Name: c.database}},
		Tables: make([]DatabaseCatalogTable, 0),
	}
	var version struct {
		Version string `bson:"version"`
	}
	if err := c.client.Database("admin").RunCommand(qctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&version); err != nil {
		return nil, err
	}
	result.ServerVersion = version.Version
	cursor, err := db.ListCollections(qctx, bson.D{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(qctx)
	for cursor.Next(qctx) {
		if len(result.Tables) >= 1000 {
			result.Truncated = true
			break
		}
		var collection struct {
			Name string `bson:"name"`
			Type string `bson:"type"`
		}
		if err := cursor.Decode(&collection); err != nil {
			return nil, err
		}
		if strings.HasPrefix(collection.Name, "system.") {
			continue
		}
		table := DatabaseCatalogTable{SchemaName: c.database, TableName: collection.Name,
			TableKind: strings.ToUpper(collection.Type), Indexes: []DatabaseCatalogIndex{},
			Columns: []DatabaseCatalogColumn{}, Constraints: []DatabaseCatalogConstraint{}}
		if collection.Type == "collection" {
			var stats bson.M
			if err := db.RunCommand(qctx, bson.D{{Key: "collStats", Value: collection.Name}, {Key: "scale", Value: 1}}).Decode(&stats); err == nil {
				if size, ok := mongoMetricNumber(stats, "size"); ok {
					table.TableSizeBytes = int64(size)
				}
				if size, ok := mongoMetricNumber(stats, "totalIndexSize"); ok {
					table.IndexSizeBytes = int64(size)
				}
				if count, ok := mongoMetricNumber(stats, "count"); ok {
					table.EstimatedRows = int64(count)
				}
				table.TotalSizeBytes = table.TableSizeBytes + table.IndexSizeBytes
				result.DatabaseSizeBytes += table.TotalSizeBytes
			}
			indexes, err := db.Collection(collection.Name).Indexes().List(qctx)
			if err == nil {
				for indexes.Next(qctx) {
					if len(table.Indexes) >= 200 {
						result.Truncated = true
						break
					}
					var index bson.M
					if err := indexes.Decode(&index); err != nil {
						indexes.Close(qctx)
						return nil, err
					}
					definition, _ := json.Marshal(index["key"])
					name, _ := index["name"].(string)
					unique, _ := index["unique"].(bool)
					table.Indexes = append(table.Indexes, DatabaseCatalogIndex{
						Name: name, Definition: string(definition), Unique: unique, Primary: name == "_id_",
					})
				}
				if err := indexes.Err(); err != nil {
					indexes.Close(qctx)
					return nil, err
				}
				indexes.Close(qctx)
			}
		}
		result.Tables = append(result.Tables, table)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	result.Fingerprint = structuralCatalogFingerprint(*result)
	return result, nil
}

func init() { Default.Register("mongo.catalog", newMongoCatalogCheck) }
