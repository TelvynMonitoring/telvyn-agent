package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var mongoCustomCollection = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,119}$`)

type mongoCustomDefinition struct {
	Operation  string         `json:"operation"`
	Collection string         `json:"collection"`
	Filter     map[string]any `json:"filter"`
}

func parseMongoCustomDefinition(raw string, columns []postgresCustomColumn) (mongoCustomDefinition, error) {
	var definition mongoCustomDefinition
	if len(raw) > 8000 || json.Unmarshal([]byte(raw), &definition) != nil || !mongoCustomCollection.MatchString(definition.Collection) {
		return definition, fmt.Errorf("mongo.custom: definição inválida")
	}
	if definition.Operation != "count" && definition.Operation != "find" {
		return definition, fmt.Errorf("mongo.custom: use count ou find")
	}
	if (definition.Operation == "count" && len(columns) != 0) || (definition.Operation == "find" && len(columns) == 0) {
		return definition, fmt.Errorf("mongo.custom: find exige colunas tipadas; count é escalar")
	}
	if !safeMongoCustomFilter(definition.Filter) {
		return definition, fmt.Errorf("mongo.custom: filtro não permitido")
	}
	return definition, nil
}

func safeMongoCustomFilter(filter map[string]any) bool {
	for key, value := range filter {
		if key == "" || strings.HasPrefix(key, "$") || strings.ContainsRune(key, '\x00') {
			return false
		}
		if !safeMongoCustomValue(value) {
			return false
		}
	}
	return true
}

func safeMongoCustomValue(value any) bool {
	switch nested := value.(type) {
	case map[string]any:
		return safeMongoCustomFilter(nested)
	case []any:
		for _, item := range nested {
			if !safeMongoCustomValue(item) {
				return false
			}
		}
	}
	return true
}

type mongoCustom struct {
	id, hostID, engine, metricName, database string
	definition                               mongoCustomDefinition
	columns                                  []postgresCustomColumn
	rowLimit                                 int
	interval                                 time.Duration
	tags                                     map[string]string
	client                                   *mongo.Client
}

func newMongoCustomCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	engine := cfg.GetStaticTags()["db_engine"]
	if engine != "mongodb" && engine != "documentdb" {
		return nil, fmt.Errorf("mongo.custom: motor inválido")
	}
	if strings.TrimSpace(cfg.GetStaticTags()["db_name"]) == "" {
		return nil, fmt.Errorf("mongo.custom: db_name obrigatório")
	}
	metricName := strings.TrimSpace(params["metric_name"])
	if !postgresCustomMetricName.MatchString(metricName) {
		return nil, fmt.Errorf("mongo.custom: métrica inválida")
	}
	columns, err := parsePostgresCustomColumns(params["columns_json"])
	if err != nil {
		return nil, err
	}
	definition, err := parseMongoCustomDefinition(params["query"], columns)
	if err != nil {
		return nil, err
	}
	client, err := openMongoClient(cfg, "mongo.custom")
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	normalizeDatabaseMetricTags(params, tags)
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = time.Minute
	}
	return &mongoCustom{cfg.GetCheckId(), cfg.GetHostId(), engine, metricName, tags["db_name"],
		definition, columns, boundedParam(params, "row_limit", 1, postgresCustomMaxRows, 10), interval, tags, client}, nil
}

func (c *mongoCustom) ID() string              { return c.id }
func (c *mongoCustom) Interval() time.Duration { return c.interval }
func (c *mongoCustom) Tags() map[string]string { return c.tags }
func (c *mongoCustom) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.client.Disconnect(ctx)
}
func (c *mongoCustom) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresCustomQueryTimeout)
	defer cancel()
	collection := c.client.Database(c.database).Collection(c.definition.Collection)
	filter := bson.M(c.definition.Filter)
	if c.definition.Operation == "count" {
		count, err := collection.CountDocuments(qctx, filter)
		if err != nil {
			return nil, err
		}
		return []*collectorv1.Metric{c.metric(c.metricName, float64(count), "", c.tags)}, nil
	}
	projection := bson.M{"_id": 0}
	for _, column := range c.columns {
		projection[column.Name] = 1
	}
	cursor, err := collection.Find(qctx, filter, options.Find().SetLimit(int64(c.rowLimit)).SetProjection(projection))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(qctx)
	out := make([]*collectorv1.Metric, 0)
	for cursor.Next(qctx) {
		var row bson.M
		if err := cursor.Decode(&row); err != nil {
			return nil, err
		}
		tags := make(map[string]string, len(c.tags)+len(c.columns))
		for key, value := range c.tags {
			tags[key] = value
		}
		for _, column := range c.columns {
			if column.Type == "tag" {
				tags["custom."+column.Name] = limitText(fmt.Sprint(row[column.Name]), postgresCustomMaxTagValue)
			}
		}
		for _, column := range c.columns {
			if column.Type == "tag" {
				continue
			}
			value, err := numericValue(row[column.Name])
			if err != nil {
				return nil, fmt.Errorf("mongo.custom: coluna %s não numérica: %w", column.Name, err)
			}
			out = append(out, c.metric(c.metricName+"."+column.Name, value, column.Type, tags))
		}
	}
	return out, cursor.Err()
}

func (c *mongoCustom) metric(name string, value float64, kind string, base map[string]string) *collectorv1.Metric {
	tags := make(map[string]string, len(base)+2)
	for key, item := range base {
		tags[key] = item
	}
	tags["custom_query"] = tags["custom_name"]
	if kind != "" {
		tags["custom_metric_type"] = kind
	}
	return &collectorv1.Metric{Time: timestamppb.Now(), HostId: c.hostID,
		MetricName: c.engine + ".custom." + name, Value: value, Tags: tags, Source: c.engine + ".custom"}
}

func init() { Default.Register("mongo.custom", newMongoCustomCheck) }
