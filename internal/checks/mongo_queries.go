package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Active operations are observable over the Mongo wire protocol, including
// DocumentDB. Completed-operation ranking needs each provider's profiler.
type mongoQueries struct {
	diagnostic  *mongoDiagnostics
	mu          sync.Mutex
	seen        map[string]time.Time
	seenSamples map[string]time.Time
}

func newMongoQueriesCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	check, err := newMongoDiagnosticsCheck(cfg)
	if err != nil {
		return nil, err
	}
	return &mongoQueries{diagnostic: check.(*mongoDiagnostics), seen: make(map[string]time.Time),
		seenSamples: make(map[string]time.Time)}, nil
}

func (c *mongoQueries) ID() string                    { return c.diagnostic.ID() }
func (c *mongoQueries) Interval() time.Duration       { return c.diagnostic.Interval() }
func (c *mongoQueries) Tags() map[string]string       { return c.diagnostic.Tags() }
func (c *mongoQueries) Close() error                  { return c.diagnostic.Close() }
func (c *mongoQueries) SampleInterval() time.Duration { return 15 * time.Second }

func (c *mongoQueries) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunQueryStats(ctx)
	return nil, err
}

func (c *mongoQueries) RunQueryStats(ctx context.Context) (*DatabaseQueryStats, error) {
	result := &DatabaseQueryStats{Engine: c.diagnostic.engine, InstallationID: c.diagnostic.installationID,
		DatabaseID: c.diagnostic.databaseID, DBServer: c.diagnostic.server, DBName: c.diagnostic.database,
		WindowSeconds: max(1, int(c.Interval()/time.Second)), Queries: []DatabaseQueryStat{}}
	if c.diagnostic.engine == "documentdb" {
		return result, nil // DocumentDB publishes completed-operation profiles to CloudWatch, not system.profile.
	}
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	database := c.diagnostic.client.Database(c.diagnostic.database)
	names, err := database.ListCollectionNames(qctx, bson.D{{Key: "name", Value: "system.profile"}})
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("mongo.queries: profiler não configurado neste banco")
	}
	cursor, err := database.Collection("system.profile").Find(qctx,
		bson.D{{Key: "ts", Value: bson.D{{Key: "$gte", Value: time.Now().Add(-5 * time.Minute)}}},
			{Key: "ns", Value: bson.D{{Key: "$ne", Value: c.diagnostic.database + ".system.profile"}}}},
		options.Find().SetLimit(5000).SetSort(bson.D{{Key: "ts", Value: -1}}).
			SetProjection(bson.D{{Key: "op", Value: 1}, {Key: "ns", Value: 1},
				{Key: "planSummary", Value: 1}, {Key: "millis", Value: 1}, {Key: "nreturned", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(qctx)
	groups := map[string]*DatabaseQueryStat{}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, observed := range c.seen {
		if time.Since(observed) > 6*time.Minute {
			delete(c.seen, key)
		}
	}
	for cursor.Next(qctx) {
		var row bson.M
		if err := cursor.Decode(&row); err != nil {
			return nil, err
		}
		id := fmt.Sprint(row["_id"])
		if _, found := c.seen[id]; found {
			continue
		}
		c.seen[id] = time.Now()
		label := mongoProfileLabel(row)
		if label == "" {
			continue
		}
		hash := sha256.Sum256([]byte(label))
		key := hex.EncodeToString(hash[:16])
		entry := groups[key]
		if entry == nil {
			entry = &DatabaseQueryStat{QueryID: key, Text: label}
			groups[key] = entry
		}
		entry.Calls++
		if millis, ok := mongoMetricNumber(row, "millis"); ok {
			entry.TotalMS += millis
		}
		if returned, ok := mongoMetricNumber(row, "nreturned"); ok {
			entry.Rows += int64(returned)
		}
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	for _, entry := range groups {
		entry.MeanMS = entry.TotalMS / float64(entry.Calls)
		result.Queries = append(result.Queries, *entry)
	}
	return result, nil
}

func mongoProfileLabel(row bson.M) string {
	fields := make([]string, 0, 3)
	for _, key := range []string{"op", "ns", "planSummary"} {
		if value, ok := row[key].(string); ok && value != "" {
			fields = append(fields, limitText(value, 128))
		}
	}
	return strings.Join(fields, " ")
}

func (c *mongoQueries) RunQuerySamples(ctx context.Context) (*DatabaseQueryStats, error) {
	diagnostics, err := c.diagnostic.RunDiagnostics(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	samples := make([]DatabaseQuerySample, 0, len(diagnostics.Sessions))
	for _, session := range diagnostics.Sessions {
		if session.State != "active" {
			continue
		}
		samples = append(samples, DatabaseQuerySample{SampleID: session.Identity + ":" + now,
			QueryID: session.Identity, Text: "operação ativa", Application: session.Application,
			Client: session.Client, State: session.State, DurationMS: session.DurationSeconds * 1000,
			SampledAt: now, PlanStatus: "unsupported"})
	}
	if c.diagnostic.engine == "mongodb" {
		samples = append(samples, c.profileSamples(ctx)...)
	}
	return &DatabaseQueryStats{Engine: c.diagnostic.engine, InstallationID: c.diagnostic.installationID,
		DatabaseID: c.diagnostic.databaseID, DBServer: c.diagnostic.server, DBName: c.diagnostic.database,
		WindowSeconds: 15, Samples: samples}, nil
}

func (c *mongoQueries) profileSamples(ctx context.Context) []DatabaseQuerySample {
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	database := c.diagnostic.client.Database(c.diagnostic.database)
	names, err := database.ListCollectionNames(qctx, bson.D{{Key: "name", Value: "system.profile"}})
	if err != nil || len(names) == 0 {
		return nil
	}
	cursor, err := database.Collection("system.profile").Find(qctx,
		bson.D{{Key: "ts", Value: bson.D{{Key: "$gte", Value: time.Now().Add(-30 * time.Second)}}},
			{Key: "ns", Value: bson.D{{Key: "$ne", Value: c.diagnostic.database + ".system.profile"}}}},
		options.Find().SetLimit(50).SetSort(bson.D{{Key: "ts", Value: -1}}).
			SetProjection(bson.D{{Key: "op", Value: 1}, {Key: "ns", Value: 1}, {Key: "planSummary", Value: 1},
				{Key: "millis", Value: 1}, {Key: "ts", Value: 1}}))
	if err != nil {
		return nil
	}
	defer cursor.Close(qctx)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, observed := range c.seenSamples {
		if now.Sub(observed) > time.Minute {
			delete(c.seenSamples, key)
		}
	}
	samples := make([]DatabaseQuerySample, 0)
	for cursor.Next(qctx) {
		var row bson.M
		if cursor.Decode(&row) != nil {
			break
		}
		id := fmt.Sprint(row["_id"])
		if _, found := c.seenSamples[id]; found {
			continue
		}
		label := mongoProfileLabel(row)
		if label == "" {
			continue
		}
		c.seenSamples[id] = now
		hash := sha256.Sum256([]byte(label))
		sample := DatabaseQuerySample{SampleID: id, QueryID: hex.EncodeToString(hash[:16]), Text: label,
			State: "finished", SampledAt: now.UTC().Format(time.RFC3339Nano), PlanStatus: "unavailable"}
		if duration, ok := mongoMetricNumber(row, "millis"); ok {
			sample.DurationMS = duration
		}
		if observed, ok := row["ts"].(time.Time); ok {
			sample.SampledAt = observed.UTC().Format(time.RFC3339Nano)
		}
		if summary, ok := row["planSummary"].(string); ok {
			fields := strings.Fields(summary)
			if len(fields) > 0 {
				sample.PlanJSON, _ = json.Marshal(map[string]any{"Plan": map[string]any{"Node Type": limitText(fields[0], 64)}})
				sample.PlanStatus = "ready"
			}
		}
		samples = append(samples, sample)
	}
	return samples
}

func init() { Default.Register("mongo.queries", newMongoQueriesCheck) }
