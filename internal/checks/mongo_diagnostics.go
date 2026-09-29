package checks

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type mongoDiagnostics struct {
	id, installationID, databaseID, engine, server, database string
	interval                                                 time.Duration
	tags                                                     map[string]string
	client                                                   *mongo.Client
}

func newMongoDiagnosticsCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, databaseID := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	if installationID == "" || databaseID == "" {
		return nil, fmt.Errorf("mongo.diagnostics: installation_id e database_id obrigatórios")
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	engine := strings.TrimSpace(tags["db_engine"])
	if engine != "mongodb" && engine != "documentdb" {
		return nil, fmt.Errorf("mongo.diagnostics: motor inválido")
	}
	server, database := strings.TrimSpace(tags["db_server"]), strings.TrimSpace(tags["db_name"])
	if server == "" || database == "" {
		return nil, fmt.Errorf("mongo.diagnostics: db_server e db_name obrigatórios")
	}
	client, err := openMongoClient(cfg, "mongo.diagnostics")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &mongoDiagnostics{cfg.GetCheckId(), installationID, databaseID, engine, server, database, interval, tags, client}, nil
}

func (c *mongoDiagnostics) ID() string              { return c.id }
func (c *mongoDiagnostics) Interval() time.Duration { return c.interval }
func (c *mongoDiagnostics) Tags() map[string]string { return c.tags }
func (c *mongoDiagnostics) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.client.Disconnect(ctx)
}
func (c *mongoDiagnostics) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunDiagnostics(ctx)
	return nil, err
}

func (c *mongoDiagnostics) RunDiagnostics(ctx context.Context) (*DatabaseDiagnostics, error) {
	out := &DatabaseDiagnostics{
		Engine: c.engine, InstallationID: c.installationID, DatabaseID: c.databaseID,
		DBServer: c.server, DBName: c.database, Capabilities: map[string]string{},
		Sessions: []DatabaseSession{}, Blocking: []DatabaseBlocking{}, Waits: []DatabaseWait{},
		Replicas: []DatabaseReplica{}, Bloat: []DatabaseBloat{},
		ReplicationSlots: []DatabaseReplicationSlot{}, MaintenanceOperations: []DatabaseMaintenanceOperation{},
		Errors: []string{},
	}
	qctx, cancel := context.WithTimeout(ctx, sqlDatabaseQueryTimeout)
	defer cancel()
	cursor, err := c.client.Database("admin").Aggregate(qctx, mongo.Pipeline{
		{{Key: "$currentOp", Value: bson.D{{Key: "allUsers", Value: true}, {Key: "idleConnections", Value: false}}}},
		{{Key: "$match", Value: bson.D{{Key: "ns", Value: bson.D{{Key: "$regex", Value: "^" + regexp.QuoteMeta(c.database) + "\\."}}}}}},
		{{Key: "$limit", Value: 200}},
	})
	if err != nil {
		out.Capabilities["sessions"] = "unavailable"
		out.Errors = append(out.Errors, truncateDiagnosticsError("sessions: "+err.Error()))
	} else {
		defer cursor.Close(qctx)
		var decodeErr error
		for cursor.Next(qctx) {
			var operation bson.M
			if decodeErr = cursor.Decode(&operation); decodeErr != nil {
				break
			}
			id := fmt.Sprint(operation["opid"])
			if operation["opid"] == nil {
				id = ""
			}
			client, _ := operation["client"].(string)
			application, _ := operation["appName"].(string)
			state := "idle"
			if active, _ := operation["active"].(bool); active {
				state = "active"
			}
			seconds, _ := mongoMetricNumber(operation, "secs_running")
			out.Sessions = append(out.Sessions, DatabaseSession{Identity: id,
				Application: application, Client: client, State: state, DurationSeconds: seconds})
		}
		if err := cursor.Err(); err != nil {
			out.Capabilities["sessions"] = "unavailable"
			out.Errors = append(out.Errors, truncateDiagnosticsError("sessions: "+err.Error()))
		} else if decodeErr != nil {
			out.Capabilities["sessions"] = "unavailable"
			out.Errors = append(out.Errors, "sessions: resposta inválida")
		} else {
			out.Capabilities["sessions"] = "available"
		}
	}
	if c.engine == "mongodb" {
		var status bson.M
		replCtx, replCancel := context.WithTimeout(ctx, sqlDatabaseQueryTimeout)
		err := c.client.Database("admin").RunCommand(replCtx, bson.D{{Key: "replSetGetStatus", Value: 1}}).Decode(&status)
		replCancel()
		if commandError, ok := err.(mongo.CommandError); ok && commandError.Code == 76 {
			out.Capabilities["replication"] = "available"
		} else if err != nil {
			out.Capabilities["replication"] = "unavailable"
			out.Errors = append(out.Errors, truncateDiagnosticsError("replication: "+err.Error()))
		} else {
			out.Capabilities["replication"] = "available"
			out.Replicas = mongoReplicaMembers(status)
		}
	} else {
		out.Capabilities["replication"] = "unsupported"
	}
	for _, name := range []string{"blocking", "waits", "bloat", "wraparound", "wal", "replication_slots"} {
		out.Capabilities[name] = "unsupported"
	}
	if out.Capabilities["sessions"] != "available" {
		return nil, fmt.Errorf("mongo.diagnostics: operações indisponíveis")
	}
	return out, nil
}

func mongoReplicaMembers(status bson.M) []DatabaseReplica {
	members, _ := status["members"].(bson.A)
	if len(members) > 200 {
		members = members[:200]
	}
	var primaryTime time.Time
	for _, member := range members {
		row, ok := member.(bson.M)
		if !ok || row["stateStr"] != "PRIMARY" {
			continue
		}
		if date, ok := row["optimeDate"].(primitive.DateTime); ok {
			primaryTime = date.Time()
		}
		break
	}
	out := make([]DatabaseReplica, 0, len(members))
	for _, member := range members {
		row, ok := member.(bson.M)
		if !ok {
			continue
		}
		name, _ := row["name"].(string)
		state, _ := row["stateStr"].(string)
		if name == "" || state == "" {
			continue
		}
		replica := DatabaseReplica{Identity: name, State: strings.ToLower(state), Mode: "replica_set"}
		if state == "SECONDARY" && !primaryTime.IsZero() {
			if date, ok := row["optimeDate"].(primitive.DateTime); ok {
				lag := primaryTime.Sub(date.Time()).Seconds()
				if lag < 0 {
					lag = 0
				}
				replica.ReplayLagSeconds = &lag
			}
		}
		out = append(out, replica)
	}
	return out
}

func init() { Default.Register("mongo.diagnostics", newMongoDiagnosticsCheck) }
