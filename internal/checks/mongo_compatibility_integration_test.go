package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"go.mongodb.org/mongo-driver/bson"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestMongoDiscoveryCompatibility(t *testing.T) {
	dsn := os.Getenv("MONGO_TEST_DSN")
	if dsn == "" {
		t.Skip("set MONGO_TEST_DSN for a local MongoDB instance")
	}
	cfg := &collectorv1.CheckConfig{
		CheckId: "mongo-discovery-integration", CheckType: "mongo.instance_discovery", HostId: "host",
		Interval:   durationpb.New(time.Minute),
		Params:     map[string]string{"dsn": dsn, "installation_id": "installation-1"},
		StaticTags: map[string]string{"db_engine": "mongodb", "db_server": "127.0.0.1", "db_port": "27017"},
	}
	check, err := newMongoInstanceDiscoveryCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	result, err := check.(InstanceDiscoveryCheck).RunInstanceDiscovery(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Engine != "mongodb" || result.ServerVersion == "" {
		t.Fatalf("invalid discovery: %+v", result)
	}
	if expected := os.Getenv("MONGO_TEST_EXPECT_DATABASE"); expected != "" {
		found := false
		for _, name := range result.Databases {
			if name == expected {
				found = true
			}
		}
		if !found {
			t.Fatalf("database %q not discovered: %+v", expected, result.Databases)
		}
	}
	cfg.CheckType = "mongo.server"
	cfg.StaticTags["db_name"] = "app"
	server, err := newMongoServerCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.(interface{ Close() error }).Close()
	metrics, err := server.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"mongodb.total_connections": false, "mongodb.database_size_bytes": false}
	for _, metric := range metrics {
		if _, ok := want[metric.MetricName]; ok {
			want[metric.MetricName] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("metric %s missing", name)
		}
	}
	cfg.CheckType = "mongo.catalog"
	cfg.Params["database_id"] = "database-1"
	catalogCheck, err := newMongoCatalogCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer catalogCheck.(interface{ Close() error }).Close()
	catalog, err := catalogCheck.(CatalogCheck).RunCatalog(context.Background())
	if err != nil || catalog.Engine != "mongodb" {
		t.Fatalf("MongoDB catalog: %+v, %v", catalog, err)
	}
	for _, table := range catalog.Tables {
		if table.TableName == "telvyn_test" && len(table.Indexes) > 0 {
			return
		}
	}
	t.Fatalf("MongoDB catalog missing telvyn_test and its index: %+v", catalog.Tables)
}

func TestMongoDiagnosticsCompatibility(t *testing.T) {
	dsn := os.Getenv("MONGO_TEST_DSN")
	if dsn == "" {
		t.Skip("set MONGO_TEST_DSN for a local MongoDB instance")
	}
	cfg := &collectorv1.CheckConfig{CheckId: "mongo-diagnostics-integration", HostId: "host",
		Interval:   durationpb.New(15 * time.Second),
		Params:     map[string]string{"dsn": dsn, "installation_id": "installation-1", "database_id": "database-1"},
		StaticTags: map[string]string{"db_engine": "mongodb", "db_server": "mongo-test", "db_name": "app"}}
	check, err := newMongoDiagnosticsCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	snapshot, err := check.(DiagnosticsCheck).RunDiagnostics(context.Background())
	if err != nil || snapshot.Engine != "mongodb" || snapshot.Capabilities["sessions"] != "available" || snapshot.Capabilities["replication"] != "available" {
		t.Fatalf("MongoDB diagnostics: %+v, %v", snapshot, err)
	}
	if os.Getenv("MONGO_TEST_EXPECT_REPLICA") != "" && len(snapshot.Replicas) == 0 {
		t.Fatalf("MongoDB replica set returned no members: %+v", snapshot)
	}
}

func TestMongoCustomCompatibility(t *testing.T) {
	dsn := os.Getenv("MONGO_TEST_DSN")
	if dsn == "" {
		t.Skip("set MONGO_TEST_DSN for a local MongoDB instance")
	}
	for _, engine := range []string{"mongodb", "documentdb"} {
		t.Run(engine, func(t *testing.T) {
			cfg := &collectorv1.CheckConfig{CheckId: "mongo-custom-integration", HostId: "host",
				Interval: durationpb.New(time.Minute),
				Params: map[string]string{"dsn": dsn, "query": `{"operation":"count","collection":"telvyn_test","filter":{}}`,
					"metric_name": "test.count"},
				StaticTags: map[string]string{"db_engine": engine, "db_server": "mongo-test", "db_name": "app"}}
			check, err := newMongoCustomCheck(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer check.(interface{ Close() error }).Close()
			metrics, err := check.Run(context.Background())
			if err != nil || len(metrics) != 1 || metrics[0].MetricName != engine+".custom.test.count" || metrics[0].Source != engine+".custom" {
				t.Fatalf("custom count: %+v, %v", metrics, err)
			}
			cfg.Params["query"] = `{"operation":"find","collection":"telvyn_test","filter":{}}`
			cfg.Params["columns_json"] = `[{"name":"id","type":"gauge"}]`
			find, err := newMongoCustomCheck(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer find.(interface{ Close() error }).Close()
			metrics, err = find.Run(context.Background())
			if err != nil || len(metrics) == 0 || metrics[0].MetricName != engine+".custom.test.count.id" {
				t.Fatalf("custom typed find: %+v, %v", metrics, err)
			}
		})
	}
}

func TestMongoQueriesCompatibility(t *testing.T) {
	dsn := os.Getenv("MONGO_TEST_DSN")
	if dsn == "" {
		t.Skip("set MONGO_TEST_DSN for a local MongoDB instance")
	}
	cfg := &collectorv1.CheckConfig{CheckId: "mongo-queries-integration", HostId: "host",
		Interval:   durationpb.New(time.Minute),
		Params:     map[string]string{"dsn": dsn, "installation_id": "installation-1", "database_id": "database-1"},
		StaticTags: map[string]string{"db_engine": "mongodb", "db_server": "mongo-test", "db_name": "app"}}
	check, err := newMongoQueriesCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	samples, err := check.(QuerySamplesCheck).RunQuerySamples(context.Background())
	if err != nil || samples.Engine != "mongodb" {
		t.Fatalf("MongoDB samples: %+v, %v", samples, err)
	}
	for _, sample := range samples.Samples {
		if sample.Text != "operação ativa" {
			t.Fatalf("MongoDB raw command leaked: %+v", sample)
		}
	}
	if os.Getenv("MONGO_TEST_PROFILE") == "1" {
		queryCheck := check.(QueryStatsCheck)
		if _, err := queryCheck.RunQueryStats(context.Background()); err != nil {
			t.Fatal(err)
		}
		client := check.(*mongoQueries).diagnostic.client
		_ = client.Database("app").Collection("telvyn_test").FindOne(context.Background(), bson.M{}).Err()
		stats, err := queryCheck.RunQueryStats(context.Background())
		if err != nil || len(stats.Queries) == 0 {
			t.Fatalf("MongoDB profiler metrics: %+v, %v", stats, err)
		}
		samples, err := check.(QuerySamplesCheck).RunQuerySamples(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, sample := range samples.Samples {
			if sample.State == "finished" && sample.PlanStatus == "ready" {
				found = true
			}
			if strings.Contains(sample.Text, "private@example.test") {
				t.Fatal("profile sample leaked query values")
			}
		}
		if !found {
			t.Fatalf("MongoDB profile plan summary missing: %+v", samples.Samples)
		}
	}
}

func TestDocumentDBWireContract(t *testing.T) {
	dsn := os.Getenv("MONGO_TEST_DSN")
	if dsn == "" {
		t.Skip("set MONGO_TEST_DSN for a local Mongo wire-compatible instance")
	}
	cfg := &collectorv1.CheckConfig{CheckId: "documentdb-wire-integration", HostId: "host",
		Interval:   durationpb.New(time.Minute),
		Params:     map[string]string{"dsn": dsn, "installation_id": "installation-1", "database_id": "database-1"},
		StaticTags: map[string]string{"db_engine": "documentdb", "db_server": "mongo-test", "db_name": "app"}}
	check, err := newMongoQueriesCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer check.(interface{ Close() error }).Close()
	stats, err := check.(QueryStatsCheck).RunQueryStats(context.Background())
	if err != nil || stats.Engine != "documentdb" || len(stats.Queries) != 0 {
		t.Fatalf("DocumentDB completed operations must not use MongoDB system.profile: %+v, %v", stats, err)
	}
	samples, err := check.(QuerySamplesCheck).RunQuerySamples(context.Background())
	if err != nil || samples.Engine != "documentdb" {
		t.Fatalf("DocumentDB active samples: %+v, %v", samples, err)
	}
}
