package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func TestPostgresInstanceDiscoveryOnlyReturnsConnectableDatabases(t *testing.T) {
	stub := &stubPgxPool{defaultRow: &stubRow{vals: []any{`{
"server_version":"PostgreSQL 17.2",
"databases":["app","reporting"]
}`}}}
	cfg := &collectorv1.CheckConfig{
		CheckId:   "instance-discovery",
		CheckType: "postgres.instance_discovery",
		HostId:    "database-agent-host",
		Interval:  durationpb.New(time.Minute),
		Params: map[string]string{
			"dsn":             "postgres://readonly:secret@postgres.internal:5544/postgres",
			"installation_id": "installation-1",
		},
		StaticTags: map[string]string{"db_server": "postgres.internal", "db_port": "5544"},
	}

	check, err := newPostgresInstanceDiscoveryCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	discovery, err := check.(InstanceDiscoveryCheck).RunInstanceDiscovery(context.Background())
	if err != nil {
		t.Fatalf("RunInstanceDiscovery: %v", err)
	}
	if discovery.InstallationID != "installation-1" || discovery.Engine != "postgres" {
		t.Fatalf("identity = %+v", discovery)
	}
	if discovery.Server != "postgres.internal" || discovery.Port != 5544 {
		t.Fatalf("address = %s:%d", discovery.Server, discovery.Port)
	}
	if tags := check.Tags(); tags["installation_id"] != "installation-1" {
		t.Fatalf("normalized check tags = %#v", tags)
	}
	if len(discovery.Databases) != 2 || discovery.Databases[0] != "app" || discovery.Databases[1] != "reporting" {
		t.Fatalf("databases = %#v", discovery.Databases)
	}
	if len(stub.queries) != 1 || !strings.Contains(stub.queries[0], "has_database_privilege") {
		t.Fatalf("expected CONNECT-filtered query, got %#v", stub.queries)
	}
}

func TestPostgresInstanceDiscoveryRequiresInstallationID(t *testing.T) {
	_, err := newPostgresInstanceDiscoveryCheck(&collectorv1.CheckConfig{
		CheckType: "postgres.instance_discovery",
		Params:    map[string]string{"dsn": "postgres://readonly:secret@postgres.internal/postgres"},
	})
	if err == nil || !strings.Contains(err.Error(), "installation_id") {
		t.Fatalf("error = %v, want installation_id requirement", err)
	}
}
