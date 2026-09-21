//go:build postgres_integration

package checks

import (
	"context"
	"os"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// TestPostgresCompatibilityMatrix is executed by the CI matrix against every
// certified PostgreSQL major. It deliberately runs the same capability-driven
// collectors on every version; adding version switches to the test would hide
// exactly the regressions this contract is intended to catch.
func TestPostgresCompatibilityMatrix(t *testing.T) {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	config := func(checkType string) *collectorv1.CheckConfig {
		return &collectorv1.CheckConfig{
			CheckId: checkType + "-compat", CheckType: checkType, HostId: "compat-host",
			Interval: durationpb.New(time.Minute),
			Params: map[string]string{
				"dsn":             dsn,
				"installation_id": "11111111-1111-1111-1111-111111111111",
				"database_id":     "22222222-2222-2222-2222-222222222222",
			},
			StaticTags: map[string]string{
				"db_server": "127.0.0.1", "db_port": "5432", "db_name": "postgres",
			},
		}
	}

	t.Run("instance discovery", func(t *testing.T) {
		check, err := newPostgresInstanceDiscoveryCheck(config("postgres.instance_discovery"))
		if err != nil {
			t.Fatalf("factory: %v", err)
		}
		defer check.(interface{ Close() error }).Close()
		result, err := check.(InstanceDiscoveryCheck).RunInstanceDiscovery(ctx)
		if err != nil || result.ServerVersion == "" || len(result.Databases) == 0 {
			t.Fatalf("discovery: result=%+v err=%v", result, err)
		}
	})

	t.Run("query metrics", func(t *testing.T) {
		check, err := newPostgresQueriesCheck(config("postgres.queries"))
		if err != nil {
			t.Fatalf("factory: %v", err)
		}
		defer check.(interface{ Close() error }).Close()
		if _, err := check.(QueryStatsCheck).RunQueryStats(ctx); err != nil {
			t.Fatalf("query metrics: %v", err)
		}
	})

	t.Run("diagnostics", func(t *testing.T) {
		check, err := newPostgresDiagnosticsCheck(config("postgres.diagnostics"))
		if err != nil {
			t.Fatalf("factory: %v", err)
		}
		defer check.(interface{ Close() error }).Close()
		result, err := check.(DiagnosticsCheck).RunDiagnostics(ctx)
		if err != nil {
			t.Fatalf("diagnostics: %v", err)
		}
		if result.Capabilities["sessions"] != "available" {
			t.Fatalf("sessions capability: %+v", result.Capabilities)
		}
	})

	t.Run("catalog", func(t *testing.T) {
		check, err := newPostgresCatalogCheck(config("postgres.catalog"))
		if err != nil {
			t.Fatalf("factory: %v", err)
		}
		defer check.(interface{ Close() error }).Close()
		result, err := check.(CatalogCheck).RunCatalog(ctx)
		if err != nil || result.ServerVersion == "" {
			t.Fatalf("catalog: result=%+v err=%v", result, err)
		}
	})
}
