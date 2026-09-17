package ebpf

import (
	"testing"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func postgresMonitorConfig(id, monitorID, server, port string) *collectorv1.CheckConfig {
	return &collectorv1.CheckConfig{
		CheckId:   id,
		CheckType: "postgres.server",
		StaticTags: map[string]string{
			"db_monitor_id": monitorID,
			"db_server":     server,
			"db_port":       port,
		},
	}
}

func TestDatabaseMonitorRegistry_MatchesConfiguredPostgresEndpoint(t *testing.T) {
	registry := NewDatabaseMonitorRegistry()
	registry.ApplyPostgresServerDelta([]*collectorv1.CheckConfig{
		postgresMonitorConfig("check-a", "monitor-a", "192.0.2.15", "5432"),
	}, nil)

	if got := registry.MatchPostgresEndpoint("192.0.2.15", 5432); got != "monitor-a" {
		t.Fatalf("match = %q, want monitor-a", got)
	}
	if got := registry.MatchPostgresEndpoint("192.0.2.15", 5433); got != "" {
		t.Fatalf("wrong port must not match, got %q", got)
	}
}

func TestDatabaseMonitorRegistry_DeltaRemovesAndReplacesTargets(t *testing.T) {
	registry := NewDatabaseMonitorRegistry()
	registry.ApplyPostgresServerDelta([]*collectorv1.CheckConfig{
		postgresMonitorConfig("check-a", "monitor-a", "192.0.2.15", "5432"),
	}, nil)
	registry.ApplyPostgresServerDelta([]*collectorv1.CheckConfig{
		postgresMonitorConfig("check-a", "monitor-b", "192.0.2.16", "5432"),
	}, nil)

	if got := registry.MatchPostgresEndpoint("192.0.2.15", 5432); got != "" {
		t.Fatalf("old endpoint was retained as %q", got)
	}
	if got := registry.MatchPostgresEndpoint("192.0.2.16", 5432); got != "monitor-b" {
		t.Fatalf("replacement match = %q, want monitor-b", got)
	}

	registry.ApplyPostgresServerDelta(nil, []string{"check-a"})
	if got := registry.MatchPostgresEndpoint("192.0.2.16", 5432); got != "" {
		t.Fatalf("deleted endpoint was retained as %q", got)
	}
}

func TestDatabaseMonitorRegistry_RefusesAmbiguousDatabaseEndpoint(t *testing.T) {
	registry := NewDatabaseMonitorRegistry()
	registry.ApplyPostgresServerDelta([]*collectorv1.CheckConfig{
		postgresMonitorConfig("check-a", "monitor-a", "192.0.2.15", "5432"),
		postgresMonitorConfig("check-b", "monitor-b", "192.0.2.15", "5432"),
	}, nil)

	if got := registry.MatchPostgresEndpoint("192.0.2.15", 5432); got != "" {
		t.Fatalf("ambiguous endpoint must not be attributed, got %q", got)
	}
}

func TestDatabaseMonitorRegistry_RequiresExplicitPostgresIdentityTags(t *testing.T) {
	registry := NewDatabaseMonitorRegistry()
	registry.ApplyPostgresServerDelta([]*collectorv1.CheckConfig{
		{CheckId: "not-postgres", CheckType: "mysql.server", StaticTags: map[string]string{
			"db_monitor_id": "monitor-a", "db_server": "192.0.2.15", "db_port": "5432",
		}},
		{CheckId: "missing-monitor", CheckType: "postgres.server", StaticTags: map[string]string{
			"db_server": "192.0.2.15", "db_port": "5432",
		}},
	}, nil)

	if got := registry.MatchPostgresEndpoint("192.0.2.15", 5432); got != "" {
		t.Fatalf("incomplete/non-Postgres config must not match, got %q", got)
	}
}
