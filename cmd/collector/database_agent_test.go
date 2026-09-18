package main

import (
	"reflect"
	"testing"
)

func TestDatabaseProfileKeepsLinuxKindAndAdvertisesDatabaseCapabilities(t *testing.T) {
	t.Setenv("ISPWATCH_AGENT_KIND", "linux")
	t.Setenv("ISPWATCH_AGENT_PROFILE", "database")

	if !isDatabaseAgent() {
		t.Fatal("database profile was not detected")
	}
	if got := collectorInstallMode(); got != "linux" {
		t.Fatalf("install mode=%q, want linux", got)
	}
	want := []string{"metrics", "checks", "db-postgres", "host-metrics"}
	if got := collectorCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities=%v, want %v", got, want)
	}
	if got := databaseCollectorName("postgres-01", "12345678-aaaa-4bbb-8ccc-dddddddddddd"); got != "postgres-01 · banco · 12345678" {
		t.Fatalf("collector name=%q", got)
	}
}

func TestDatabaseProfileUsesAgentIdentityInsteadOfInstallationIdentity(t *testing.T) {
	t.Setenv("ISPWATCH_AGENT_PROFILE", "database")
	t.Setenv("ISPWATCH_DATABASE_INSTALLATION_ID", "")
	t.Setenv("ISPWATCH_DATABASE_ENGINE", "postgres")

	if got := databaseEngine(); got != "postgres" {
		t.Fatalf("database engine=%q, want postgres", got)
	}
	if got := databaseCollectorName("postgres-01", "87654321-aaaa-4bbb-8ccc-dddddddddddd"); got != "postgres-01 · banco · 87654321" {
		t.Fatalf("collector name=%q", got)
	}
}

func TestDatabaseAgentIDPersistsSeparatelyFromMachineIdentity(t *testing.T) {
	path := t.TempDir() + "/agent-id"
	t.Setenv("ISPWATCH_DATABASE_AGENT_ID_PATH", path)

	first, err := databaseAgentID()
	if err != nil || !isUUID(first) {
		t.Fatalf("first agent ID=%q err=%v", first, err)
	}
	second, err := databaseAgentID()
	if err != nil || second != first {
		t.Fatalf("agent ID must persist: first=%q second=%q err=%v", first, second, err)
	}
}

func TestDatabaseProfileKeepsDockerKindEvenWhenInstalledBySystemd(t *testing.T) {
	t.Setenv("ISPWATCH_AGENT_KIND", "docker")
	t.Setenv("ISPWATCH_AGENT_PROFILE", "database")
	t.Setenv("ISPWATCH_INSTALL_MODE", "linux")

	if got := collectorInstallMode(); got != "docker" {
		t.Fatalf("database install mode=%q, want docker", got)
	}
}

func TestDatabaseRevocationMarkerIsPersistent(t *testing.T) {
	marker := t.TempDir() + "/database-agent-revoked"
	if databaseAgentRevoked(marker) {
		t.Fatal("marker cannot exist before persistence")
	}
	if err := persistDatabaseAgentRevocation(marker, 410); err != nil {
		t.Fatalf("persist marker: %v", err)
	}
	if !databaseAgentRevoked(marker) {
		t.Fatal("marker should survive after terminal removal")
	}
}

func TestDatabaseProfileDoesNotUseGlobalUpdateMarker(t *testing.T) {
	t.Setenv("ISPWATCH_AGENT_KIND", "linux")
	t.Setenv("ISPWATCH_AGENT_PROFILE", "database")
	t.Setenv("ISPWATCH_UPDATE_MARKER_PATH", t.TempDir()+"/must-not-be-used")

	if got := updateMarkerPath(); got != "" {
		t.Fatalf("database update marker=%q, want empty", got)
	}
}

func TestGenericLinuxAgentKeepsUpdateMarker(t *testing.T) {
	marker := t.TempDir() + "/update-requested"
	t.Setenv("ISPWATCH_AGENT_KIND", "linux")
	t.Setenv("ISPWATCH_AGENT_PROFILE", "")
	t.Setenv("ISPWATCH_UPDATE_MARKER_PATH", marker)

	if got := updateMarkerPath(); got != marker {
		t.Fatalf("generic update marker=%q, want %q", got, marker)
	}
}
