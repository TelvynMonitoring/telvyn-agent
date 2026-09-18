package checks

import "strings"

// databaseIdentity lê os IDs imutáveis que o backend entrega junto de cada
// check de banco. db_monitor_id é o nome legado já usado pelo Agent/eBPF;
// database_id é o contrato novo do ingest estrito. Aceitamos os dois no pull e
// normalizamos para database_id nos payloads novos.
func databaseIdentity(params, tags map[string]string) (installationID, databaseID string) {
	installationID = firstDatabaseIdentity(tags, "installation_id")
	if installationID == "" {
		installationID = firstDatabaseIdentity(params, "installation_id")
	}
	databaseID = firstDatabaseIdentity(tags, "database_id", "db_monitor_id")
	if databaseID == "" {
		databaseID = firstDatabaseIdentity(params, "database_id", "db_monitor_id")
	}
	return installationID, databaseID
}

// normalizeDatabaseMetricTags preserves the legacy tag and adds the canonical
// immutable IDs so generic OTLP metrics can be authorized by instance/child.
func normalizeDatabaseMetricTags(params, tags map[string]string) {
	installationID, databaseID := databaseIdentity(params, tags)
	if installationID != "" {
		tags["installation_id"] = installationID
	}
	if databaseID != "" {
		tags["database_id"] = databaseID
	}
}

func firstDatabaseIdentity(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}
