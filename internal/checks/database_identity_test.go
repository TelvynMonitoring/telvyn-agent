package checks

import "testing"

func TestNormalizeDatabaseMetricTagsUsesImmutableLegacyFallback(t *testing.T) {
	params := map[string]string{
		"installation_id": "installation-1",
		"db_monitor_id":  "logical-db-1",
	}
	tags := map[string]string{"db_name": "app"}

	normalizeDatabaseMetricTags(params, tags)

	if got := tags["installation_id"]; got != "installation-1" {
		t.Fatalf("installation_id=%q", got)
	}
	if got := tags["database_id"]; got != "logical-db-1" {
		t.Fatalf("database_id=%q", got)
	}
	if _, ok := tags["db_monitor_id"]; ok {
		t.Fatal("legacy ID from params must be normalized, not copied as a metric tag")
	}
}

func TestNormalizeDatabaseMetricTagsPreservesStaticLegacyTag(t *testing.T) {
	tags := map[string]string{"db_monitor_id": "logical-db-1"}

	normalizeDatabaseMetricTags(nil, tags)

	if got := tags["database_id"]; got != "logical-db-1" {
		t.Fatalf("database_id=%q", got)
	}
	if got := tags["db_monitor_id"]; got != "logical-db-1" {
		t.Fatalf("db_monitor_id=%q", got)
	}
}
