package checks

import (
	"context"
	"testing"
	"time"
)

type runtimeDiagnosticsCheck struct {
	countingCheck
	tags map[string]string
}

func (c *runtimeDiagnosticsCheck) Tags() map[string]string { return c.tags }
func (c *runtimeDiagnosticsCheck) RunDiagnostics(_ context.Context) (*DatabaseDiagnostics, error) {
	return &DatabaseDiagnostics{}, nil
}

func TestDatabaseExecutionReportContainsOnlyDatabaseIdentity(t *testing.T) {
	check := &runtimeDiagnosticsCheck{
		countingCheck: countingCheck{id: "diag-1", interval: time.Minute},
		tags: map[string]string{
			"installation_id": "installation-1",
			"database_id":     "database-1",
			"password":        "must-not-leave-agent",
		},
	}
	report := databaseExecutionReport(check, false, true, "timeout", 125*time.Millisecond)
	if report.CheckSignal != "diagnostics_snapshot" || report.Tags["database_id"] != "database-1" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if _, leaked := report.Tags["password"]; leaked {
		t.Fatal("runtime report leaked a non-identity tag")
	}
}
