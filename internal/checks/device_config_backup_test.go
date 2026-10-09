package checks

import (
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func TestDeviceConfigBackupRestoresNextRun(t *testing.T) {
	params := map[string]string{
		"host_id": "test-host", "target": "192.0.2.1", "vendor": "mikrotik",
		"ssh_user": "test", "ssh_secret": "test-only", "next_run_at": "2030-01-02T03:00:00Z",
	}
	for i := 0; i < 2; i++ {
		check, err := newDeviceConfigBackupCheck(&collectorv1.CheckConfig{Params: params})
		if err != nil {
			t.Fatal(err)
		}
		want, _ := time.Parse(time.RFC3339, params["next_run_at"])
		if got := check.(*deviceConfigBackupCheck).InitialRunAt(); !got.Equal(want) {
			t.Fatalf("recreated check lost schedule: got %v, want %v", got, want)
		}
	}
	params["next_run_at"] = "invalid"
	if _, err := newDeviceConfigBackupCheck(&collectorv1.CheckConfig{Params: params}); err == nil {
		t.Fatal("invalid schedule must not run immediately")
	}
}
