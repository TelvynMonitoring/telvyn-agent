package checks

import "testing"

func TestMariaDBReplicaFromFields(t *testing.T) {
	replica := mariaDBReplicaFromFields(map[string]string{
		"connection_name": "branch-a", "master_host": "db-primary",
		"slave_io_running": "Yes", "slave_sql_running": "Yes",
		"seconds_behind_master": "7",
	})
	if replica.Identity != "branch-a" || replica.Client != "db-primary" || replica.State != "running" ||
		replica.ReplayLagSeconds == nil || *replica.ReplayLagSeconds != 7 {
		t.Fatalf("unexpected replica status: %+v", replica)
	}
	unavailable := mariaDBReplicaFromFields(map[string]string{"slave_io_running": "No"})
	if unavailable.State != "stopped" || unavailable.ReplayLagSeconds != nil {
		t.Fatalf("missing lag must not become zero: %+v", unavailable)
	}
}
