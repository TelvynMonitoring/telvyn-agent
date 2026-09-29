package checks

import (
	"context"
	"errors"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

type mysqlDiscoveryRows struct {
	names []string
	index int
}

func (r *mysqlDiscoveryRows) Next() bool { return r.index < len(r.names) }
func (r *mysqlDiscoveryRows) Scan(dest ...any) error {
	if len(dest) != 1 {
		return errors.New("expected one column")
	}
	*dest[0].(*string) = r.names[r.index]
	r.index++
	return nil
}
func (r *mysqlDiscoveryRows) Err() error   { return nil }
func (r *mysqlDiscoveryRows) Close() error { return nil }

type mysqlDiscoveryPool struct {
	stubSQLPool
	names []string
}

func (p *mysqlDiscoveryPool) Query(context.Context, string, ...any) (sqlDatabaseRows, error) {
	return &mysqlDiscoveryRows{names: p.names}, nil
}

func TestMySQLInstanceDiscoveryReportsVisibleDatabases(t *testing.T) {
	pool := &mysqlDiscoveryPool{names: []string{"app", "reporting"}}
	pool.defaultRow = &stubSQLRow{values: []any{"8.4.5"}}
	cfg := &collectorv1.CheckConfig{
		CheckId: "mysql-discovery", CheckType: "mysql.instance_discovery", HostId: "host",
		Interval:   durationpb.New(time.Minute),
		Params:     map[string]string{"dsn": "reader:secret@tcp(db:3306)/", "installation_id": "installation-1"},
		StaticTags: map[string]string{"db_server": "db", "db_port": "3306"},
	}
	check, err := newMySQLInstanceDiscoveryCheckWithFactory(cfg, stubSQLPoolFactory(pool, nil))
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := check.(InstanceDiscoveryCheck).RunInstanceDiscovery(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Engine != "mysql" || discovery.InstallationID != "installation-1" ||
		discovery.Server != "db" || discovery.Port != 3306 || discovery.ServerVersion != "8.4.5" ||
		len(discovery.Databases) != 2 || discovery.Databases[0] != "app" || discovery.Databases[1] != "reporting" {
		t.Fatalf("unexpected discovery: %+v", discovery)
	}
}
