package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestPostgresCatalog_ReadsMetadataOnlyAndSetsIdentity(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix = map[string]*stubRow{"WITH table_catalog": {vals: []any{`{
      "db_name":"billing",
      "server_version":"16.4",
      "database_size_bytes":123456,
      "tables":[{
        "schema_name":"public","table_name":"invoices","table_kind":"table",
        "total_size_bytes":900,"table_size_bytes":700,"index_size_bytes":200,
        "estimated_rows":42,"seq_scans":10,"index_scans":31,"dead_rows":2,
        "last_vacuum":"2026-08-28 10:00:00+00","last_autovacuum":"",
        "last_analyze":"2026-08-28 10:00:00+00","last_autoanalyze":"",
	        "columns":[{"name":"id","ordinal":1,"data_type":"bigint","nullable":false,"has_default":true}],
        "indexes":[{"name":"invoices_pkey","definition":"CREATE UNIQUE INDEX invoices_pkey ON public.invoices USING btree (id)","unique":true,"primary":true,"scans":17,"tuples_read":42,"tuples_fetched":42,"size_bytes":8192}],
        "constraints":[{"name":"invoices_pkey","type":"primary_key","definition":"PRIMARY KEY (id)"}]
      }]
    }`}}}
	cfg := &collectorv1.CheckConfig{
		CheckId: "pg-catalog-1", CheckType: "postgres.catalog",
		Interval: durationpb.New(5 * time.Minute), HostId: "host-1",
		StaticTags: map[string]string{"db_server": "db.internal", "db_name": "billing"},
		Params:     map[string]string{"dsn": "postgres://u:p@h:5432/d"},
	}
	check, err := newPostgresCatalogCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	catalog, err := check.(CatalogCheck).RunCatalog(context.Background())
	if err != nil {
		t.Fatalf("RunCatalog failed: %v", err)
	}
	if catalog.DBServer != "db.internal" || catalog.DBName != "billing" {
		t.Fatalf("unexpected identity: %+v", catalog)
	}
	if catalog.ServerVersion != "16.4" || catalog.DatabaseSizeBytes != 123456 {
		t.Fatalf("unexpected database metadata: %+v", catalog)
	}
	if len(catalog.Tables) != 1 || catalog.Tables[0].TableName != "invoices" {
		t.Fatalf("unexpected tables: %+v", catalog.Tables)
	}
	if len(catalog.Tables[0].Columns) != 1 || !catalog.Tables[0].Columns[0].HasDefault || !catalog.Tables[0].Indexes[0].Primary {
		t.Fatalf("nested metadata was not decoded: %+v", catalog.Tables[0])
	}
	index := catalog.Tables[0].Indexes[0]
	if index.Scans != 17 || index.TuplesRead != 42 || index.TuplesFetched != 42 || index.SizeBytes != 8192 {
		t.Fatalf("index usage metadata was not decoded: %+v", index)
	}
	if len(catalog.Fingerprint) != 64 {
		t.Fatalf("expected SHA-256 fingerprint; got %q", catalog.Fingerprint)
	}
	for _, query := range stub.queries {
		if strings.Contains(strings.ToLower(query), "select * from") || strings.Contains(strings.ToLower(query), " from invoices") {
			t.Fatalf("catalog query must not read business rows: %q", query)
		}
	}
}

func TestPostgresCatalog_TruncatesAtBoundedTableLimit(t *testing.T) {
	stub := newStubPgxPool()
	stub.rowsBySQLPrefix = map[string]*stubRow{}
	rows := make([]string, postgresCatalogTableLimit+1)
	for i := range rows {
		rows[i] = `{"schema_name":"public","table_name":"t"}`
	}
	stub.rowsBySQLPrefix["WITH table_catalog"] = &stubRow{vals: []any{`{"db_name":"d","tables":[` + strings.Join(rows, ",") + `]}`}}
	cfg := &collectorv1.CheckConfig{
		CheckType: "postgres.catalog", HostId: "host-1",
		StaticTags: map[string]string{"db_server": "db.internal"},
		Params:     map[string]string{"dsn": "postgres://u:p@h:5432/d"},
	}
	check, err := newPostgresCatalogCheckWithFactory(cfg, newStubPoolFactory(stub, nil))
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	catalog, err := check.(CatalogCheck).RunCatalog(context.Background())
	if err != nil {
		t.Fatalf("RunCatalog failed: %v", err)
	}
	if len(catalog.Tables) != postgresCatalogTableLimit || !catalog.Truncated {
		t.Fatalf("expected bounded/truncated catalog, got len=%d truncated=%v", len(catalog.Tables), catalog.Truncated)
	}
}

func TestPostgresCatalog_IsRegistered(t *testing.T) {
	if _, ok := Default.Get("postgres.catalog"); !ok {
		t.Fatal("postgres.catalog must be registered in Default registry")
	}
}
