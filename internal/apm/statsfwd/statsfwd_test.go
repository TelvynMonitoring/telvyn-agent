package statsfwd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/ispwatch/collector/internal/apm/concentrator"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func TestForwarder_SendMontaPayloadEHeaders(t *testing.T) {
	var gotBody []byte
	var gotAuth, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted_groups":1}`))
	}))
	defer srv.Close()

	f := New(srv.Client(), srv.URL, "tok123", "test-agent", nil)
	groups := []concentrator.GroupedStats{{
		BucketStartUnixNano: 1_700_000_000_000_000_000,
		Service:             "svc",
		Resource:            "GET /x",
		Hits:                5,
		Errors:              1,
		DurationSumNano:     100,
		HTTPStatusCode:      200,
		DatabaseMonitorID:   "monitor-a",
	}}
	if err := f.Send(context.Background(), groups); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if gotAuth != "Bearer tok123" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotCT != "application/x-protobuf" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	var payload collectorv1.ApmStatsPayload
	if err := proto.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if payload.AgentVersion != "test-agent" {
		t.Errorf("agentVersion = %q", payload.AgentVersion)
	}
	if len(payload.Buckets) != 1 || len(payload.Buckets[0].Stats) != 1 {
		t.Fatalf("buckets/stats inesperados: %+v", payload.Buckets)
	}
	gs := payload.Buckets[0].Stats[0]
	if gs.Hits != 5 || gs.Errors != 1 || gs.Service != "svc" || gs.HttpStatusCode != 200 {
		t.Errorf("grouped stats errado: %+v", gs)
	}
	if gs.DatabaseMonitorId != "monitor-a" {
		t.Errorf("databaseMonitorId = %q", gs.DatabaseMonitorId)
	}
	if payload.Buckets[0].DurationNano != int64(concentrator.BucketDuration) {
		t.Errorf("durationNano = %d", payload.Buckets[0].DurationNano)
	}
}

func TestForwarder_SendVazioNoOp(t *testing.T) {
	f := New(nil, "http://nao-usado", "t", "v", nil)
	if err := f.Send(context.Background(), nil); err != nil {
		t.Fatalf("Send vazio devia ser no-op: %v", err)
	}
}

func TestApmGroupedStats_DatabaseMonitorIDContract(t *testing.T) {
	field := (&collectorv1.ApmGroupedStats{}).ProtoReflect().Descriptor().Fields().ByName("database_monitor_id")
	if field == nil {
		t.Fatal("database_monitor_id field missing from protobuf descriptor")
	}
	if got := int(field.Number()); got != 16 {
		t.Fatalf("database_monitor_id field number = %d, want 16", got)
	}
}

func TestForwarder_ErroEm5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	f := New(srv.Client(), srv.URL, "t", "v", nil)
	err := f.Send(context.Background(), []concentrator.GroupedStats{{BucketStartUnixNano: 1, Hits: 1}})
	if err == nil {
		t.Fatal("esperava erro em status 500")
	}
}
