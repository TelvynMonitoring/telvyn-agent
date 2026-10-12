package otlp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ispwatch/collector/internal/inventory"
)

func TestExternalInventoryWireContract(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/ingest/v1/proxmox/inventory" || r.Method != "POST" ||
			r.Header.Get("Authorization") != "Bearer synthetic" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("wrong endpoint/auth")
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		want := []string{"protocol_version", "check_id", "config_version", "host_id", "provider", "observed_at", "complete", "cluster_mode", "resources"}
		if len(body) != len(want) {
			t.Error("wire contains unexpected fields")
		}
		for _, key := range want {
			if _, ok := body[key]; !ok {
				t.Errorf("missing %s", key)
			}
		}
		if string(body["host_id"]) != `"42"` || string(body["resources"]) != `[]` {
			t.Error("empty snapshot or host ID type mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	e := &IngestExporter{base: server.URL + "/api/ingest/v1", token: "synthetic", client: server.Client(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := inventory.Snapshot{ProtocolVersion: 1, CheckID: "11111111-1111-4111-8111-111111111111", ConfigVersion: 17,
		HostID: "42", Provider: "proxmox", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Complete: true, ClusterMode: "standalone"}
	if err := e.PostExternalInventory(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("empty report was dropped")
	}
	bad := report
	bad.ClusterMode = "cluster"
	if e.PostExternalInventory(context.Background(), bad) == nil {
		t.Fatal("wrong enum accepted")
	}
	bad = report
	bad.ConfigVersion = 0
	if e.PostExternalInventory(context.Background(), bad) == nil {
		t.Fatal("zero version accepted")
	}
	bad = report
	bad.Resources = make([]inventory.Resource, 1001)
	if e.PostExternalInventory(context.Background(), bad) == nil {
		t.Fatal("too many resources")
	}
	bad = report
	bad.Resources = []inventory.Resource{{Name: strings.Repeat("x", inventory.MaxBodyBytes)}}
	if e.PostExternalInventory(context.Background(), bad) == nil {
		t.Fatal("oversized payload accepted")
	}
	if calls != 1 {
		t.Fatal("invalid report reached HTTP")
	}
}

