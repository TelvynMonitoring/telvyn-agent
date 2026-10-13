package configpull

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ispwatch/collector/internal/inventory"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type inventoryApplier struct{ configs []*collectorv1.CheckConfig }

func (a *inventoryApplier) ApplyDelta(added []*collectorv1.CheckConfig, _ []string) (int, int) {
	a.configs = added
	return len(added), 0
}

func TestExternalInventoryConfigVersionIsAuthoritative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": 18, "added_or_updated": []map[string]any{{
			"id": "11111111-1111-4111-8111-111111111111", "check_type": "external.python", "host_id": 42,
			"config_version": 17, "params": `{"__core_config_version":"999"}`, "static_tags": "{}", "interval_seconds": 60,
		}}, "deleted_ids": []string{}})
	}))
	defer server.Close()
	var since atomic.Int64
	applier := &inventoryApplier{}
	if err := pullOnce(context.Background(), server.Client(), Config{Endpoint: server.URL, CollectorID: "collector-a", TenantID: "tenant-a"},
		&since, applier, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if len(applier.configs) != 1 || applier.configs[0].Params[inventory.ConfigVersionParam] != "17" {
		t.Fatal("lost/spoofed check config version")
	}
}
