package configpull

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type recordingApplier struct{}

func (recordingApplier) ApplyDelta(added []*collectorv1.CheckConfig, deletedIDs []string) (int, int) {
	return len(added), len(deletedIDs)
}

type retryingApplier struct {
	recordingApplier
	retries atomic.Int32
}

func (r *retryingApplier) RetryFailedStarts() int {
	r.retries.Add(1)
	return 0
}

type recordingPostgresTargets struct {
	added   []*collectorv1.CheckConfig
	deleted []string
}

func (r *recordingPostgresTargets) ApplyPostgresServerDelta(added []*collectorv1.CheckConfig, deletedIDs []string) {
	r.added = append([]*collectorv1.CheckConfig(nil), added...)
	r.deleted = append([]string(nil), deletedIDs...)
}

func TestExecuteSnmpTest_DeliversSanitizedResult(t *testing.T) {
	resultReceived := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s, want POST", r.Method)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode result: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resultReceived <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	testCase := pulledSnmpTest{
		ID: "job-1", HostUUID: "host-1", Target: "", Version: "v3",
		Params: map[string]any{
			"v3_user":      "monitor",
			"v3_auth_pass": "auth-secret",
			"v3_priv_pass": "priv-secret",
		},
	}
	err := executeSnmpTest(context.Background(), server.Client(), Config{
		Endpoint: server.URL, TenantID: "tenant-1", CollectorID: "collector-1",
	}, testCase, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("executeSnmpTest returned error: %v", err)
	}

	payload := <-resultReceived
	if payload["job_id"] != "job-1" {
		t.Fatalf("job_id=%v, want job-1", payload["job_id"])
	}
	if payload["ok"] != false {
		t.Fatalf("ok=%v, want false for invalid target", payload["ok"])
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"auth-secret", "priv-secret", "monitor"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("resultado contém segredo/credencial %q: %s", secret, encoded)
		}
	}
}

func TestPullOnce_MirrorsPostgresServerDeltaToTargetRegistry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": 1,
			"added_or_updated": []map[string]any{{
				"id":               "check-a",
				"check_type":       "postgres.server",
				"host_id":          7,
				"params":           "{}",
				"static_tags":      `{"db_monitor_id":"monitor-a","db_server":"192.0.2.15","db_port":5432}`,
				"interval_seconds": 60,
			}},
			"deleted_ids": []string{"check-deleted"},
		})
	}))
	defer server.Close()

	var since atomic.Int64
	targets := &recordingPostgresTargets{}
	err := pullOnce(context.Background(), server.Client(), Config{
		Endpoint:        server.URL,
		CollectorID:     "collector-a",
		TenantID:        "tenant-a",
		PostgresTargets: targets,
	}, &since, recordingApplier{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("pullOnce: %v", err)
	}
	if len(targets.added) != 1 {
		t.Fatalf("target registry added count = %d, want 1", len(targets.added))
	}
	got := targets.added[0]
	if got.GetCheckType() != "postgres.server" || got.GetStaticTags()["db_monitor_id"] != "monitor-a" {
		t.Fatalf("target registry received wrong config: %+v", got)
	}
	if len(targets.deleted) != 1 || targets.deleted[0] != "check-deleted" {
		t.Fatalf("target registry deleted = %#v", targets.deleted)
	}
}

func TestPullOnce_RetriesFailedStartsWhenConfigurationIsUnchanged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":          8,
			"added_or_updated": []any{},
			"deleted_ids":      []any{},
		})
	}))
	defer server.Close()

	var since atomic.Int64
	since.Store(7)
	applier := &retryingApplier{}
	err := pullOnce(context.Background(), server.Client(), Config{
		Endpoint: server.URL, CollectorID: "collector-a", TenantID: "tenant-a",
	}, &since, applier, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("pullOnce: %v", err)
	}
	if got := applier.retries.Load(); got != 1 {
		t.Fatalf("retry calls=%d, want 1", got)
	}
}

func TestPullOnceNotifiesOnlyTerminalDatabaseRemoval(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusGone} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			var since atomic.Int64
			called := make(chan int, 1)
			err := pullOnce(context.Background(), server.Client(), Config{
				Endpoint: server.URL, CollectorID: "collector-1", TenantID: "tenant-1",
				OnTerminalRemoval: func(got int) { called <- got },
			}, &since, recordingApplier{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err == nil {
				t.Fatal("expected pull error")
			}
			select {
			case got := <-called:
				if status != http.StatusGone || got != http.StatusGone {
					t.Fatalf("terminal callback status=%d, response=%d", got, status)
				}
			default:
				if status == http.StatusGone {
					t.Fatal("410 must notify terminal removal")
				}
			}
		})
	}
}
