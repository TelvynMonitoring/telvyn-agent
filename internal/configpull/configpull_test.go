package configpull

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
			"v3_user": "monitor",
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
