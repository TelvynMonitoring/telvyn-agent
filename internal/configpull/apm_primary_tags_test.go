package configpull

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPrimarySourceDiscoveryReportsKeysOnlyBeforePolicyPull(t *testing.T) {
	reported := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "apm-primary-tags-sources") {
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"keys":["host.tag.team","kube_label.app"]}` {
				t.Errorf("unexpected discovery body: %s", body)
			}
			if r.URL.Query().Get("tenant_id") != "2" || r.URL.Query().Get("collector_id") != "collector" {
				t.Error("metadata report not collector scoped")
			}
			reported = true
			return
		}
		if !reported {
			t.Error("pull preceded metadata discovery")
		}
		fmt.Fprint(w, `{"version":0}`)
	}))
	defer server.Close()
	var version atomic.Int64
	err := pullOnce(context.Background(), server.Client(), Config{Endpoint: server.URL, TenantID: "2", CollectorID: "collector", APMPrimaryTagSources: func() []string { return []string{"host.tag.team", "kube_label.app"} }}, &version, recordingApplier{}, slog.Default())
	if err != nil || !reported {
		t.Fatalf("metadata report failed: %v", err)
	}
}

func TestPrimaryTagsACKRequiresSuccessfulApply(t *testing.T) {
	for _, fail := range []bool{false, true} {
		applied, acks := false, 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				if !applied {
					t.Error("receipt falsely acknowledged as applied")
				}
				acks++
				return
			}
			fmt.Fprint(w, `{"version":0,"apm_primary_tags":{"version":7,"keys":["host"]}}`)
		}))
		var version atomic.Int64
		err := pullOnce(context.Background(), server.Client(), Config{Endpoint: server.URL, TenantID: "2", CollectorID: "collector", ApplyAPMPrimaryTags: func(keys []string) error {
			if fail {
				return fmt.Errorf("apply failed")
			}
			if len(keys) != 1 || keys[0] != "host" {
				t.Error("lost policy")
			}
			applied = true
			return nil
		}}, &version, recordingApplier{}, slog.Default())
		server.Close()
		if fail && (err == nil || acks != 0) {
			t.Fatalf("failure err=%v ACK=%d", err, acks)
		}
		if !fail && (err != nil || acks != 1) {
			t.Fatalf("success err=%v ACK=%d", err, acks)
		}
	}
}
