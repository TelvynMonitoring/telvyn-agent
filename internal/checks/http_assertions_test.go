package checks

import (
	"context"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPAssertions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(418)
		if r.URL.Path == "/large" {
			_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
			return
		}
		_, _ = w.Write([]byte(`{"state":"ready"}`))
	}))
	defer server.Close()
	for _, test := range []struct {
		name   string
		params map[string]string
		want   float64
	}{
		{"expected non-2xx", map[string]string{"expected_status": "418", "body_contains": "ready", "expected_header_name": "content-type", "expected_header_value": "application/json"}, 1},
		{"wrong status", map[string]string{"expected_status": "200"}, 0},
		{"wrong body", map[string]string{"expected_status": "418", "body_contains": "missing"}, 0},
		{"wrong header", map[string]string{"expected_status": "418", "expected_header_name": "content-type", "expected_header_value": "text/plain"}, 0},
		{"missing empty header", map[string]string{"expected_status": "418", "expected_header_name": "x-missing", "expected_header_value": ""}, 0},
		{"oversized body assertion", map[string]string{"expected_status": "418", "body_contains": "x", "target": server.URL + "/large"}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.params["target"] == "" {
				test.params["target"] = server.URL
			}
			check, err := newHTTPGetCheck(&collectorv1.CheckConfig{Params: test.params})
			if err != nil {
				t.Fatal(err)
			}
			metrics, err := check.Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, metric := range metrics {
				if metric.MetricName == "http.success" {
					if metric.Value != test.want {
						t.Fatalf("success=%v want=%v", metric.Value, test.want)
					}
					return
				}
			}
			t.Fatal("missing success metric")
		})
	}
	for _, params := range []map[string]string{{"expected_status": "99"}, {"expected_status": "200.5"}, {"max_response_ms": "0"}, {"expected_header_name": "bad\r\nheader"}, {"expected_header_value": "missing name"}} {
		params["target"] = server.URL
		if _, err := newHTTPGetCheck(&collectorv1.CheckConfig{Params: params}); err == nil {
			t.Fatal("invalid assertion accepted")
		}
	}
}
