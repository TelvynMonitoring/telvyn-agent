package otlp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ispwatch/collector/internal/clock"
)

func TestPostRawObservesOnlyAcceptedIntakeDate(t *testing.T) {
	status, header := 200, time.Now().Add(5*time.Second).UTC().Format(http.TimeFormat)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", header)
		w.WriteHeader(status)
	}))
	defer server.Close()
	exporter := NewIngestExporter(server.URL, "test", "host", "cluster", "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := exporter.PostRaw(context.Background(), "metrics", "application/json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	offset, ok := clock.IntakeOffsetSeconds(time.Now())
	if !ok || offset < 3 || offset > 5 {
		t.Fatalf("accepted Date offset = %v, %v", offset, ok)
	}
	status, header = 500, time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)
	if err := exporter.PostRaw(context.Background(), "metrics", "application/json", []byte("{}")); err == nil {
		t.Fatal("failed response accepted")
	}
	if after, ok := clock.IntakeOffsetSeconds(time.Now()); !ok || after != offset {
		t.Fatal("failed response replaced valid observation")
	}
}
