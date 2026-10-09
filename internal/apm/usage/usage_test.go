package usage

import (
	"context"
	"encoding/json"
	"errors"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"testing"
	"time"
)

func TestUsageDeduplicatesIDsAndRetriesAbsoluteSnapshots(t *testing.T) {
	aggregator, err := New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(6000, 0)
	aggregator.now = func() time.Time { return now }
	aggregator.coverageFrom = now.Unix()
	span := &collectorv1.Span{TraceId: "0123456789abcdef0123456789abcdef", ServiceName: "backend", Attributes: map[string]string{"deployment.environment": "local"}}
	aggregator.Observe(Observation{Received: []*collectorv1.Span{span, span}, Retained: []*collectorv1.Span{span}, ReceivedBytes: 120, ForwardedBytes: 80})
	aggregator.Observe(Observation{Received: []*collectorv1.Span{span}, ReceivedBytes: 60})
	var first, second Payload
	now = now.Add(time.Minute)
	err = aggregator.Flush(context.Background(), func(_ context.Context, body []byte) error {
		_ = json.Unmarshal(body, &first)
		return errors.New("offline")
	})
	if err == nil {
		t.Fatal("failed sender accepted")
	}
	err = aggregator.Flush(context.Background(), func(_ context.Context, body []byte) error { return json.Unmarshal(body, &second) })
	if err != nil {
		t.Fatal(err)
	}
	if first.Session != second.Session || len(first.Rows) != 2 || len(second.Rows) != 2 || len(aggregator.rows) != 0 {
		t.Fatal("retry identity/count changed")
	}
	for _, row := range second.Rows {
		if row.ReceivedSpans != 3 || row.RetainedSpans != 1 || row.DroppedSpans != 2 || row.ReceivedTraces != 1 || row.RetainedTraces != 1 {
			t.Fatalf("wrong counts: %+v", row)
		}
		if row.Scope == "service" && (row.ReceivedBytes != 0 || row.ForwardedBytes != 0) {
			t.Fatal("invented service bytes")
		}
		if row.Scope == "collector" && (row.ReceivedBytes != 180 || row.ForwardedBytes != 80) {
			t.Fatal("wrong payload bytes")
		}
	}
}

func TestCapsMarkCoverageAndCurrentBucketRemainsForDeduplication(t *testing.T) {
	a, _ := New()
	now := time.Unix(6000, 0)
	a.now = func() time.Time { return now }
	a.coverageFrom = now.Unix()
	a.traceIDs = maxTraceIDs
	span := &collectorv1.Span{TraceId: "0123456789abcdef0123456789abcdef", ServiceName: "backend"}
	a.Observe(Observation{Received: []*collectorv1.Span{span}})
	var payload Payload
	if err := a.Flush(context.Background(), func(_ context.Context, body []byte) error { return json.Unmarshal(body, &payload) }); err != nil {
		t.Fatal(err)
	}
	if len(a.rows) != 2 || payload.Rows[0].TraceCountsComplete {
		t.Fatal("current bucket or incomplete flag lost")
	}
	a.SetEnabled(false)
	previous := len(a.rows)
	a.Observe(Observation{Received: []*collectorv1.Span{span}})
	if len(a.rows) != previous {
		t.Fatal("disabled usage accumulated")
	}
	now = now.Add(121 * time.Minute)
	a.SetEnabled(true)
	a.Observe(Observation{})
	if a.lostBuckets != 1 {
		t.Fatal("expired unsent minute not recorded")
	}
}
