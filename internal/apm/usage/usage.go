// Package usage records observed OTLP ingestion, not request estimates from APM stats.
package usage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const maxBuckets = 120
const maxRows = 2000
const maxTraceIDs = 20000

type Observation struct {
	Received, Retained                             []*collectorv1.Span
	ReceivedBytes, ForwardedBytes                  int64
	ForwardFailed, ParseFailed, ProcessingRejected bool
}

type Row struct {
	Minute                int64  `json:"minute"`
	Scope                 string `json:"scope"`
	Service               string `json:"service"`
	Env                   string `json:"env"`
	Requests              int64  `json:"requests"`
	ReceivedSpans         int64  `json:"received_spans"`
	RetainedSpans         int64  `json:"retained_spans"`
	DroppedSpans          int64  `json:"dropped_spans"`
	ReceivedTraces        int64  `json:"received_traces"`
	RetainedTraces        int64  `json:"retained_traces"`
	ReceivedBytes         int64  `json:"received_bytes"`
	ForwardedBytes        int64  `json:"forwarded_bytes"`
	ForwardFailures       int64  `json:"forward_failures"`
	ParseFailures         int64  `json:"parse_failures"`
	ProcessingRejections  int64  `json:"processing_rejections"`
	TraceCountsComplete   bool   `json:"trace_counts_complete"`
	ServiceCountsComplete bool   `json:"service_counts_complete"`
}

type Payload struct {
	Session        string `json:"session"`
	CoverageFrom   int64  `json:"coverage_from"`
	ObservedAt     int64  `json:"observed_at"`
	LostBuckets    int64  `json:"lost_buckets"`
	ByteDefinition string `json:"byte_definition"`
	Rows           []Row  `json:"rows"`
}

type key struct {
	minute              int64
	scope, service, env string
}
type bucket struct {
	row                Row
	received, retained map[string]struct{}
	revision           int64
}
type Aggregator struct {
	mu           sync.Mutex
	flushMu      sync.Mutex
	session      string
	coverageFrom int64
	rows         map[key]*bucket
	traceIDs     int
	lostBuckets  int64
	now          func() time.Time
	enabled      atomic.Bool
}

func New() (*Aggregator, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	aggregator := &Aggregator{session: hex.EncodeToString(id), coverageFrom: time.Now().Unix(), rows: make(map[key]*bucket), now: time.Now}
	aggregator.enabled.Store(true)
	return aggregator, nil
}

func (a *Aggregator) SetEnabled(enabled bool) { a.enabled.Store(enabled) }

// Observe runs once after a request completes. Retry attempts are counted as
// received attempts; traces are deduplicated within each service/minute only.
func (a *Aggregator) Observe(observation Observation) {
	if !a.enabled.Load() {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	minute := a.now().Unix() / 60 * 60
	a.prune(minute)
	global := a.get(key{minute: minute, scope: "collector"})
	if global == nil {
		return
	}
	global.row.Requests++
	global.row.ReceivedBytes += observation.ReceivedBytes
	global.row.ForwardedBytes += observation.ForwardedBytes
	if observation.ForwardFailed {
		global.row.ForwardFailures++
	}
	if observation.ParseFailed {
		global.row.ParseFailures++
		global.row.TraceCountsComplete = false
		global.row.ServiceCountsComplete = false
	}
	if observation.ProcessingRejected {
		global.row.ProcessingRejections++
	}
	for _, direction := range []struct {
		spans    []*collectorv1.Span
		retained bool
	}{{observation.Received, false}, {observation.Retained, true}} {
		for _, span := range direction.spans {
			if span == nil {
				continue
			}
			a.add(global, span.TraceId, direction.retained)
			env := span.Attributes["deployment.environment"]
			if env == "" {
				env = span.Attributes["deployment.environment.name"]
			}
			service := span.ServiceName
			if len(service) > 255 || len(env) > 200 || strings.IndexFunc(service, unicode.IsControl) >= 0 || strings.IndexFunc(env, unicode.IsControl) >= 0 {
				global.row.ServiceCountsComplete = false
				continue
			}
			group := a.get(key{minute: minute, scope: "service", service: service, env: env})
			if group == nil {
				global.row.ServiceCountsComplete = false
				continue
			}
			a.add(group, span.TraceId, direction.retained)
		}
	}
	global.revision++
}

func (a *Aggregator) get(k key) *bucket {
	if row := a.rows[k]; row != nil {
		return row
	}
	if len(a.rows) >= maxRows && k.scope != "collector" {
		return nil
	}
	row := &bucket{row: Row{Minute: k.minute, Scope: k.scope, Service: k.service, Env: k.env, TraceCountsComplete: true, ServiceCountsComplete: true}, received: make(map[string]struct{}), retained: make(map[string]struct{})}
	a.rows[k] = row
	return row
}

func (a *Aggregator) add(row *bucket, traceID string, retained bool) {
	set := row.received
	if retained {
		row.row.RetainedSpans++
		set = row.retained
	} else {
		row.row.ReceivedSpans++
	}
	row.revision++
	traceID = strings.ToLower(traceID)
	if len(traceID) != 32 {
		row.row.TraceCountsComplete = false
		return
	}
	if _, err := hex.DecodeString(traceID); err != nil {
		row.row.TraceCountsComplete = false
		return
	}
	if _, exists := set[traceID]; exists {
		return
	}
	if a.traceIDs >= maxTraceIDs {
		row.row.TraceCountsComplete = false
		return
	}
	set[traceID] = struct{}{}
	a.traceIDs++
}

func (a *Aggregator) remove(k key) {
	row := a.rows[k]
	a.traceIDs -= len(row.received) + len(row.retained)
	delete(a.rows, k)
}

func (a *Aggregator) prune(minute int64) {
	lost := make(map[int64]bool)
	for k := range a.rows {
		if k.minute <= minute-maxBuckets*60 {
			lost[k.minute] = true
			a.remove(k)
		}
	}
	a.lostBuckets += int64(len(lost))
}

// Flush sends absolute snapshots: retries cannot double-count persisted rows.
// Only acknowledged closed, unchanged buckets are discarded. The current
// bucket remains for trace-ID deduplication across requests and flushes.
func (a *Aggregator) Flush(ctx context.Context, send func(context.Context, []byte) error) error {
	if !a.enabled.Load() {
		return nil
	}
	if send == nil {
		return errors.New("usage sender required")
	}
	a.flushMu.Lock()
	defer a.flushMu.Unlock()
	a.mu.Lock()
	now := a.now().Unix()
	a.prune(now / 60 * 60)
	payload := Payload{Session: a.session, CoverageFrom: a.coverageFrom, ObservedAt: now, LostBuckets: a.lostBuckets, ByteDefinition: "decoded_request_and_forwarded_payload_bytes", Rows: make([]Row, 0, len(a.rows))}
	revisions := make(map[key]int64, len(a.rows))
	for k, bucket := range a.rows {
		row := bucket.row
		row.ReceivedTraces = int64(len(bucket.received))
		row.RetainedTraces = int64(len(bucket.retained))
		row.DroppedSpans = row.ReceivedSpans - row.RetainedSpans
		payload.Rows = append(payload.Rows, row)
		revisions[k] = bucket.revision
	}
	a.mu.Unlock()
	if len(payload.Rows) == 0 {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := send(ctx, body); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, revision := range revisions {
		if k.minute < now/60*60 {
			if current := a.rows[k]; current != nil && current.revision == revision {
				a.remove(k)
			}
		}
	}
	return nil
}
