// Package collectorobs agrega saúde de execução sem armazenar métricas,
// destinos ou segredos. O snapshot é enviado junto do heartbeat do collector.
package collectorobs

import (
	"sync"
	"time"
)

type Snapshot struct {
	PollRuns              int64  `json:"poll_runs"`
	PollSuccesses         int64  `json:"poll_successes"`
	PollFailures          int64  `json:"poll_failures"`
	PollTimeouts          int64  `json:"poll_timeouts"`
	LastPollDurationMS    int64  `json:"last_poll_duration_ms"`
	AveragePollDurationMS int64  `json:"avg_poll_duration_ms"`
	MaxPollDurationMS     int64  `json:"max_poll_duration_ms"`
	LastPollAt            string `json:"last_poll_at,omitempty"`
	LastPollSuccessAt     string `json:"last_poll_success_at,omitempty"`
	LastPollFailureAt     string `json:"last_poll_failure_at,omitempty"`
}

type Tracker struct {
	mu              sync.Mutex
	runs            int64
	successes       int64
	failures        int64
	timeouts        int64
	totalDurationMS int64
	lastDurationMS  int64
	maxDurationMS   int64
	lastAt          time.Time
	lastSuccessAt   time.Time
	lastFailureAt   time.Time
}

func New() *Tracker { return &Tracker{} }

func (t *Tracker) Observe(ok, timedOut bool, duration time.Duration, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	durationMS := max(duration.Milliseconds(), 0)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.runs++
	t.totalDurationMS += durationMS
	t.lastDurationMS = durationMS
	if durationMS > t.maxDurationMS {
		t.maxDurationMS = durationMS
	}
	t.lastAt = at
	if ok {
		t.successes++
		t.lastSuccessAt = at
	} else {
		t.failures++
		t.lastFailureAt = at
		if timedOut {
			t.timeouts++
		}
	}
}

func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	average := int64(0)
	if t.runs > 0 {
		average = t.totalDurationMS / t.runs
	}
	return Snapshot{
		PollRuns: t.runs, PollSuccesses: t.successes, PollFailures: t.failures,
		PollTimeouts: t.timeouts, LastPollDurationMS: t.lastDurationMS,
		AveragePollDurationMS: average, MaxPollDurationMS: t.maxDurationMS,
		LastPollAt: format(t.lastAt), LastPollSuccessAt: format(t.lastSuccessAt),
		LastPollFailureAt: format(t.lastFailureAt),
	}
}

func format(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
