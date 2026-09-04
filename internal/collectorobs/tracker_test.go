package collectorobs

import (
	"testing"
	"time"
)

func TestTrackerAggregatesSuccessFailureTimeoutAndDuration(t *testing.T) {
	tracker := New()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	tracker.Observe(true, false, 100*time.Millisecond, now)
	tracker.Observe(false, true, 300*time.Millisecond, now.Add(time.Minute))

	snapshot := tracker.Snapshot()
	if snapshot.PollRuns != 2 || snapshot.PollSuccesses != 1 || snapshot.PollFailures != 1 || snapshot.PollTimeouts != 1 {
		t.Fatalf("contadores inesperados: %+v", snapshot)
	}
	if snapshot.AveragePollDurationMS != 200 || snapshot.MaxPollDurationMS != 300 || snapshot.LastPollDurationMS != 300 {
		t.Fatalf("durações inesperadas: %+v", snapshot)
	}
	if snapshot.LastPollSuccessAt == "" || snapshot.LastPollFailureAt == "" {
		t.Fatalf("timestamps ausentes: %+v", snapshot)
	}
}
