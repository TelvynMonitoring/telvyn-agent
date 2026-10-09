package clock

import (
	"net/http"
	"testing"
	"time"
)

func TestIntakeOffsetPreservesSignAndRequiresRecentValidObservation(t *testing.T) {
	latestIntake.Store(nil)
	t.Cleanup(func() { latestIntake.Store(nil) })
	now := time.Unix(1700000000, 0)
	if _, ok := IntakeOffsetSeconds(now); ok {
		t.Fatal("missing Date must not become zero")
	}
	for _, seconds := range []float64{5, -5, 0} {
		ObserveIntakeDate(now.Add(time.Duration(seconds)*time.Second).UTC().Format(http.TimeFormat), now)
		for _, header := range []string{"", "invalid"} {
			ObserveIntakeDate(header, now)
		}
		if value, ok := IntakeOffsetSeconds(now); !ok || value != seconds {
			t.Fatalf("offset = %v, %v; want %v", value, ok, seconds)
		}
	}
	for _, query := range []time.Time{now.Add(-time.Second), now.Add(2*time.Minute + time.Second)} {
		if _, ok := IntakeOffsetSeconds(query); ok {
			t.Fatal("future or stale observation must not be published")
		}
	}
}
