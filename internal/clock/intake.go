package clock

import (
	"net/http"
	"sync/atomic"
	"time"
)

type intakeSample struct {
	offset   float64
	observed time.Time
}

var latestIntake atomic.Pointer[intakeSample]

// ObserveIntakeDate measures server minus agent time, not NTP or network RTT.
// HTTP Date has one-second resolution. Missing/invalid headers are not zero.
func ObserveIntakeDate(header string, received time.Time) {
	server, err := http.ParseTime(header)
	if err != nil {
		return
	}
	latestIntake.Store(&intakeSample{offset: server.Sub(received).Seconds(), observed: received})
}

func IntakeOffsetSeconds(now time.Time) (float64, bool) {
	sample := latestIntake.Load()
	if sample == nil || now.Before(sample.observed) || now.Sub(sample.observed) > 2*time.Minute {
		return 0, false
	}
	return sample.offset, true
}
