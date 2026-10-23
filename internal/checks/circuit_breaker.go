package checks

import (
	"sync/atomic"
	"time"
)

// circuitBreakCooldownFloor is the shortest gap between probe runs while a check is circuit-broken.
const circuitBreakCooldownFloor = time.Minute

// circuitBreaker stops a failing check from hammering its target, and lets it recover on its own: once the
// threshold of consecutive errors is reached, normal ticks are skipped, but one probe run is allowed per
// cooldown. A successful probe closes the breaker. Without the probe, a failure that outlasts the threshold
// (for example a DNS outage of a minute) would latch the check until the agent restarts.
type circuitBreaker struct {
	threshold   int32
	cooldown    time.Duration
	errors      atomic.Int32
	lastAttempt atomic.Int64 // unix nanoseconds of the last failure or probe
}

func newCircuitBreaker(threshold int32, interval time.Duration) *circuitBreaker {
	cooldown := interval
	if cooldown < circuitBreakCooldownFloor {
		cooldown = circuitBreakCooldownFloor
	}
	return &circuitBreaker{threshold: threshold, cooldown: cooldown}
}

// allow reports whether a run may start now. While the breaker is open it admits one probe per cooldown.
func (b *circuitBreaker) allow(now time.Time) bool {
	if b.errors.Load() < b.threshold {
		return true
	}
	last := b.lastAttempt.Load()
	if now.UnixNano()-last < int64(b.cooldown) {
		return false
	}
	return b.lastAttempt.CompareAndSwap(last, now.UnixNano())
}

// failure records a failed run and returns the consecutive error count.
func (b *circuitBreaker) failure(now time.Time) int32 {
	b.lastAttempt.Store(now.UnixNano())
	return b.errors.Add(1)
}

// success closes the breaker and reports whether it had been open.
func (b *circuitBreaker) success() bool {
	return b.errors.Swap(0) >= b.threshold
}
