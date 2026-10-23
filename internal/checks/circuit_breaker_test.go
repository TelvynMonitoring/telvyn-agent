package checks

import (
	"testing"
	"time"
)

func TestCircuitBreakerOpensAndRecovers(t *testing.T) {
	b := newCircuitBreaker(5, 10*time.Second) // interval below the floor: cooldown is one minute
	now := time.Unix(1_000_000, 0)

	for i := 0; i < 4; i++ {
		if !b.allow(now) {
			t.Fatalf("breaker closed below the threshold, run %d refused", i)
		}
		b.failure(now)
	}
	if !b.allow(now) {
		t.Fatal("fifth run must still be allowed")
	}
	b.failure(now) // threshold reached: open

	if b.allow(now.Add(10 * time.Second)) {
		t.Fatal("open breaker must skip ticks inside the cooldown")
	}
	if b.allow(now.Add(59 * time.Second)) {
		t.Fatal("open breaker must skip ticks until the cooldown ends")
	}
	probe := now.Add(61 * time.Second)
	if !b.allow(probe) {
		t.Fatal("open breaker must let one probe through after the cooldown")
	}
	if b.allow(probe) {
		t.Fatal("only one probe per cooldown")
	}

	b.failure(probe) // probe failed: stays open and waits a new cooldown
	if b.allow(probe.Add(30 * time.Second)) {
		t.Fatal("a failed probe must restart the cooldown")
	}
	second := probe.Add(61 * time.Second)
	if !b.allow(second) {
		t.Fatal("second probe must be allowed")
	}
	if !b.success() {
		t.Fatal("success after the breaker opened must report it was open")
	}
	if !b.allow(second.Add(time.Second)) {
		t.Fatal("breaker must be closed after a successful probe")
	}
	if b.success() {
		t.Fatal("success on a closed breaker must not report it was open")
	}
}

func TestCircuitBreakerCooldownFollowsLongIntervals(t *testing.T) {
	b := newCircuitBreaker(2, 5*time.Minute)
	now := time.Unix(2_000_000, 0)
	b.failure(now)
	b.failure(now)
	if b.allow(now.Add(4 * time.Minute)) {
		t.Fatal("cooldown must follow an interval longer than the floor")
	}
	if !b.allow(now.Add(5*time.Minute + time.Second)) {
		t.Fatal("probe must be allowed after the interval")
	}
}
