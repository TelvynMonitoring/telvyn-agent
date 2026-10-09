package sampler

import (
	"fmt"
	"math"
	"testing"
	"time"
)

func TestAdaptiveBudgetReplayExceptionsAndBounds(t *testing.T) {
	s := New(.1, 2*time.Second)
	if err := s.ApplyPolicy(Policy{Mode: "adaptive_agent", BaseRate: .1, SlowThresholdMs: 2000, TargetTracesPerSecond: 10}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	a := s.adaptive
	kept := 0
	for i := 0; i < 1000; i++ {
		if a.keep(fmt.Sprintf("%032x", i), "backend", false, 10, now) {
			kept++
		}
	}
	if kept != 10 {
		t.Fatalf("burst=%d want10", kept)
	}
	if !a.keep(fmt.Sprintf("%032x", 0), "backend", false, 10, now) {
		t.Fatal("replay changed kept decision")
	}
	if a.keep(fmt.Sprintf("%032x", 500), "backend", false, 10, now) {
		t.Fatal("replay changed dropped decision")
	}
	if !a.keep(fmt.Sprintf("%032x", 500), "backend", true, 10, now) {
		t.Fatal("error did not promote")
	}
	if !a.keep(fmt.Sprintf("%032x", 500), "backend", false, 10, now) {
		t.Fatal("promotion not reused")
	}
	if err := s.ApplyPolicy(Policy{Mode: "adaptive_agent", BaseRate: .1, SlowThresholdMs: 2000, TargetTracesPerSecond: 10}); err != nil {
		t.Fatal(err)
	}
	if s.adaptive != a {
		t.Fatal("unchanged pull resets budget")
	}
	for i := 1000; i < 20000; i++ {
		a.keep(fmt.Sprintf("%032x", i), fmt.Sprint(i), false, 10, now)
	}
	if len(a.decisions) > maxAdaptiveDecisions || len(a.services) > maxAdaptiveServices {
		t.Fatalf("unbounded decisions=%d services=%d", len(a.decisions), len(a.services))
	}
}

func TestAdaptiveObservedServiceRateAndPreservation(t *testing.T) {
	a := &adaptiveState{services: make(map[string]*serviceTraffic), decisions: make(map[string]*traceDecision)}
	now := time.Unix(1000, 0)
	for i := 0; i < 1000; i++ {
		a.keep(fmt.Sprintf("%032x", i), "java", false, 10, now)
	}
	a.keep("next", "java", false, 10, now.Add(10*time.Second))
	if rate := a.services["java"].rate; math.Abs(rate-.1) > .000001 {
		t.Fatalf("rate=%f want.1", rate)
	}
	s := New(0, 2*time.Second)
	_ = s.ApplyPolicy(Policy{Mode: "adaptive_agent", SlowThresholdMs: 2000, TargetTracesPerSecond: .1})
	if !s.KeepForService("error", "java", 2, 1) || !s.KeepForService("slow", "java", 0, int64(2*time.Second)) {
		t.Fatal("exceptions must survive exhausted budget")
	}
}

func TestAdaptivePolicyValidation(t *testing.T) {
	s := New(.1, 0)
	for _, p := range []Policy{{Mode: "monthly"}, {Mode: "adaptive_agent", TargetTracesPerSecond: 0}, {Mode: "adaptive_agent", TargetTracesPerSecond: math.NaN()}, {Mode: "adaptive_agent", TargetTracesPerSecond: 10001}} {
		if s.ApplyPolicy(p) == nil {
			t.Fatalf("accepted%+v", p)
		}
	}
	if s.ApplyPolicy(Policy{Mode: "static", BaseRate: .1}) != nil {
		t.Fatal("legacy static")
	}
}
