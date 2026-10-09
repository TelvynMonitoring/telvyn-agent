package sampler

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMonthlyRareScopeAndBudgetValidation(t *testing.T) {
	s := New(.1, time.Second)
	p := Policy{Mode: "adaptive_monthly", BaseRate: 0, SlowThresholdMs: 1000, BudgetRevision: strings.Repeat("a", 64)}
	if err := s.ApplyPolicy(p); err != nil {
		t.Fatal(err)
	}
	if !s.KeepForScope("first", "svc", "prod", "GET /a", 1, 2, 1) {
		t.Fatal("first observed server resource must survive")
	}
	if s.KeepForScope("normal", "svc", "prod", "GET /a", 1, 2, 1) {
		t.Fatal("normal trace exceeds zero budget")
	}
	if !s.KeepForScope("env", "svc", "dev", "GET /a", 1, 2, 1) || !s.KeepForScope("resource", "svc", "prod", "GET /b", 1, 2, 1) {
		t.Fatal("rare scope must include environment and resource")
	}
	if s.KeepForScope("client", "other", "prod", "new", 1, 3, 1) {
		t.Fatal("clients must not create rare server resources")
	}
	if !s.KeepForScope("error", "svc", "prod", "GET /a", 2, 2, 1) || !s.KeepForScope("slow", "svc", "prod", "GET /a", 1, 2, int64(time.Second)) {
		t.Fatal("protected traces dropped")
	}
	before := s.adaptive
	p.BaseRate = .2
	if err := s.ApplyPolicy(p); err != nil || s.adaptive != before {
		t.Fatal("feedback rate update reset rare history")
	}
	p.BudgetRevision = ""
	if s.ApplyPolicy(p) == nil {
		t.Fatal("monthly without exact revision accepted")
	}
}

func TestMonthlyRareIntervalAndCardinalityBound(t *testing.T) {
	a := &adaptiveState{rare: map[string]time.Time{}, decisions: map[string]*traceDecision{}}
	now := time.Now()
	if !a.keepMonthly("a", "svc", "prod", "a", 2, false, 0, now) || a.keepMonthly("b", "svc", "prod", "a", 2, false, 0, now.Add(time.Minute)) || !a.keepMonthly("c", "svc", "prod", "a", 2, false, 0, now.Add(5*time.Minute)) {
		t.Fatal("rare five minute interval")
	}
	for i := 0; i < 3000; i++ {
		a.keepMonthly(fmt.Sprint(i), "svc", "prod", fmt.Sprint(i), 2, false, 0, now)
	}
	if len(a.rare) > 2048 || len(a.decisions) > maxAdaptiveDecisions {
		t.Fatal("unbounded monthly sampler state")
	}
	if _, ok := a.rare["\x00overflow"]; !ok {
		t.Fatal("overflow must share explicitly bounded slot")
	}
}
