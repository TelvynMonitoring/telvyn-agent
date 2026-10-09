package sampler

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// Policy is an explicit collector policy. Monthly rates come from the observed tenant pool.
type Policy struct {
	Mode                  string  `json:"mode"`
	BaseRate              float64 `json:"base_rate"`
	SlowThresholdMs       int64   `json:"slow_threshold_ms"`
	TargetTracesPerSecond float64 `json:"target_traces_per_second"`
	BudgetRevision        string  `json:"budget_revision"`
}

func (s *Sampler) ApplyPolicy(p Policy) error {
	if p.Mode == "" {
		p.Mode = "static"
	}
	if p.Mode != "static" && p.Mode != "adaptive_agent" && p.Mode != "adaptive_monthly" || math.IsNaN(p.BaseRate) || math.IsInf(p.BaseRate, 0) || p.BaseRate < 0 || p.BaseRate > 1 || p.SlowThresholdMs < 0 || p.SlowThresholdMs > 600000 || p.Mode == "adaptive_agent" && (math.IsNaN(p.TargetTracesPerSecond) || math.IsInf(p.TargetTracesPerSecond, 0) || p.TargetTracesPerSecond < 0.1 || p.TargetTracesPerSecond > 10000) || p.Mode == "adaptive_monthly" && (len(p.BudgetRevision) != 64 || strings.Trim(p.BudgetRevision, "0123456789abcdef") != "") {
		return fmt.Errorf("invalid APM sampling policy")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode == p.Mode && s.baseRate == p.BaseRate && s.slowThreshold == p.SlowThresholdMs*int64(time.Millisecond) && (p.Mode != "adaptive_agent" || s.targetTPS == p.TargetTracesPerSecond) {
		return nil
	}
	previousMode := s.mode
	s.mode = p.Mode
	s.baseRate = p.BaseRate
	s.slowThreshold = p.SlowThresholdMs * int64(time.Millisecond)
	s.targetTPS = p.TargetTracesPerSecond
	if s.adaptive == nil || previousMode != p.Mode {
		s.adaptive = &adaptiveState{services: make(map[string]*serviceTraffic), decisions: make(map[string]*traceDecision), rare: make(map[string]time.Time)}
	}
	return nil
}

const maxAdaptiveServices = 128
const maxAdaptiveDecisions = 16384
const adaptiveWindow = 10 * time.Second
const decisionTTL = time.Minute

type serviceTraffic struct {
	observed int
	rate     float64
	last     time.Time
}
type traceDecision struct {
	id   string
	keep bool
	at   time.Time
}
type adaptiveState struct {
	services           map[string]*serviceTraffic
	decisions          map[string]*traceDecision
	ring               [maxAdaptiveDecisions]*traceDecision
	next               int
	window, timeTokens time.Time
	tokens             float64
	rare               map[string]time.Time
}

// The rare guarantee covers observed SERVER/CONSUMER combinations only, capped at
// 2048. Overflow shares one slot; this is not a complete cross-request tail buffer.
func (a *adaptiveState) keepMonthly(id, service, env, resource string, kind int32, preserve bool, rate float64, now time.Time) bool {
	id = strings.ToLower(id)
	if len(id) > 128 {
		id = id[:128]
	}
	key := ""
	if kind == 2 || kind == 5 {
		for _, part := range []string{service, env, resource} {
			if len(part) > 512 {
				part = part[:512]
			}
			key += fmt.Sprintf("%d:%s", len(part), part)
		}
		if _, ok := a.rare[key]; !ok && len(a.rare) >= 2047 {
			key = "\x00overflow"
		}
		if last, ok := a.rare[key]; !ok || now.Sub(last) >= 5*time.Minute {
			preserve = true
		}
	}
	keep := preserve || rate >= 1 || rate > 0 && float64(traceHash(id)>>11)*0x1.0p-53 < rate
	if old := a.decisions[id]; old != nil && now.Sub(old.at) < decisionTTL {
		old.keep = old.keep || keep
		keep = old.keep
	} else {
		entry := &traceDecision{id: id, keep: keep, at: now}
		if old := a.ring[a.next]; old != nil && a.decisions[old.id] == old {
			delete(a.decisions, old.id)
		}
		a.ring[a.next] = entry
		a.next = (a.next + 1) % maxAdaptiveDecisions
		a.decisions[id] = entry
	}
	if keep && key != "" {
		a.rare[key] = now
	}
	return keep
}

// A global token budget bounds normal traces; observed per-service traffic sets
// deterministic hash rates. Exceptions are intentionally outside this budget.
// Cached decisions survive chunks/replays for one minute, not an unbounded tail buffer.
func (a *adaptiveState) keep(id, service string, preserve bool, target float64, now time.Time) bool {
	id = strings.ToLower(id)
	if len(id) > 128 {
		id = id[:128]
	}
	if old := a.decisions[id]; old != nil && now.Sub(old.at) < decisionTTL {
		if preserve {
			old.keep = true
		}
		return old.keep
	}
	if a.window.IsZero() {
		a.window = now
		a.timeTokens = now
		a.tokens = math.Max(1, target)
	}
	if elapsed := now.Sub(a.window); elapsed >= adaptiveWindow {
		for name, traffic := range a.services {
			if now.Sub(traffic.last) > time.Minute {
				delete(a.services, name)
			}
		}
		share := target / math.Max(1, float64(len(a.services)))
		for _, traffic := range a.services {
			traffic.rate = math.Min(1, share/(math.Max(1, float64(traffic.observed))/elapsed.Seconds()))
			traffic.observed = 0
		}
		a.window = now
	}
	if len(service) > 200 {
		service = service[:200]
	}
	if a.services[service] == nil && len(a.services) >= maxAdaptiveServices-1 {
		service = "\x00overflow"
	}
	traffic := a.services[service]
	if traffic == nil {
		traffic = &serviceTraffic{rate: 1}
		a.services[service] = traffic
	}
	traffic.last = now
	keep := preserve
	if !preserve {
		traffic.observed++
		a.tokens = math.Min(math.Max(1, target), a.tokens+math.Max(0, now.Sub(a.timeTokens).Seconds())*target)
		a.timeTokens = now
		if traffic.rate >= 1 || float64(traceHash(id)>>11)*0x1.0p-53 < traffic.rate {
			if a.tokens >= 1 {
				keep = true
				a.tokens--
			}
		}
	}
	entry := &traceDecision{id: id, keep: keep, at: now}
	if old := a.ring[a.next]; old != nil && a.decisions[old.id] == old {
		delete(a.decisions, old.id)
	}
	a.ring[a.next] = entry
	a.next = (a.next + 1) % maxAdaptiveDecisions
	a.decisions[id] = entry
	return keep
}
