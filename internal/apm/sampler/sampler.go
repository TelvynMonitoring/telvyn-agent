// Package sampler decide quais traces guardar em DETALHE (spans crus), igual ao
// mantém tudo que é erro, tudo que é lento e uma
// AMOSTRA determinística dos normais — descarta o resto.
//
// Importante: as ESTATÍSTICAS (concentrator) são contadas ANTES do sampler, com
// 100% dos spans. Então hits/errors/p95 continuam EXATOS mesmo guardando o
// detalhe de só 1 trace em N. O sampler só afeta o que vira waterfall.
//
// A decisão dos "normais" é um hash determinístico do trace_id: o mesmo trace
// recebe sempre a mesma decisão para a amostra base. O receiver promove todos
// os spans do mesmo trace NO BATCH quando um deles é erro/lento; batches distintos
// ainda podem produzir detalhes parciais (não há tail buffer entre requests).
package sampler

import (
	"fmt"
	"hash/fnv"
	"math"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Sampler permits atomic policy updates while receiving concurrent spans.
type Sampler struct {
	mu            sync.RWMutex
	baseRate      float64 // fração [0,1] dos traces normais mantidos
	slowThreshold int64   // nanos; spans >= isso são sempre mantidos (0 = desliga)
	mode          string
	targetTPS     float64
	adaptive      *adaptiveState
}

func (s *Sampler) Apply(baseRate float64, slowThreshold time.Duration) error {
	if math.IsNaN(baseRate) || math.IsInf(baseRate, 0) || baseRate < 0 || baseRate > 1 || slowThreshold < 0 || slowThreshold > 10*time.Minute {
		return fmt.Errorf("invalid APM sampling policy")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseRate, s.slowThreshold, s.mode = baseRate, int64(slowThreshold), "static"
	s.adaptive = nil
	return nil
}

// New cria um sampler. baseRate é clampado em [0,1].
func New(baseRate float64, slowThreshold time.Duration) *Sampler {
	switch {
	case baseRate < 0:
		baseRate = 0
	case baseRate > 1:
		baseRate = 1
	}
	return &Sampler{baseRate: baseRate, slowThreshold: int64(slowThreshold)}
}

// Keep decide se o span deve ser guardado em detalhe.
func (s *Sampler) Keep(span *collectorv1.Span) bool {
	if span == nil {
		return false
	}
	return s.KeepRaw(span.TraceId, span.StatusCode, span.EndUnixNano-span.StartUnixNano)
}

// KeepRaw é a mesma decisão a partir dos campos crus — usada no caminho OTLP do
// receiver, que lida com tracepb.Span (não com collectorv1.Span).
func (s *Sampler) KeepRaw(traceID string, statusCode int32, durationNano int64) bool {
	return s.KeepForService(traceID, "", statusCode, durationNano)
}

func (s *Sampler) KeepForService(traceID, service string, statusCode int32, durationNano int64) bool {
	return s.KeepForScope(traceID, service, "", "", statusCode, 0, durationNano)
}

func (s *Sampler) KeepForScope(traceID, service, env, resource string, statusCode, kind int32, durationNano int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode == "adaptive_monthly" {
		return s.adaptive.keepMonthly(traceID, service, env, resource, kind, statusCode == 2 || s.slowThreshold > 0 && durationNano >= s.slowThreshold, s.baseRate, time.Now())
	}
	if s.mode == "adaptive_agent" {
		return s.adaptive.keep(traceID, service, statusCode == 2 || s.slowThreshold > 0 && durationNano >= s.slowThreshold, s.targetTPS, time.Now())
	}
	// 1) erro — sempre mantém.
	if statusCode == 2 {
		return true
	}
	// 2) lento — sempre mantém.
	if s.slowThreshold > 0 && durationNano >= s.slowThreshold {
		return true
	}
	// 3) amostra determinística dos normais.
	if s.baseRate >= 1 {
		return true
	}
	if s.baseRate <= 0 {
		return false
	}
	threshold := uint64(s.baseRate * float64(^uint64(0)))
	return traceHash(traceID) < threshold
}

func traceHash(traceID string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(traceID))
	return h.Sum64()
}
