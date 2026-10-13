package checks

import (
	"strings"
	"testing"
	"time"
)

// fakeClock devolve instantes programados, em ordem, a cada chamada de now().
type fakeClock struct {
	times []time.Time
	i     int
}

func (f *fakeClock) now() time.Time {
	t := f.times[f.i]
	f.i++
	return t
}

// RTT sai da diferença envio→resposta por sequência, inclusive fora de ordem.
func TestRTTTracker_PairsBySequence(t *testing.T) {
	base := time.Now()
	clock := &fakeClock{times: []time.Time{
		base,                             // send seq 0
		base.Add(200 * time.Millisecond), // send seq 1
		base.Add(210 * time.Millisecond), // recv seq 1 → 10ms
		base.Add(230 * time.Millisecond), // recv seq 0 → 230ms
	}}
	tr := newRTTTracker()
	tr.now = clock.now

	tr.onSend(0)
	tr.onSend(1)
	tr.onRecv(1)
	tr.onRecv(0)

	s := tr.summary()
	if s.count != 2 {
		t.Fatalf("count=%d want 2", s.count)
	}
	if s.min != 10*time.Millisecond || s.max != 230*time.Millisecond {
		t.Errorf("min=%v max=%v want 10ms/230ms", s.min, s.max)
	}
	if s.avg != 120*time.Millisecond {
		t.Errorf("avg=%v want 120ms", s.avg)
	}
}

// Resposta sem envio conhecido e segunda resposta da mesma sequência não
// geram amostra: RTT não é inventado.
func TestRTTTracker_IgnoresUnknownAndRepeatedSequence(t *testing.T) {
	base := time.Now()
	clock := &fakeClock{times: []time.Time{
		base,                            // send seq 5
		base.Add(5 * time.Millisecond),  // recv seq 5
		base.Add(9 * time.Millisecond),  // recv seq 5 de novo
		base.Add(12 * time.Millisecond), // recv seq 99 (nunca enviado)
	}}
	tr := newRTTTracker()
	tr.now = clock.now

	tr.onSend(5)
	tr.onRecv(5)
	tr.onRecv(5)
	tr.onRecv(99)

	if s := tr.summary(); s.count != 1 || s.avg != 5*time.Millisecond {
		t.Fatalf("summary=%+v want uma amostra de 5ms", s)
	}
}

// Relógio que anda para trás entre envio e resposta (o cenário que gerava
// -10507 ms) não pode produzir RTT negativo.
func TestRTTTracker_DropsNegativeRTT(t *testing.T) {
	base := time.Now()
	clock := &fakeClock{times: []time.Time{
		base,
		base.Add(-10507 * time.Millisecond),
	}}
	tr := newRTTTracker()
	tr.now = clock.now

	tr.onSend(0)
	tr.onRecv(0)

	if s := tr.summary(); s.count != 0 || s.avg != 0 {
		t.Fatalf("summary=%+v want vazio", s)
	}
}

// A leitura que o check usa de verdade (time.Now) é monotônica: subtrair dois
// instantes dela nunca dá negativo. Já a reconstrução a partir de UnixNano —
// o que o pro-bing faz com o payload — perde a leitura monotônica, e é por
// isso que um ajuste de relógio entrava no RTT.
func TestRTTTracker_DefaultClockIsMonotonic(t *testing.T) {
	// time.Time.String() inclui "m=±..." só quando há leitura monotônica.
	sent := newRTTTracker().now()
	if !strings.Contains(sent.String(), "m=") {
		t.Fatalf("relógio do tracker sem leitura monotônica: %s", sent)
	}
	wallOnly := time.Unix(0, sent.UnixNano())
	if strings.Contains(wallOnly.String(), "m=") {
		t.Fatalf("instante de UnixNano não deveria ter leitura monotônica: %s", wallOnly)
	}
}

// Mesma fórmula do pro-bing: desvio padrão populacional.
func TestSummarizeRTTs(t *testing.T) {
	s := summarizeRTTs([]time.Duration{2 * time.Millisecond, 4 * time.Millisecond, 4 * time.Millisecond, 4 * time.Millisecond, 5 * time.Millisecond, 5 * time.Millisecond, 7 * time.Millisecond, 9 * time.Millisecond})
	if s.avg != 5*time.Millisecond {
		t.Errorf("avg=%v want 5ms", s.avg)
	}
	if s.stdDev != 2*time.Millisecond {
		t.Errorf("stdDev=%v want 2ms", s.stdDev)
	}
	if s.min != 2*time.Millisecond || s.max != 9*time.Millisecond {
		t.Errorf("min=%v max=%v want 2ms/9ms", s.min, s.max)
	}
	if empty := summarizeRTTs(nil); empty != (rttSummary{}) {
		t.Errorf("vazio=%+v want zero", empty)
	}
}
