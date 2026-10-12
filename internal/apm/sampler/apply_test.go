package sampler

import (
	"math"
	"testing"
	"time"
)

func TestApplyValidatesAndUpdates(t *testing.T) {
	s := New(0, 0)
	if s.KeepRaw("trace", 0, 100) {
		t.Fatal("initial policy")
	}
	if err := s.Apply(1, 2*time.Second); err != nil || !s.KeepRaw("trace", 0, 100) {
		t.Fatal("policy not applied", err)
	}
	if s.Apply(math.NaN(), 0) == nil || s.Apply(0, 11*time.Minute) == nil {
		t.Fatal("invalid accepted")
	}
	if !s.KeepRaw("trace", 0, 100) {
		t.Fatal("invalid policy changed state")
	}
}
