package latency

import (
	"bytes"
	"encoding/hex"
	"math"
	"math/rand"
	"sort"
	"testing"
)

func TestQuantisDentroDoErroRelativo(t *testing.T) {
	s := New()
	r := rand.New(rand.NewSource(7))
	values := make([]float64, 20000)
	for i := range values {
		values[i] = math.Exp(r.NormFloat64()*1.2 + 16)
		s.Add(values[i])
	}
	sort.Float64s(values)
	for _, q := range []float64{0.5, 0.9, 0.95, 0.99, 0.999} {
		exact := values[int(math.Round(q*float64(len(values)-1)))]
		got := s.Quantile(q)
		if math.Abs(got-exact)/exact > 0.0125 {
			t.Fatalf("q=%v exato=%v estimado=%v", q, exact, got)
		}
	}
}

func TestEncodeDecodeEMerge(t *testing.T) {
	a, b := New(), New()
	for i := 0; i < 100; i++ {
		a.Add(10e6)
	}
	for i := 0; i < 300; i++ {
		b.Add(200e6)
	}
	b.Add(0)
	back, err := Decode(b.Encode())
	if err != nil || back.Count() != b.Count() || back.Quantile(0.95) != b.Quantile(0.95) {
		t.Fatalf("round trip falhou: %v", err)
	}
	a.MergeWith(back)
	if a.Count() != 401 {
		t.Fatalf("count=%d", a.Count())
	}
	if p := a.Quantile(0.5); math.Abs(p-200e6)/200e6 > 0.0125 {
		t.Fatalf("p50=%v", p)
	}
}

// Os mesmos 10 valores, codificados pelo backend (Java), têm que dar exatamente estes bytes: os dois lados concordam.
func TestFormatoCompartilhadoComOBackend(t *testing.T) {
	s := New()
	for _, v := range []float64{1e6, 2e6, 2e6, 5e6, 8e6, 30e6, 40e6, 40e6, 120e6, 900e6} {
		s.Add(v)
	}
	want, _ := hex.DecodeString("fe010008e60a0146025c012e018401011e026e01c80101")
	if got := s.Encode(); !bytes.Equal(got, want) {
		t.Fatalf("bytes diferentes do backend: %x", got)
	}
	back, err := Decode(want)
	if err != nil || back.Count() != 10 {
		t.Fatalf("decode: %v", err)
	}
	if _, err := Decode([]byte{0x09, 0x01}); err == nil {
		t.Fatal("formato desconhecido deveria falhar")
	}
}
