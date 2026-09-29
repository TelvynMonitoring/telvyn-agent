package checks

import "testing"

func TestOracleLagSeconds(t *testing.T) {
	if value, ok := oracleLagSeconds("+01 02:03:04"); !ok || value != 93784 {
		t.Fatalf("Data Guard lag: %v, %v", value, ok)
	}
	if _, ok := oracleLagSeconds("UNKNOWN"); ok {
		t.Fatal("unknown lag must not become zero")
	}
}
