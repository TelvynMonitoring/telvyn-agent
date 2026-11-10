package snmp

import "testing"

func TestNormalizeTagValue(t *testing.T) {
	for in, want := range map[string]string{
		`C: Label:  Serial Number 6a2b3c`: `C: Label:`,
		"  Physical   memory\n":           "Physical memory",
		"":                                "",
	} {
		if got := normalizeTagValue(in); got != want {
			t.Fatalf("%q -> %q, want %q", in, got, want)
		}
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	if got := normalizeTagValue(string(long)); len(got) != maxTagValueLen {
		t.Fatalf("len=%d", len(got))
	}
}
