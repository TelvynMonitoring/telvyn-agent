package main

import "testing"

func TestConfiguredTaggerBudget(t *testing.T) {
	for raw, want := range map[string]int{"": 50000, "bad": 50000, "0": 50000, "-1": 50000, "20000": 20000, "100000": 100000, "100001": 50000} {
		if got := configuredTaggerBudget(raw); got != want {
			t.Fatalf("budget %q = %d, want %d", raw, got, want)
		}
	}
}
