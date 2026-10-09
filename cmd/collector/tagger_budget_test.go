package main

import "testing"

func TestConfiguredTaggerBudget(t *testing.T) {
	for raw, want := range map[string]int{"": 10000, "bad": 10000, "0": 10000, "-1": 10000, "50000": 50000, "100001": 10000} {
		if got := configuredTaggerBudget(raw); got != want {
			t.Fatalf("budget %q = %d, want %d", raw, got, want)
		}
	}
}
