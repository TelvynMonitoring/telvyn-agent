package main

import "testing"

func TestParseAPMSampleRate(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  float64
		valid bool
	}{
		{"", 0.10, true},
		{"  ", 0.10, true},
		{"0", 0, true},
		{"0.10", 0.10, true},
		{"1", 1, true},
		{"-0.01", 0, false},
		{"1.01", 0, false},
		{"NaN", 0, false},
		{"invalid", 0, false},
	} {
		got, err := parseAPMSampleRate(tc.input)
		if tc.valid && err != nil {
			t.Errorf("parseAPMSampleRate(%q) error = %v", tc.input, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("parseAPMSampleRate(%q) expected error", tc.input)
		}
		if tc.valid && got != tc.want {
			t.Errorf("parseAPMSampleRate(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
