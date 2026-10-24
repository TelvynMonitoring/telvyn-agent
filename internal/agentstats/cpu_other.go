//go:build !linux

package agentstats

func processCPUSeconds() *float64 { return nil }
