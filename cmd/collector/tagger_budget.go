package main

import "strconv"

func configuredTaggerBudget(raw string) int {
	if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 100000 {
		return n
	}
	return 10000
}
