package main

import "strconv"

const (
	// defaultTaggerBudget é o orçamento de séries por equipamento quando a
	// variável não está definida ou é inválida.
	defaultTaggerBudget = 50000
	// maxTaggerBudget é o teto aceito em TELVYN_TAGGER_BUDGET_PER_HOST.
	maxTaggerBudget = 100000
)

func configuredTaggerBudget(raw string) int {
	if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= maxTaggerBudget {
		return n
	}
	return defaultTaggerBudget
}
