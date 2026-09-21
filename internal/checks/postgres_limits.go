package checks

import (
	"strconv"
	"strings"
)

func boundedInt(value, minimum, maximum, fallback int) int {
	if value < minimum || value > maximum {
		return fallback
	}
	return value
}

func boundedParam(params map[string]string, key string, minimum, maximum, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(params[key]))
	if err != nil {
		return fallback
	}
	return boundedInt(value, minimum, maximum, fallback)
}

func boolParam(params map[string]string, key string, fallback bool) bool {
	raw := strings.TrimSpace(params[key])
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func floatParam(params map[string]string, key string, minimum, maximum, fallback float64) float64 {
	value, err := strconv.ParseFloat(strings.TrimSpace(params[key]), 64)
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}
