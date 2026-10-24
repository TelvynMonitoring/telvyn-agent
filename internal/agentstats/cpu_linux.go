//go:build linux

package agentstats

import (
	"os"
	"strconv"
	"strings"
)

// clockTicksPerSecond é o USER_HZ do Linux; é 100 em todas as arquiteturas suportadas.
const clockTicksPerSecond = 100.0

// processCPUSeconds lê utime+stime de /proc/self/stat. O campo comm pode ter espaços,
// então os campos só são contados depois do último ')'.
func processCPUSeconds() *float64 {
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return nil
	}
	text := string(raw)
	end := strings.LastIndex(text, ")")
	if end < 0 {
		return nil
	}
	fields := strings.Fields(text[end+1:])
	// Depois do ')' o campo 1 é o estado (campo 3 do arquivo); utime e stime são os
	// campos 14 e 15 do arquivo, ou seja, os índices 11 e 12 aqui.
	if len(fields) < 13 {
		return nil
	}
	utime, errU := strconv.ParseFloat(fields[11], 64)
	stime, errS := strconv.ParseFloat(fields[12], 64)
	if errU != nil || errS != nil {
		return nil
	}
	seconds := (utime + stime) / clockTicksPerSecond
	return &seconds
}
