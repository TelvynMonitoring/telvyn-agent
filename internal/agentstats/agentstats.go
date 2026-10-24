// Package agentstats mede o próprio processo do agent (goroutines, memória, CPU, disco da
// fila) para o heartbeat e para as métricas do agent. Só lê contadores do runtime e do
// /proc do processo; não toca o que o agent monitora.
package agentstats

import (
	"os"
	"path/filepath"
	"runtime"
	"time"
)

var startedAt = time.Now()

// Process é o retrato do processo do agent.
type Process struct {
	Goroutines     int64
	HeapAllocBytes int64
	SysBytes       int64
	UptimeSeconds  int64
	// CPUSeconds é o tempo de CPU acumulado do processo; nil onde o sistema não informa.
	CPUSeconds *float64
	// QueueDiskBytes é o espaço que as filas duráveis ocupam em disco.
	QueueDiskBytes int64
}

// Read devolve o retrato atual. queueDir é o diretório das filas duráveis.
func Read(queueDir string) Process {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return Process{
		Goroutines:     int64(runtime.NumGoroutine()),
		HeapAllocBytes: int64(mem.HeapAlloc),
		SysBytes:       int64(mem.Sys),
		UptimeSeconds:  int64(time.Since(startedAt).Seconds()),
		CPUSeconds:     processCPUSeconds(),
		QueueDiskBytes: dirSize(queueDir),
	}
}

// dirSize soma os arquivos do diretório (as filas são arquivos .bolt, sem subpastas).
func dirSize(dir string) int64 {
	if dir == "" {
		return 0
	}
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return 0
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if info, err := entry.Info(); err == nil {
			total += info.Size()
		}
	}
	return total
}
