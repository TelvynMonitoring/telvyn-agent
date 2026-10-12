package checks

import (
	"context"
	"github.com/shirou/gopsutil/v4/common"
	"github.com/shirou/gopsutil/v4/cpu"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestNodeSystemHostContextAndCPUAccounting(t *testing.T) {
	if got := cpuTotal(cpu.TimesStat{User: 10, Nice: 2, System: 3, Idle: 20, Irq: 1, Guest: 4, GuestNice: 1}); got != 36 {
		t.Fatalf("guest double-counted: %v", got)
	}
	proc := t.TempDir()
	for name, contents := range map[string]string{
		"stat":      "cpu  100 2 30 400 5 6 7 8 9 1\ncpu0 100 2 30 400 5 6 7 8 9 1\nctxt 1000\n",
		"meminfo":   "MemTotal: 1000 kB\nMemFree: 200 kB\nMemAvailable: 400 kB\nBuffers: 50 kB\nCached: 100 kB\nSwapTotal: 100 kB\nSwapFree: 80 kB\n",
		"loadavg":   "1.00 2.00 3.00 1/10 100\n",
		"vmstat":    "pswpin 1\npswpout 2\n",
		"diskstats": "8 0 sda 100 0 200 300 400 0 500 600 0 0 0\n",
	} {
		if err := os.WriteFile(filepath.Join(proc, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.WithValue(context.Background(), common.EnvKey, common.EnvMap{common.HostProcEnvKey: proc})
	c := &linuxSystemCheck{hostID: "node-under-test"}
	metrics, err := c.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, m := range metrics {
		if m.HostId != "node-under-test" {
			t.Fatal("incorrect host identity")
		}
		values[m.MetricName] = m.Value
	}
	for name, expected := range map[string]float64{"mem.total": 1024000, "mem.occupied": 819200, "mem.available": 409600, "load.5": 2, "cpu.guest.total": 0.09, "cpu.context_switches_total": 1000, "mem.swap_in_bytes_total": 4096, "mem.swap_out_bytes_total": 8192, "disk.read_time_ms_total": 300, "disk.write_time_ms_total": 600} {
		if values[name] != expected {
			t.Fatalf("%s = %v, want %v", name, values[name], expected)
		}
	}
	if err := os.WriteFile(filepath.Join(proc, "stat"), []byte("cpu 110 4 33 420 6 8 8 9 10 1\ncpu0 110 4 33 420 6 8 8 9 10 1\nctxt 1200\n"), 0600); err != nil {
		t.Fatal(err)
	}
	metrics, err = c.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string]float64{"cpu.user": 30, "cpu.system": 15, "cpu.interrupt": 7.5, "cpu.stolen": 2.5, "cpu.guest": 2.5, "cpu.idle": 50, "cpu.usage": 50, "cpu.context_switches_total": 1200} {
		got, exists := metricValue(metrics, name)
		if !exists || math.Abs(got-expected) > 1e-10 {
			t.Fatalf("%s = %v, want %v", name, got, expected)
		}
	}
}

func TestNodeSystemLoopbackAttributesWithoutTraffic(t *testing.T) {
	proc, sys := t.TempDir(), t.TempDir()
	files := map[string]string{
		filepath.Join(proc, "net/dev"):                  "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\nlo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\neth0: 200 2 0 0 0 0 0 0 300 3 0 0 0 0 0 0\n",
		filepath.Join(sys, "class/net/lo/mtu"):          "65536\n",
		filepath.Join(sys, "class/net/lo/tx_queue_len"): "1000\n",
		filepath.Join(sys, "class/net/lo/flags"):        "0x9\n",
		filepath.Join(sys, "class/net/lo/carrier"):      "0\n",
	}
	for path, value := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, queue := range []string{"rx-0", "tx-0"} {
		if err := os.MkdirAll(filepath.Join(sys, "class/net/lo/queues", queue), 0700); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.WithValue(context.Background(), common.EnvKey, common.EnvMap{common.HostProcEnvKey: proc, common.HostSysEnvKey: sys})
	c := &linuxSystemCheck{hostID: "node-under-test", root: proc}
	metrics, err := c.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, m := range metrics {
		if m.InterfaceName == "lo" {
			values[m.MetricName] = m.Value
		}
	}
	if len(values) != 6 {
		t.Fatalf("loopback metrics = %v, want only six attributes", values)
	}
	for name, expected := range map[string]float64{"mtu": 65536, "tx_queue_len": 1000, "up": 0, "admin_up": 1, "num_rx_queues": 1, "num_tx_queues": 1} {
		if values["net.interface."+name] != expected {
			t.Fatalf("%s = %v, want %v", name, values["net.interface."+name], expected)
		}
	}
}
