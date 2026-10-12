package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerCPULimitUsesQuotaCPUSetParentAndHostCapacity(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pod", "container")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(path, value string) {
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "cpuset.cpus.effective"), "0-3\n")
	write(filepath.Join(dir, "cpuset.cpus.effective"), "0-3\n")
	write(filepath.Join(dir, "cpu.max"), "max 100000\n")
	if value, ok := containerCPULimit(dir, root); !ok || value != 4 {
		t.Fatal(value, ok)
	}
	write(filepath.Join(filepath.Dir(dir), "cpu.max"), "25000 100000\n")
	if value, ok := containerCPULimit(dir, root); !ok || value != .25 {
		t.Fatal(value, ok)
	}
	write(filepath.Join(dir, "cpu.max"), "150000 100000\n")
	write(filepath.Join(dir, "cpuset.cpus.effective"), "0\n")
	if value, ok := containerCPULimit(dir, root); !ok || value != 1 {
		t.Fatal(value, ok)
	}
	for raw, want := range map[string]uint64{"0-3,5,7-8": 7, "": 0, "3-1": 0, "0,0": 0, "0-2,1": 0, "invalid": 0} {
		if value := cpuListCount(raw); value != want {
			t.Fatal(raw, value, want)
		}
	}
}

func TestContainerCgroupMemoryUsesKernelCounterAndDoesNotFabricateMissingValues(t *testing.T) {
	root := t.TempDir()
	id := "/kubepods.slice/pod.slice/cri-containerd-test.scope"
	dir := filepath.Join(root, strings.TrimPrefix(id, "/"))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(name, text string) {
		if err := os.WriteFile(name, []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "cgroup.controllers"), "memory")
	write(filepath.Join(dir, "memory.stat"), "kernel 4096\nkernel_stack 10\nslab 20\npgfault 123\npgmajfault 0\n")
	write(filepath.Join(dir, "memory.peak"), "8192\n")
	check := k8sKubeletCheck{cgroupRoot: root}
	values := check.containerCgroupMemory(id)
	if values["memory_kernel_bytes"] != 4096 || values["memory_peak_bytes"] != 8192 {
		t.Fatal(values)
	}
	if value, exists := values["memory_major_page_faults_total"]; !exists || value != 0 || values["memory_page_faults_total"] != 123 {
		t.Fatal(values)
	}
	write(filepath.Join(dir, "memory.stat"), "kernel invalid\nkernel_stack 10\nslab 20\n")
	if values = check.containerCgroupMemory(id); values["memory_kernel_bytes"] != 30 {
		t.Fatal(values)
	}
	write(filepath.Join(dir, "memory.stat"), "kernel_stack 10\nslab -20\n")
	write(filepath.Join(dir, "memory.peak"), "0")
	if values = check.containerCgroupMemory(id); len(values) != 0 {
		t.Fatal(values)
	}
	for _, invalid := range []string{"/", "/kubepods.slice/../../etc", "/system.slice/other.scope"} {
		if values = check.containerCgroupMemory(invalid); len(values) != 0 {
			t.Fatal(invalid, values)
		}
	}
	write(filepath.Join(dir, "cpu.pressure"), "some avg10=0 total=1500000\nfull total=9000000\n")
	write(filepath.Join(dir, "memory.pressure"), "some total=0\n")
	write(filepath.Join(dir, "io.pressure"), "some total=invalid\n")
	values = check.containerCgroupMemory(id)
	if values["cpu_partial_stall_seconds_total"] != 1.5 {
		t.Fatal(values)
	}
	if value, exists := values["memory_partial_stall_seconds_total"]; !exists || value != 0 {
		t.Fatal(values)
	}
	if _, exists := values["io_partial_stall_seconds_total"]; exists {
		t.Fatal(values)
	}
	for _, controller := range []string{"cpu", "memory", "io"} {
		if err := os.Remove(filepath.Join(dir, controller+".pressure")); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "cpu.stat"), "throttled_usec 250000\nnr_throttled 0\nusage_usec 999999\n")
	values = check.containerCgroupMemory(id)
	if value, exists := values["cpu_throttled_periods_total"]; !exists || value != 0 || values["cpu_throttled_seconds_total"] != 0.25 {
		t.Fatal(values)
	}
	write(filepath.Join(dir, "cpu.stat"), "throttled_usec invalid\nnr_throttled -1\n")
	metrics, err := check.parseCadvisor(strings.NewReader(`container_threads{id="`+id+`",namespace="ns",pod="pod",container="app"} 3
container_oom_events_total{id="`+id+`",namespace="ns",pod="pod",container="app"} 2
`), "node")
	if err != nil || len(metrics) != 2 {
		t.Fatal(metrics, err)
	}
	write(filepath.Join(dir, "memory.stat"), "kernel 4096\n")
	metrics, err = check.parseCadvisor(strings.NewReader(`container_threads{id="`+id+`",namespace="ns",pod="pod",container="app"} 3
container_oom_events_total{id="`+id+`",namespace="ns",pod="pod",container="app"} 2
`), "node")
	if err != nil || len(metrics) != 3 || metrics[0].Source != "k8s.cgroup" || metrics[0].Value != 4096 {
		t.Fatal(metrics, err)
	}
}
