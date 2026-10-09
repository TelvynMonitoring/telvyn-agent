package checks

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// cAdvisor reports zero kernel memory on this cgroup-v2 runtime. Read the
// same kernel counters as the Datadog cgroup-v2 collector, never substitute zero.
func (c *k8sKubeletCheck) containerCgroupMemory(id string) map[string]float64 {
	if !strings.HasPrefix(id, "/kubepods/") && !strings.HasPrefix(id, "/kubepods.slice/") {
		return nil
	}
	if filepath.Clean(id) != id {
		return nil
	}
	root := c.cgroupRoot
	if root == "" {
		root = "/host/sys/fs/cgroup"
	}
	dir := filepath.Join(root, strings.TrimPrefix(id, "/"))
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return nil // v1 needs different counters; absence is not a zero sample.
	}
	out := map[string]float64{}
	if raw, err := os.ReadFile(filepath.Join(dir, "memory.stat")); err == nil {
		stats := map[string]uint64{}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			if value, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				stats[fields[0]] = value
			}
		}
		if value, exists := stats["kernel"]; exists {
			out["memory_kernel_bytes"] = float64(value)
		} else if stack, exists := stats["kernel_stack"]; exists {
			if slab, exists := stats["slab"]; exists {
				out["memory_kernel_bytes"] = float64(stack) + float64(slab)
			}
		}
		for key, metric := range map[string]string{"pgfault": "memory_page_faults_total", "pgmajfault": "memory_major_page_faults_total"} {
			if value, exists := stats[key]; exists {
				out[metric] = float64(value)
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "memory.peak")); err == nil {
		if value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); err == nil && value > 0 {
			out["memory_peak_bytes"] = float64(value)
		}
	}
	for _, controller := range []string{"cpu", "memory", "io"} {
		raw, err := os.ReadFile(filepath.Join(dir, controller+".pressure"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] != "some" {
				continue
			}
			for _, field := range fields[1:] {
				if strings.HasPrefix(field, "total=") {
					if value, err := strconv.ParseUint(strings.TrimPrefix(field, "total="), 10, 64); err == nil {
						out[controller+"_partial_stall_seconds_total"] = float64(value) / 1e6
					}
				}
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "cpu.stat")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				continue
			}
			switch fields[0] {
			case "throttled_usec":
				out["cpu_throttled_seconds_total"] = float64(value) / 1e6
			case "nr_throttled":
				out["cpu_throttled_periods_total"] = float64(value)
			}
		}
	}
	if limit, exists := containerCPULimit(dir, root); exists {
		out["cpu_runtime_limit_cores"] = limit
	}
	return out
}

func containerCPULimit(dir, root string) (float64, bool) {
	hostCPUs, err := os.ReadFile(filepath.Join(root, "cpuset.cpus.effective"))
	if err != nil {
		return 0, false
	}
	hostCount := cpuListCount(string(hostCPUs))
	if hostCount == 0 {
		return 0, false
	}
	for _, path := range []string{dir, filepath.Dir(dir)} {
		limit := float64(hostCount)
		constrained := false
		if raw, err := os.ReadFile(filepath.Join(path, "cpuset.cpus.effective")); err == nil {
			if count := cpuListCount(string(raw)); count > 0 && count != hostCount {
				limit, constrained = float64(count), true
			}
		}
		if raw, err := os.ReadFile(filepath.Join(path, "cpu.max")); err == nil {
			fields := strings.Fields(string(raw))
			if len(fields) == 2 && fields[0] != "max" {
				quota, qerr := strconv.ParseUint(fields[0], 10, 64)
				period, perr := strconv.ParseUint(fields[1], 10, 64)
				if qerr == nil && perr == nil && quota > 0 && period > 0 {
					quotaLimit := float64(quota) / float64(period)
					if !constrained || quotaLimit < limit {
						limit = quotaLimit
					}
					constrained = true
				}
			}
		}
		if constrained {
			return limit, true
		}
	}
	return float64(hostCount), true
}

func cpuListCount(raw string) uint64 {
	var count uint64
	var previous uint64
	for i, part := range strings.Split(strings.TrimSpace(raw), ",") {
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return 0
		}
		start, err := strconv.ParseUint(bounds[0], 10, 32)
		end := start
		if err == nil && len(bounds) == 2 {
			end, err = strconv.ParseUint(bounds[1], 10, 32)
		}
		if err != nil || end < start || (i > 0 && start <= previous) {
			return 0
		}
		count += end - start + 1
		previous = end
	}
	return count
}
