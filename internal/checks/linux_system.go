// linux_system.go — the "linux.system" Check implementation.
//
// Collects host-level system metrics using gopsutil/v4:
//   - cpu.user / cpu.system / cpu.idle / cpu.iowait   (delta %, first run skipped)
//   - cpu.usage                                       (= 100 - idle%; nome canônico,
//     o mesmo que os perfis SNMP publicam, pra um monitor cobrir rede + servidor)
//   - mem.used / mem.available / mem.used_pct          (bytes / %)
//   - mem.swap_used                                     (bytes)
//   - disk.used_pct{mount, device}                     (%, physical fstypes only)
//   - disk.used_bytes{mount, device}                   (bytes, physical fstypes only)
//   - disk.total_bytes{mount, device}                  (bytes, physical fstypes only)
//   - disk.io_latency_ms{device}                       (ms/op, delta-based)
//   - disk.read_bytes_per_second{device}               (bytes/s, delta-based)
//   - disk.write_bytes_per_second{device}              (bytes/s, delta-based)
//   - net.bytes_in / net.bytes_out{interface_name}     (cumulative bytes, lo skipped)
//   - load.1 / load.5 / load.15                        (Linux/macOS only)
//
// Metric names match the Quarkus VmRemoteWriter regex ^(cpu|mem|disk|net|load)\.
// so they are forwarded to VictoriaMetrics without being dropped.
//
// Local Agent mode (D-12): the check runs on the same host as the agent —
// it reads /proc/stat, /proc/meminfo, /sys/class/net, etc. via gopsutil.
// No shell commands, no cgo.
package checks

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/common"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gopsutilnet "github.com/shirou/gopsutil/v4/net"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// physicalFs is the allow-list of filesystem types considered "physical"
// (i.e. backed by real storage). Virtual mounts (tmpfs, devtmpfs, proc,
// sysfs, cgroup, overlay, squashfs, binfmt_misc) are excluded from disk
// metrics to avoid cardinality explosion and misleading usage numbers.
var physicalFs = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true,
	"xfs":      true,
	"btrfs":    true,
	"zfs":      true,
	"reiserfs": true,
	"jfs":      true,
	"apfs":     true,
	"ntfs":     true,
	"fat32":    true,
	"exfat":    true,
}

// linuxSystemCheck is the concrete implementation of Check for linux.system.
type linuxSystemCheck struct {
	id          string
	interval    time.Duration
	hostID      string
	staticTags  map[string]string
	root        string
	networkProc string

	// lastCpu holds the previous cpu.TimesWithContext sample. CPU metrics are
	// deltas between consecutive samples, so the first Run() call stores the
	// baseline and emits no cpu.* metrics. Second and later calls compute and
	// emit the delta.
	lastCpu []cpu.TimesStat

	// lastDiskIO holds cumulative per-device I/O counters. Like CPU, disk
	// latency is meaningful only as a delta between consecutive samples.
	// The first sample (and a device first seen later) is therefore a baseline,
	// not a zero-latency observation.
	lastDiskIO   map[string]disk.IOCountersStat
	lastDiskIOAt time.Time
}

// newLinuxSystemCheck is the Factory function registered at init() for
// "linux.system". Validates and defaults the CheckConfig fields.
func newLinuxSystemCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 30 * time.Second
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "linux.system-" + cfg.GetHostId()
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}
	return &linuxSystemCheck{
		id:         id,
		interval:   interval,
		hostID:     cfg.GetHostId(),
		staticTags: tags,
	}, nil
}

func (c *linuxSystemCheck) ID() string              { return c.id }
func (c *linuxSystemCheck) Interval() time.Duration { return c.interval }
func (c *linuxSystemCheck) Tags() map[string]string { return c.staticTags }

// Run collects one sample and emits all metric families. CPU is delta-based
// (first call only stores baseline, returns no cpu.* metrics).
func (c *linuxSystemCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	now := timestamppb.Now()
	var out []*collectorv1.Metric

	// --- CPU (cumulative seconds → delta %) ---
	// cpu.TimesWithContext(ctx, false) returns aggregate across all cores.
	// Values are cumulative, so we keep the previous sample and calculate delta.
	times, err := cpu.TimesWithContext(ctx, false)
	if err == nil && len(times) > 0 {
		t := times[0]
		states := map[string]float64{"user": t.User, "nice": t.Nice, "system": t.System, "idle": t.Idle, "iowait": t.Iowait, "irq": t.Irq, "softirq": t.Softirq, "steal": t.Steal, "guest": t.Guest, "guestnice": t.GuestNice}
		for state, value := range states {
			out = append(out, c.metric(now, "cpu."+state+".total", value, nil))
		}
		if cores, err := cpu.CountsWithContext(ctx, true); err == nil {
			out = append(out, c.metric(now, "cpu.logical", float64(cores), nil))
		}
		if len(c.lastCpu) > 0 {
			prev := c.lastCpu[0]
			// total delta in CPU-seconds (all states combined).
			total := cpuTotal(t) - cpuTotal(prev)
			if total > 0 {
				idlePct := (t.Idle - prev.Idle) / total * 100
				out = append(out, c.metric(now, "cpu.user", (t.User+t.Nice-prev.User-prev.Nice)/total*100, nil))
				out = append(out, c.metric(now, "cpu.system", (t.System+t.Irq+t.Softirq-prev.System-prev.Irq-prev.Softirq)/total*100, nil))
				out = append(out, c.metric(now, "cpu.interrupt", (t.Irq+t.Softirq-prev.Irq-prev.Softirq)/total*100, nil))
				out = append(out, c.metric(now, "cpu.stolen", (t.Steal-prev.Steal)/total*100, nil))
				out = append(out, c.metric(now, "cpu.guest", (t.Guest-prev.Guest)/total*100, nil))
				out = append(out, c.metric(now, "cpu.idle", idlePct, nil))
				out = append(out, c.metric(now, "cpu.iowait", (t.Iowait-prev.Iowait)/total*100, nil))
				// cpu.usage — mesmo nome CANÔNICO que os perfis SNMP publicam (o perfil
				// de cada fabricante lê seu OID e grava cpu.usage). Emitindo aqui também,
				// UM único monitor "CPU acima de X%" cobre equipamento de rede e servidor.
				// Cada integração publica no namespace canônico.
				out = append(out, c.metric(now, "cpu.usage", 100-idlePct, nil))
			}
		}
		c.lastCpu = times // always update baseline (even on first call)
	}

	// --- Memory ---
	if v, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		out = append(out, c.metric(now, "mem.used", float64(v.Used), nil))
		out = append(out, c.metric(now, "mem.available", float64(v.Available), nil))
		usedPct := v.UsedPercent
		if c.root != "" && v.Total > 0 {
			usedPct = 100 - float64(v.Available)/float64(v.Total)*100
		}
		out = append(out, c.metric(now, "mem.used_pct", usedPct, nil))
		for name, value := range map[string]uint64{"total": v.Total, "free": v.Free, "occupied": v.Total - v.Free, "cached": v.Cached, "buffered": v.Buffers, "shared": v.Shared, "slab": v.Slab, "slab_reclaimable": v.Sreclaimable, "page_tables": v.PageTables, "commit_limit": v.CommitLimit, "committed_as": v.CommittedAS, "swap_cached": v.SwapCached} {
			out = append(out, c.metric(now, "mem."+name, float64(value), nil))
		}
		if v.Total > 0 {
			out = append(out, c.metric(now, "mem.available_fraction", float64(v.Available)/float64(v.Total), nil))
		}
	}
	if s, err := mem.SwapMemoryWithContext(ctx); err == nil {
		out = append(out, c.metric(now, "mem.swap_used", float64(s.Used), nil))
		out = append(out, c.metric(now, "mem.swap_total", float64(s.Total), nil), c.metric(now, "mem.swap_free", float64(s.Free), nil), c.metric(now, "mem.swap_free_fraction", (100-s.UsedPercent)/100, nil))
		out = append(out, c.metric(now, "disk.block_in_total", float64(s.PgIn), nil), c.metric(now, "disk.block_out_total", float64(s.PgOut), nil))
		out = append(out, c.metric(now, "mem.swap_in_bytes_total", float64(s.Sin), nil), c.metric(now, "mem.swap_out_bytes_total", float64(s.Sout), nil))
	}

	// --- Disk per mount (physical fstypes only) ---
	parts, _ := disk.PartitionsWithContext(ctx, false)
	ioCounters, ioErr := disk.IOCountersWithContext(ctx)
	physicalDiskIO := make(map[string]disk.IOCountersStat)
	for _, p := range parts {
		if !physicalFs[p.Fstype] {
			continue
		}
		// /proc/diskstats counters are keyed by a device name (for example,
		// "sda1"), while partitions normally expose "/dev/sda1". Associate
		// mounted filesystems with their device paths; unmounted devices are
		// added separately below, because I/O does not require a mount.
		// Keep this independent from disk.Usage: an unavailable filesystem-size
		// stat must not suppress otherwise valid I/O counters.
		if ioErr == nil && p.Device != "" {
			if counters, ok := diskIOCounterForDevice(ioCounters, p.Device); ok {
				physicalDiskIO[p.Device] = counters
			}
		}

		mountPath := p.Mountpoint
		if c.root != "" {
			mountPath = filepath.Join(c.root, p.Mountpoint)
		}
		u, err := disk.UsageWithContext(ctx, mountPath)
		if err != nil {
			continue
		}
		tags := map[string]string{
			"mount":  p.Mountpoint,
			"device": p.Device,
		}
		out = append(out, c.metric(now, "disk.used_pct", u.UsedPercent, tags))
		out = append(out, c.metric(now, "disk.used_bytes", float64(u.Used), tags))
		out = append(out, c.metric(now, "disk.total_bytes", float64(u.Total), tags))
		out = append(out, c.metric(now, "disk.free_bytes", float64(u.Free), tags), c.metric(now, "disk.inodes_total", float64(u.InodesTotal), tags), c.metric(now, "disk.inodes_used", float64(u.InodesUsed), tags), c.metric(now, "disk.inodes_free", float64(u.InodesFree), tags), c.metric(now, "disk.inodes_used_pct", u.InodesUsedPercent, tags))
	}
	if ioErr == nil {
		for device, counters := range ioCounters {
			path := "/dev/" + strings.TrimPrefix(device, "/dev/")
			if _, exists := physicalDiskIO[path]; !exists {
				physicalDiskIO[path] = counters
			}
		}
		out = append(out, c.diskIOLatencyMetrics(now, physicalDiskIO)...)
		for device, counters := range physicalDiskIO {
			tags := map[string]string{"device": device}
			out = append(out, c.metric(now, "disk.read_time_ms_total", float64(counters.ReadTime), tags), c.metric(now, "disk.write_time_ms_total", float64(counters.WriteTime), tags))
		}
	}

	// --- Net per interface (loopback attributes, but no loopback traffic) ---
	netCtx := ctx
	if c.networkProc != "" {
		netCtx = context.WithValue(ctx, common.EnvKey, common.EnvMap{common.HostProcEnvKey: c.networkProc})
	}
	counters, _ := gopsutilnet.IOCountersWithContext(netCtx, true)
	for _, n := range counters {
		if n.Name != "lo" && n.Name != "Loopback Pseudo-Interface 1" {
			m1 := c.metric(now, "net.bytes_in", float64(n.BytesRecv), nil)
			m1.InterfaceName = n.Name
			m2 := c.metric(now, "net.bytes_out", float64(n.BytesSent), nil)
			m2.InterfaceName = n.Name
			out = append(out, m1, m2)
			for name, value := range map[string]uint64{"packets_in": n.PacketsRecv, "packets_out": n.PacketsSent, "errors_in": n.Errin, "errors_out": n.Errout, "drops_in": n.Dropin, "drops_out": n.Dropout} {
				m := c.metric(now, "net."+name, float64(value), nil)
				m.InterfaceName = n.Name
				out = append(out, m)
			}
		}
		if paths, ok := ctx.Value(common.EnvKey).(common.EnvMap); ok && c.root != "" {
			iface := filepath.Join(paths[common.HostSysEnvKey], "class/net", n.Name)
			for file, name := range map[string]string{"mtu": "mtu", "tx_queue_len": "tx_queue_len", "carrier": "up", "flags": "admin_up"} {
				if value, ok := readSystemNumber(filepath.Join(iface, file)); ok {
					if file == "flags" {
						value = float64(uint64(value) & 1)
					}
					m := c.metric(now, "net.interface."+name, value, nil)
					m.InterfaceName = n.Name
					out = append(out, m)
				}
			}
			if queues, err := os.ReadDir(filepath.Join(iface, "queues")); err == nil {
				var rx, tx float64
				for _, q := range queues {
					if strings.HasPrefix(q.Name(), "rx-") {
						rx++
					}
					if strings.HasPrefix(q.Name(), "tx-") {
						tx++
					}
				}
				for name, value := range map[string]float64{"num_rx_queues": rx, "num_tx_queues": tx} {
					m := c.metric(now, "net.interface."+name, value, nil)
					m.InterfaceName = n.Name
					out = append(out, m)
				}
			}
		}
	}
	if protocols, err := gopsutilnet.ProtoCountersWithContext(netCtx, []string{"tcp"}); err == nil {
		for _, p := range protocols {
			if value, ok := p.Stats["CurrEstab"]; ok {
				out = append(out, c.metric(now, "net.tcp.current_established", float64(value), nil))
			}
		}
	}
	if paths, ok := ctx.Value(common.EnvKey).(common.EnvMap); ok && c.root != "" {
		for file, name := range map[string]string{"nf_conntrack_count": "count", "nf_conntrack_max": "max", "nf_conntrack_expect_max": "expect_max", "nf_conntrack_tcp_max_retrans": "tcp_max_retrans", "nf_conntrack_tcp_timeout_max_retrans": "tcp_timeout_max_retrans"} {
			if value, ok := readSystemNumber(filepath.Join(paths[common.HostProcEnvKey], "sys/net/netfilter", file)); ok {
				out = append(out, c.metric(now, "net.conntrack."+name, value, nil))
			}
		}
	}

	// --- Load average (Linux / macOS; Windows returns error — ignored) ---
	if misc, err := load.MiscWithContext(ctx); err == nil {
		out = append(out, c.metric(now, "cpu.context_switches_total", float64(misc.Ctxt), nil))
	}
	if l, err := load.AvgWithContext(ctx); err == nil {
		out = append(out, c.metric(now, "load.1", l.Load1, nil))
		out = append(out, c.metric(now, "load.5", l.Load5, nil))
		out = append(out, c.metric(now, "load.15", l.Load15, nil))
		if cores, err := cpu.CountsWithContext(ctx, true); err == nil && cores > 0 {
			for period, value := range map[string]float64{"1": l.Load1, "5": l.Load5, "15": l.Load15} {
				out = append(out, c.metric(now, "load.norm."+period, value/float64(cores), nil))
			}
		}
	}
	if uptime, err := host.UptimeWithContext(ctx); err == nil {
		out = append(out, c.metric(now, "system.uptime", float64(uptime), nil))
	}
	procRoot := os.Getenv(string(common.HostProcEnvKey))
	if paths, ok := ctx.Value(common.EnvKey).(common.EnvMap); ok && paths[common.HostProcEnvKey] != "" {
		procRoot = paths[common.HostProcEnvKey]
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	if raw, err := os.ReadFile(filepath.Join(procRoot, "sys/fs/file-nr")); err == nil {
		out = append(out, c.fileHandleMetrics(now, string(raw))...)
	}

	return out, nil
}

func (c *linuxSystemCheck) fileHandleMetrics(now *timestamppb.Timestamp, raw string) []*collectorv1.Metric {
	fields := strings.Fields(raw)
	if len(fields) != 3 {
		return nil
	}
	var values [3]uint64
	for i, field := range fields {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return nil
		}
		values[i] = value
	}
	if values[1] > values[0] || values[2] == 0 {
		return nil
	}
	used := float64(values[0] - values[1])
	var out []*collectorv1.Metric
	for name, value := range map[string]float64{"allocated": float64(values[0]), "allocated_unused": float64(values[1]), "used": used, "max": float64(values[2]), "in_use": used / float64(values[2])} {
		out = append(out, c.metric(now, "system.fs.file_handles."+name, value, nil))
	}
	return out
}

// diskIOCounterForDevice finds the gopsutil counter that corresponds to a
// mounted device. On Linux partitions commonly use /dev/<name>, while
// IOCounters uses <name> as its map key.
// Guest times are already included in user/nice, not additional CPU time.
func cpuTotal(t cpu.TimesStat) float64 {
	return t.User + t.Nice + t.System + t.Idle + t.Iowait + t.Irq + t.Softirq + t.Steal
}

func readSystemNumber(path string) (float64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 0, 64)
	return float64(v), err == nil
}

func diskIOCounterForDevice(counters map[string]disk.IOCountersStat, device string) (disk.IOCountersStat, bool) {
	if counters == nil {
		return disk.IOCountersStat{}, false
	}
	if counter, ok := counters[device]; ok {
		return counter, true
	}

	name := strings.TrimPrefix(strings.TrimSpace(device), "/dev/")
	if counter, ok := counters[name]; ok {
		return counter, true
	}
	for _, counter := range counters {
		if counter.Name == device || counter.Name == name {
			return counter, true
		}
	}
	return disk.IOCountersStat{}, false
}

// diskIOLatencyMetrics emits the mean completed I/O latency for each physical
// device: (delta read time + delta write time) / (delta reads + delta writes).
// gopsutil reports ReadTime and WriteTime in milliseconds. No point is emitted
// until a device has two monotonic samples; this prevents a first sample or a
// counter reset from being presented as a real 0 ms observation.
func (c *linuxSystemCheck) diskIOLatencyMetrics(now *timestamppb.Timestamp, current map[string]disk.IOCountersStat) []*collectorv1.Metric {
	previous := c.lastDiskIO
	previousAt := c.lastDiskIOAt
	c.lastDiskIO = current
	c.lastDiskIOAt = now.AsTime()
	if len(previous) == 0 || previousAt.IsZero() {
		return nil
	}
	elapsedSeconds := now.AsTime().Sub(previousAt).Seconds()
	if elapsedSeconds <= 0 {
		return nil
	}

	var out []*collectorv1.Metric
	for device, counters := range current {
		last, ok := previous[device]
		if !ok {
			continue
		}
		// A restarted device or reset kernel counters would otherwise underflow
		// and produce a bogus value. Treat the new value as the next baseline.
		if counters.ReadCount < last.ReadCount || counters.WriteCount < last.WriteCount ||
			counters.ReadTime < last.ReadTime || counters.WriteTime < last.WriteTime ||
			counters.ReadBytes < last.ReadBytes || counters.WriteBytes < last.WriteBytes {
			continue
		}

		tags := map[string]string{"device": device}
		readOperations := float64(counters.ReadCount - last.ReadCount)
		writeOperations := float64(counters.WriteCount - last.WriteCount)
		out = append(out,
			c.metric(now, "disk.read_bytes_per_second", float64(counters.ReadBytes-last.ReadBytes)/elapsedSeconds, tags),
			c.metric(now, "disk.write_bytes_per_second", float64(counters.WriteBytes-last.WriteBytes)/elapsedSeconds, tags),
			c.metric(now, "disk.read_operations_per_second", readOperations/elapsedSeconds, tags),
			c.metric(now, "disk.write_operations_per_second", writeOperations/elapsedSeconds, tags),
		)
		if counters.MergedReadCount >= last.MergedReadCount && counters.MergedWriteCount >= last.MergedWriteCount {
			out = append(out, c.metric(now, "disk.read_merged_operations_per_second", float64(counters.MergedReadCount-last.MergedReadCount)/elapsedSeconds, tags), c.metric(now, "disk.write_merged_operations_per_second", float64(counters.MergedWriteCount-last.MergedWriteCount)/elapsedSeconds, tags))
		}
		if counters.IoTime >= last.IoTime {
			out = append(out, c.metric(now, "disk.io_utilization_pct", float64(counters.IoTime-last.IoTime)/(elapsedSeconds*10), tags))
		}
		if counters.WeightedIO >= last.WeightedIO {
			// Kernel weighted I/O time is milliseconds, hence /1000 for queue depth.
			out = append(out, c.metric(now, "disk.io_queue_size", float64(counters.WeightedIO-last.WeightedIO)/(elapsedSeconds*1000), tags))
		}
		if readOperations > 0 {
			out = append(out, c.metric(now, "disk.read_latency_ms", float64(counters.ReadTime-last.ReadTime)/readOperations, tags))
		}
		if writeOperations > 0 {
			out = append(out, c.metric(now, "disk.write_latency_ms", float64(counters.WriteTime-last.WriteTime)/writeOperations, tags))
		}
		operations := readOperations + writeOperations
		if operations > 0 {
			elapsedMilliseconds := float64(counters.ReadTime-last.ReadTime) + float64(counters.WriteTime-last.WriteTime)
			out = append(out, c.metric(now, "disk.io_latency_ms", elapsedMilliseconds/operations, tags))
			out = append(out, c.metric(now, "disk.io_request_size_bytes", float64(counters.ReadBytes-last.ReadBytes+counters.WriteBytes-last.WriteBytes)/operations, tags))
			if counters.IoTime >= last.IoTime {
				out = append(out, c.metric(now, "disk.io_service_time_ms", float64(counters.IoTime-last.IoTime)/operations, tags))
			}
		}
	}
	return out
}

// metric constructs a collectorv1.Metric with the check's static tags merged
// with any extra per-metric tags. Extra tags take precedence.
func (c *linuxSystemCheck) metric(t *timestamppb.Timestamp, name string, val float64, extraTags map[string]string) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags)+len(extraTags))
	for k, v := range c.staticTags {
		tags[k] = v
	}
	for k, v := range extraTags {
		tags[k] = v
	}
	return &collectorv1.Metric{
		Time:       t,
		HostId:     c.hostID,
		MetricName: name,
		Value:      val,
		Tags:       tags,
		Source:     "linux.system",
	}
}

// init auto-registers the linux.system factory in the Default registry.
// Placing the registration here (rather than in main.go) follows the
// Cada pacote de check registra a si mesmo, e o
// binary only needs to blank-import the packages it wants.
func init() {
	Default.Register("linux.system", newLinuxSystemCheck)
}
