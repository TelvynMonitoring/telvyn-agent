// docker_host_test.go — testes do check "docker.host" (Phase 4 Plan 07).
//
// Estratégia: usa fake `dockerClient` (interface seam) que injeta resultados
// de Ping / ContainerList / ContainerStatsOneShot sem precisar de daemon
// real ou socket. Cobre Pitfalls 2 (permission denied), 8 (parallelism cap).
//
// Cobertura:
//   1. Factory falha quando Ping retorna permission denied; mensagem inclui
//      hint TELVYN_DOCKER_INTEGRATION=true
//   2. Run emite docker.containers_running + docker.containers_stopped
//   3. Run emite 5 métricas por container running (CPU, mem, restart, rx, tx)
//   4. Semaphore limita concorrência de stats em 5 (Pitfall 8)
//   5. Stats com erro num container não aborta a Run (best-effort)
//   6. Factory registrada em Default

package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"google.golang.org/protobuf/types/known/durationpb"

	collectorv1 "github.com/telvynmonitoring/telvyn-agent/proto/v1"
)

// fakeDockerClient implementa dockerClient via fixtures controladas.
type fakeDockerClient struct {
	pingErr error

	listResult []container.Summary
	listErr    error

	// statsByID retorna fixtures pré-fabricadas; chaves devem casar com
	// container IDs em listResult.
	statsByID  map[string]container.StatsResponse
	statsErrs  map[string]error
	statsDelay map[string]time.Duration // delay para teste de semaphore

	// Inspect (restart_count, oom, uptime, health).
	inspectByID map[string]container.InspectResponse
	inspectErr  error

	closed atomic.Bool

	// instrumentação de semaphore: contadores e máximo concorrente
	inFlight    atomic.Int64
	maxInFlight atomic.Int64
}

func (f *fakeDockerClient) Ping(ctx context.Context) (dockertypes.Ping, error) {
	if f.pingErr != nil {
		return dockertypes.Ping{}, f.pingErr
	}
	return dockertypes.Ping{APIVersion: "1.45"}, nil
}

func (f *fakeDockerClient) ContainerList(ctx context.Context, opts container.ListOptions) ([]container.Summary, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResult, nil
}

func (f *fakeDockerClient) ContainerStatsOneShot(ctx context.Context, containerID string) (container.StatsResponseReader, error) {
	// instrumentação de concorrência: incrementa no entry, decrementa no exit.
	cur := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		max := f.maxInFlight.Load()
		if cur <= max || f.maxInFlight.CompareAndSwap(max, cur) {
			break
		}
	}

	if d, ok := f.statsDelay[containerID]; ok && d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return container.StatsResponseReader{}, ctx.Err()
		}
	}

	if err, ok := f.statsErrs[containerID]; ok && err != nil {
		return container.StatsResponseReader{}, err
	}
	if stats, ok := f.statsByID[containerID]; ok {
		buf, err := json.Marshal(stats)
		if err != nil {
			return container.StatsResponseReader{}, err
		}
		return container.StatsResponseReader{
			Body:   io.NopCloser(bytes.NewReader(buf)),
			OSType: "linux",
		}, nil
	}
	return container.StatsResponseReader{}, errors.New("no fixture for container")
}

// ContainerInspect devolve fixture de inspectByID; sem fixture devolve um container "running"
// sem reinícios (o suficiente para os testes que não olham o Inspect).
func (f *fakeDockerClient) ContainerInspect(ctx context.Context, containerID string) (container.InspectResponse, error) {
	if f.inspectErr != nil {
		return container.InspectResponse{}, f.inspectErr
	}
	if r, ok := f.inspectByID[containerID]; ok {
		return r, nil
	}
	return container.InspectResponse{ContainerJSONBase: &container.ContainerJSONBase{
		State: &container.State{Status: "running", Running: true, StartedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)},
	}}, nil
}

func (f *fakeDockerClient) Close() error {
	f.closed.Store(true)
	return nil
}

// newDockerHostWithClient cria dockerHost com cliente fake injetado, pulando
// a Factory pública (que tentaria abrir socket real).
func newDockerHostWithClient(hostID string, staticTags map[string]string, cli dockerClient) *dockerHost {
	if staticTags == nil {
		staticTags = map[string]string{}
	}
	return &dockerHost{
		id:         "docker.host-" + hostID,
		hostID:     hostID,
		interval:   60 * time.Second,
		staticTags: staticTags,
		cli:        cli,
		statsCap:   5,
	}
}

// TestDockerHost_FactoryFailsOnPingError — quando Ping retorna permission
// denied, factory devolve erro contendo o hint do install.sh.
func TestDockerHost_FactoryFailsOnPingError(t *testing.T) {
	// Substituir o factory default por um que injeta cliente com pingErr.
	orig := defaultDockerClientFactory
	defer func() { defaultDockerClientFactory = orig }()
	defaultDockerClientFactory = func() (dockerClient, error) {
		return &fakeDockerClient{pingErr: errors.New("permission denied while trying to connect to /var/run/docker.sock")}, nil
	}

	cfg := &collectorv1.CheckConfig{
		CheckType: "docker.host",
		Interval:  durationpb.New(60 * time.Second),
		Enabled:   true,
		HostId:    "host-perm",
		Params:    map[string]string{},
	}
	_, err := newDockerHostCheck(cfg)
	if err == nil {
		t.Fatal("expected factory error from Ping permission denied, got nil")
	}
	if !contains(err.Error(), "TELVYN_DOCKER_INTEGRATION=true") {
		t.Errorf("error should hint install.sh flag, got %q", err.Error())
	}
}

// TestDockerHost_RunEmitsRunningStoppedCounts — métricas top-level cobrem
// containers running e stopped (sem precisar de stats por container).
func TestDockerHost_RunEmitsRunningStoppedCounts(t *testing.T) {
	cli := &fakeDockerClient{
		listResult: []container.Summary{
			{ID: "c1", Names: []string{"/a"}, State: container.StateRunning},
			{ID: "c2", Names: []string{"/b"}, State: container.StateRunning},
			{ID: "c3", Names: []string{"/c"}, State: container.StateRunning},
			{ID: "c4", Names: []string{"/d"}, State: container.StateExited},
			{ID: "c5", Names: []string{"/e"}, State: container.StateExited},
		},
		statsByID: map[string]container.StatsResponse{
			"c1": minimalStats("c1"),
			"c2": minimalStats("c2"),
			"c3": minimalStats("c3"),
		},
	}
	dh := newDockerHostWithClient("host-counts", nil, cli)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	metrics, err := dh.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var running, stopped *float64
	for _, m := range metrics {
		v := m.Value
		switch m.MetricName {
		case "docker.containers_running":
			running = &v
		case "docker.containers_stopped":
			stopped = &v
		}
	}
	if running == nil {
		t.Fatal("missing docker.containers_running")
	}
	if *running != 3 {
		t.Errorf("running=%v want 3", *running)
	}
	if stopped == nil {
		t.Fatal("missing docker.containers_stopped")
	}
	if *stopped != 2 {
		t.Errorf("stopped=%v want 2", *stopped)
	}
}

// TestDockerHost_RunEmitsPerContainerMetrics — para 1 container running,
// emite 5 métricas com tag container_name + 2 top-level (running/stopped).
func TestDockerHost_RunEmitsPerContainerMetrics(t *testing.T) {
	stats := container.StatsResponse{
		ID:   "abc123",
		Name: "/web",
		CPUStats: container.CPUStats{
			CPUUsage:    container.CPUUsage{TotalUsage: 2_000_000},
			SystemUsage: 10_000_000,
			OnlineCPUs:  4,
		},
		PreCPUStats: container.CPUStats{
			CPUUsage:    container.CPUUsage{TotalUsage: 1_000_000},
			SystemUsage: 8_000_000,
		},
		MemoryStats: container.MemoryStats{
			Usage: 200_000_000,
			Stats: map[string]uint64{"cache": 50_000_000},
		},
		Networks: map[string]container.NetworkStats{
			"eth0": {RxBytes: 1024, TxBytes: 2048},
			"eth1": {RxBytes: 512, TxBytes: 256},
		},
	}
	cli := &fakeDockerClient{
		listResult: []container.Summary{
			{ID: "abc123", Names: []string{"/web"}, State: container.StateRunning},
		},
		statsByID: map[string]container.StatsResponse{"abc123": stats},
	}
	dh := newDockerHostWithClient("host-perc", nil, cli)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	metrics, err := dh.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	wantNames := map[string]bool{
		"docker.container.cpu_percent":      false,
		"docker.container.mem_used_bytes":   false,
		"docker.container.restart_count":    false,
		"docker.container.network_rx_bytes": false,
		"docker.container.network_tx_bytes": false,
	}
	for _, m := range metrics {
		if _, ok := wantNames[m.MetricName]; !ok {
			continue
		}
		if m.Tags["container_name"] != "web" {
			t.Errorf("metric %q container_name=%q want web", m.MetricName, m.Tags["container_name"])
		}
		wantNames[m.MetricName] = true
		switch m.MetricName {
		case "docker.container.mem_used_bytes":
			// 200M − 50M = 150M
			if m.Value != 150_000_000 {
				t.Errorf("mem_used_bytes=%v want 150000000", m.Value)
			}
		case "docker.container.network_rx_bytes":
			if m.Value != 1536 { // 1024+512
				t.Errorf("network_rx_bytes=%v want 1536", m.Value)
			}
		case "docker.container.network_tx_bytes":
			if m.Value != 2304 { // 2048+256
				t.Errorf("network_tx_bytes=%v want 2304", m.Value)
			}
		case "docker.container.cpu_percent":
			// cpuDelta=1M, sysDelta=2M, cpus=4 → 0.5 * 4 * 100 = 200
			if m.Value != 200.0 {
				t.Errorf("cpu_percent=%v want 200", m.Value)
			}
		}
	}
	for name, ok := range wantNames {
		if !ok {
			t.Errorf("missing per-container metric %q", name)
		}
	}
}

// TestDockerHost_SemaphoreBoundsConcurrency — 20 containers com stats
// blocantes; max concurrent stats <= 5 (Pitfall 8).
func TestDockerHost_SemaphoreBoundsConcurrency(t *testing.T) {
	const N = 20
	delays := make(map[string]time.Duration, N)
	statsByID := make(map[string]container.StatsResponse, N)
	summaries := make([]container.Summary, 0, N)
	for i := 0; i < N; i++ {
		id := "c" + itoa(i)
		summaries = append(summaries, container.Summary{
			ID:    id,
			Names: []string{"/" + id},
			State: container.StateRunning,
		})
		delays[id] = 60 * time.Millisecond
		statsByID[id] = minimalStats(id)
	}
	cli := &fakeDockerClient{
		listResult: summaries,
		statsByID:  statsByID,
		statsDelay: delays,
	}
	dh := newDockerHostWithClient("host-sem", nil, cli)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := dh.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := cli.maxInFlight.Load(); got > 5 {
		t.Errorf("maxInFlight=%d, expected <=5 (semaphore Pitfall 8)", got)
	}
	if got := cli.maxInFlight.Load(); got == 0 {
		t.Errorf("maxInFlight=0 — stats never reached fake client")
	}
}

// TestDockerHost_StatsErrorOnOneContainerDoesntAbortRun — stats com erro num
// container não impede que os outros emitam métricas (best-effort).
func TestDockerHost_StatsErrorOnOneContainerDoesntAbortRun(t *testing.T) {
	cli := &fakeDockerClient{
		listResult: []container.Summary{
			{ID: "good", Names: []string{"/good"}, State: container.StateRunning},
			{ID: "bad", Names: []string{"/bad"}, State: container.StateRunning},
		},
		statsByID: map[string]container.StatsResponse{
			"good": minimalStats("good"),
		},
		statsErrs: map[string]error{
			"bad": errors.New("stats: connection broken"),
		},
	}
	dh := newDockerHostWithClient("host-mix", nil, cli)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	metrics, err := dh.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v (expected nil — best-effort)", err)
	}

	// Esperado: métricas top-level + 5 métricas do "good"; nada de "bad".
	foundGood := false
	for _, m := range metrics {
		if m.Tags["container_name"] == "good" {
			foundGood = true
		}
		if m.Tags["container_name"] == "bad" {
			t.Errorf("unexpected metric for failed container: %q", m.MetricName)
		}
	}
	if !foundGood {
		t.Errorf("missing metrics for healthy container 'good'")
	}
}

// TestDockerHost_Registry — confirma init() registrou em Default.
func TestDockerHost_Registry(t *testing.T) {
	f, ok := Default.Get("docker.host")
	if !ok {
		t.Fatal("docker.host not registered in Default")
	}
	if f == nil {
		t.Fatal("registered factory is nil")
	}
}

// --- helpers --------------------------------------------------------------

// minimalStats devolve StatsResponse minimamente válido — útil pra tests
// que só medem presença de métricas (não valor exato).
func minimalStats(id string) container.StatsResponse {
	return container.StatsResponse{
		ID:   id,
		Name: "/" + id,
		CPUStats: container.CPUStats{
			CPUUsage:    container.CPUUsage{TotalUsage: 100},
			SystemUsage: 1000,
			OnlineCPUs:  1,
		},
		PreCPUStats: container.CPUStats{
			CPUUsage:    container.CPUUsage{TotalUsage: 50},
			SystemUsage: 500,
		},
		MemoryStats: container.MemoryStats{Usage: 1024},
		Networks: map[string]container.NetworkStats{
			"eth0": {RxBytes: 1, TxBytes: 1},
		},
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[n:])
}

// ensure import compatibility for sync (used implicitly via atomic; some IDEs
// will mark unused otherwise) — keep a no-op guard.
var _ = sync.Mutex{}

// metricsByName indexa os valores de um container pelo nome da métrica.
func metricsByName(metrics []*collectorv1.Metric, ctr string) map[string]float64 {
	got := map[string]float64{}
	for _, m := range metrics {
		if m.Tags["container_name"] == ctr {
			got[m.MetricName] = m.Value
		}
	}
	return got
}

// TestDockerHost_RunEmitsExtendedMetrics — throttling, limite/RSS/cache (cgroup v1), pacotes/erros/
// descartes de rede, blkio, PIDs e os dados do Inspect (restart real, OOM, health, uptime).
func TestDockerHost_RunEmitsExtendedMetrics(t *testing.T) {
	stats := minimalStats("abc")
	stats.CPUStats.ThrottlingData = container.ThrottlingData{ThrottledPeriods: 7, ThrottledTime: 2_500_000_000}
	stats.MemoryStats = container.MemoryStats{
		Usage: 300, Limit: 1000,
		Stats: map[string]uint64{"cache": 40, "rss": 90},
	}
	stats.Networks = map[string]container.NetworkStats{
		"eth0": {RxPackets: 10, TxPackets: 20, RxErrors: 1, TxErrors: 2, RxDropped: 3, TxDropped: 4},
		"eth1": {RxPackets: 5, TxPackets: 5, RxErrors: 1, TxErrors: 1, RxDropped: 1, TxDropped: 1},
	}
	stats.BlkioStats = container.BlkioStats{
		IoServiceBytesRecursive: []container.BlkioStatEntry{
			{Op: "Read", Value: 100}, {Op: "Write", Value: 50}, {Op: "Read", Value: 11}, {Op: "Total", Value: 999}, {Op: "Sync", Value: 5},
		},
		IoServicedRecursive: []container.BlkioStatEntry{{Op: "read", Value: 4}, {Op: "write", Value: 6}},
	}
	stats.PidsStats = container.PidsStats{Current: 12}
	cli := &fakeDockerClient{
		listResult: []container.Summary{{ID: "abc", Names: []string{"/web"}, State: container.StateRunning}},
		statsByID:  map[string]container.StatsResponse{"abc": stats},
		inspectByID: map[string]container.InspectResponse{"abc": {ContainerJSONBase: &container.ContainerJSONBase{
			RestartCount: 3,
			State: &container.State{
				OOMKilled: true,
				StartedAt: time.Now().Add(-90 * time.Second).UTC().Format(time.RFC3339Nano),
				Health:    &container.Health{Status: container.Unhealthy},
			},
		}}},
	}
	dh := newDockerHostWithClient("h", nil, cli)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	metrics, err := dh.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := metricsByName(metrics, "web")
	want := map[string]float64{
		"docker.container.cpu_throttled_periods": 7,
		"docker.container.cpu_throttled_seconds": 2.5,
		"docker.container.mem_limit_bytes":       1000,
		"docker.container.mem_rss_bytes":         90,
		"docker.container.mem_cache_bytes":       40,
		"docker.container.network_rx_packets":    15,
		"docker.container.network_tx_packets":    25,
		"docker.container.network_rx_errors":     2,
		"docker.container.network_tx_errors":     3,
		"docker.container.network_rx_dropped":    4,
		"docker.container.network_tx_dropped":    5,
		"docker.container.blkio_read_bytes":      111,
		"docker.container.blkio_write_bytes":     50,
		"docker.container.blkio_read_ops":        4,
		"docker.container.blkio_write_ops":       6,
		"docker.container.pids":                  12,
		"docker.container.restart_count":         3,
		"docker.container.oom_killed":            1,
		"docker.container.health_status":         0,
	}
	for name, v := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("missing metric %q", name)
			continue
		}
		if g != v {
			t.Errorf("%s=%v want %v", name, g, v)
		}
	}
	if up := got["docker.container.uptime_seconds"]; up < 89 || up > 120 {
		t.Errorf("uptime_seconds=%v want ~90", up)
	}
}

// TestDockerHost_MemoryStatsCgroupV2 — cgroup v2 usa anon/file em vez de rss/cache.
func TestDockerHost_MemoryStatsCgroupV2(t *testing.T) {
	stats := minimalStats("v2")
	stats.MemoryStats = container.MemoryStats{Usage: 500, Stats: map[string]uint64{"anon": 120, "file": 60}}
	cli := &fakeDockerClient{
		listResult: []container.Summary{{ID: "v2", Names: []string{"/v2"}, State: container.StateRunning}},
		statsByID:  map[string]container.StatsResponse{"v2": stats},
	}
	metrics, err := newDockerHostWithClient("h", nil, cli).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := metricsByName(metrics, "v2")
	if got["docker.container.mem_rss_bytes"] != 120 || got["docker.container.mem_cache_bytes"] != 60 {
		t.Errorf("rss/cache=%v/%v want 120/60", got["docker.container.mem_rss_bytes"], got["docker.container.mem_cache_bytes"])
	}
	if _, ok := got["docker.container.mem_limit_bytes"]; ok {
		t.Errorf("mem_limit_bytes não deveria sair quando Limit=0")
	}
	if _, ok := got["docker.container.health_status"]; ok {
		t.Errorf("health_status não deveria sair sem healthcheck")
	}
}

// TestDockerHost_InspectErrorSkipsInspectMetrics — sem Inspect não há restart_count (antes saía um 0 falso),
// mas as métricas de stats continuam.
func TestDockerHost_InspectErrorSkipsInspectMetrics(t *testing.T) {
	cli := &fakeDockerClient{
		listResult: []container.Summary{{ID: "x", Names: []string{"/x"}, State: container.StateRunning}},
		statsByID:  map[string]container.StatsResponse{"x": minimalStats("x")},
		inspectErr: errors.New("inspect: boom"),
	}
	metrics, err := newDockerHostWithClient("h", nil, cli).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := metricsByName(metrics, "x")
	for _, name := range []string{"docker.container.restart_count", "docker.container.oom_killed", "docker.container.uptime_seconds"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s não deveria sair quando o Inspect falha", name)
		}
	}
	if _, ok := got["docker.container.cpu_percent"]; !ok {
		t.Errorf("cpu_percent deveria sair mesmo sem Inspect")
	}
}

// TestDockerHost_InfoMetricCarriesIdentity — docker.container.info (valor 1) leva imagem, comando, portas,
// montagens e criação como tags estáveis.
func TestDockerHost_InfoMetricCarriesIdentity(t *testing.T) {
	cli := &fakeDockerClient{
		listResult: []container.Summary{{
			ID: "0123456789abcdef0123", Names: []string{"/api"}, State: container.StateRunning,
			Image: "ghcr.io/acme/api:1.2", Command: "java -jar app.jar", Created: 1700000000,
			Ports: []container.Port{
				{PrivatePort: 8080, PublicPort: 18080, Type: "tcp"},
				{PrivatePort: 8080, PublicPort: 18080, Type: "tcp"}, // duplicada (ipv4/ipv6)
				{PrivatePort: 5432, Type: "tcp"},
			},
			Mounts: []container.MountPoint{
				{Type: "volume", Name: "data", Destination: "/var/lib/data"},
				{Type: "bind", Source: "/srv/conf", Destination: "/etc/app"},
			},
		}},
		statsByID: map[string]container.StatsResponse{"0123456789abcdef0123": minimalStats("x")},
	}
	metrics, err := newDockerHostWithClient("h", nil, cli).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var info *collectorv1.Metric
	for _, m := range metrics {
		if m.MetricName == "docker.container.info" {
			info = m
		}
	}
	if info == nil || info.Value != 1 {
		t.Fatalf("docker.container.info ausente ou valor != 1: %+v", info)
	}
	want := map[string]string{
		"container_name": "api", "container_id": "0123456789ab", "image": "ghcr.io/acme/api:1.2",
		"command": "java -jar app.jar", "created": "1700000000",
		"mounts": "/srv/conf:/etc/app,data:/var/lib/data",
	}
	for k, v := range want {
		if info.Tags[k] != v {
			t.Errorf("tag %s=%q want %q", k, info.Tags[k], v)
		}
	}
	if got := info.Tags["ports"]; got != "18080→8080/tcp,5432/tcp" {
		t.Errorf("ports=%q want %q", got, "18080→8080/tcp,5432/tcp")
	}
}

// TestDockerHost_BlkioOpsOnlyWhenReported — cgroup v2: a API não informa operações; não emitir 0 fixo.
func TestDockerHost_BlkioOpsOnlyWhenReported(t *testing.T) {
	stats := minimalStats("o")
	stats.BlkioStats = container.BlkioStats{IoServiceBytesRecursive: []container.BlkioStatEntry{{Op: "read", Value: 9}}}
	cli := &fakeDockerClient{
		listResult: []container.Summary{{ID: "o", Names: []string{"/o"}, State: container.StateRunning}},
		statsByID:  map[string]container.StatsResponse{"o": stats},
	}
	metrics, _ := newDockerHostWithClient("h", nil, cli).Run(context.Background())
	got := metricsByName(metrics, "o")
	if got["docker.container.blkio_read_bytes"] != 9 {
		t.Errorf("blkio_read_bytes=%v want 9", got["docker.container.blkio_read_bytes"])
	}
	for _, n := range []string{"docker.container.blkio_read_ops", "docker.container.blkio_write_ops"} {
		if _, ok := got[n]; ok {
			t.Errorf("%s não deveria sair sem io_serviced_recursive", n)
		}
	}
}
