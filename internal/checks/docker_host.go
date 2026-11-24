// docker_host.go — Check "docker.host" (Phase 4 Plan 07).
//
// Coleta inventário e telemetria de containers Docker em um host via
// socket Unix `/var/run/docker.sock`. Para cada Run emite:
//
// Métricas top-level (sem container tag):
//   - docker.containers_running
//   - docker.containers_stopped
//
// Métricas por container running (tag container_name=<n>):
//   - docker.container.cpu_percent       (cgroup-style: cpuDelta/sysDelta * cpus * 100)
//   - docker.container.mem_used_bytes    (usage − stats.cache)
//   - docker.container.restart_count     (do Summary.HostConfig — Docker API)
//   - docker.container.network_rx_bytes  (soma de stats.Networks[*].RxBytes)
//   - docker.container.network_tx_bytes  (soma de stats.Networks[*].TxBytes)
//
// Métricas adicionais por container running (mesma tag container_name):
//   - docker.container.cpu_throttled_periods / cpu_throttled_seconds (CFS throttling, contadores)
//   - docker.container.mem_limit_bytes, mem_rss_bytes, mem_cache_bytes (cgroup v1 rss/cache; v2 anon/file)
//   - docker.container.network_{rx,tx}_{packets,errors,dropped}       (soma das interfaces, contadores)
//   - docker.container.blkio_{read,write}_{bytes,ops}                 (soma dos dispositivos, contadores)
//   - docker.container.pids                                           (PidsStats.Current)
//   - docker.container.info (valor 1) com tags de identidade: container_id, image, command,
//     ports, mounts e created (epoch). Tags estáveis: só mudam se o container for recriado.
//     blkio_*_ops só sai quando a API informa operações (cgroup v1); no cgroup v2 o Docker
//     devolve io_serviced_recursive vazio e um 0 fixo enganaria.
//   - Via ContainerInspect (best-effort, 1 chamada por container/tick):
//     restart_count (real), oom_killed (0/1), uptime_seconds, health_status (1 healthy / 0 unhealthy,
//     só quando o container tem healthcheck). Se o Inspect falhar essas métricas simplesmente não saem.
//
// Decisões locked:
//   - Cliente Docker via interface seam `dockerClient` — em prod usa
//     client.NewClientWithOpts + WithAPIVersionNegotiation; em testes
//     usa fake do _test.go. Sem dependência de daemon real em CI.
//   - Factory tenta `Ping(ctx)` cedo com timeout 3s; falha permission
//     denied → erro com hint `TELVYN_DOCKER_INTEGRATION=true`
//     (Pitfall 2). Sem isso o scheduler tentaria pra sempre e poluiria
//     logs com erros idênticos.
//   - Stats em paralelo limitado por `semaphore.NewWeighted(5)`
//     (Pitfall 8) — 100 containers × stats lentos não devem afogar o
//     daemon nem estourar timeout do Run.
//   - Best-effort: erro de stats num container é silenciosamente pulado;
//     outros containers ainda emitem métricas. Top-level counts são
//     calculados antes do fan-out e portanto independentes.
//
// Source = "docker.host" em todas as métricas.
//
// Threat note (T-04-07-02): membership no grupo `docker` é root-equivalente
// no host. install.sh trata isso como opt-in via env var, com warning
// explícito (ver packaging/install.sh).

package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/telvynmonitoring/telvyn-agent/proto/v1"
)

const (
	defaultDockerInterval    = 60 * time.Second
	defaultDockerPingTimeout = 3 * time.Second
	defaultDockerStatsCap    = 5 // Pitfall 8 — parallelism cap
)

// dockerClient é o subset da API Docker que o check usa. Permite mock
// no test sem precisar de socket real (Pitfall 2 evita CI integration).
type dockerClient interface {
	Ping(ctx context.Context) (dockertypes.Ping, error)
	ContainerList(ctx context.Context, opts container.ListOptions) ([]container.Summary, error)
	ContainerStatsOneShot(ctx context.Context, containerID string) (container.StatsResponseReader, error)
	ContainerInspect(ctx context.Context, containerID string) (container.InspectResponse, error)
	Close() error
}

// dockerClientFactory permite o test injetar um fake cliente sem tocar em
// /var/run/docker.sock; em prod aponta para client.NewClientWithOpts.
type dockerClientFactory func() (dockerClient, error)

var defaultDockerClientFactory dockerClientFactory = func() (dockerClient, error) {
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix:///var/run/docker.sock"),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, err
	}
	return cli, nil
}

// dockerHost é a implementação concreta de Check para "docker.host".
type dockerHost struct {
	id         string
	hostID     string
	interval   time.Duration
	staticTags map[string]string
	cli        dockerClient
	statsCap   int64 // semaphore weight — default 5
}

// newDockerHostCheck é a Factory registrada em init() para "docker.host".
// Faz Ping cedo (com timeout 3s) — falha permission denied vira erro
// descritivo com hint do install.sh (Pitfall 2).
func newDockerHostCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	cli, err := defaultDockerClientFactory()
	if err != nil {
		return nil, fmt.Errorf("docker.host: client init: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(context.Background(), defaultDockerPingTimeout)
	defer cancel()
	if _, err := cli.Ping(pingCtx); err != nil {
		_ = cli.Close()
		// Mensagem inclui hint pro operador habilitar via install.sh.
		return nil, fmt.Errorf("docker.host: ping failed (%w); run install.sh with TELVYN_DOCKER_INTEGRATION=true to add telvyn user to docker group", err)
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = defaultDockerInterval
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "docker.host-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &dockerHost{
		id:         id,
		hostID:     cfg.GetHostId(),
		interval:   interval,
		staticTags: tags,
		cli:        cli,
		statsCap:   defaultDockerStatsCap,
	}, nil
}

func (d *dockerHost) ID() string              { return d.id }
func (d *dockerHost) Interval() time.Duration { return d.interval }
func (d *dockerHost) Tags() map[string]string { return d.staticTags }

// Run executa um ciclo:
//  1. ContainerList(All=true) → conta running/stopped
//  2. Para cada running, ContainerStatsOneShot em paralelo (semaphore=5)
//  3. Emite 2 métricas top-level + as métricas por container running (ver cabeçalho)
//
// Erros pontuais de stats são pulados (best-effort); a Run só falha se
// ContainerList falhar (sinal de daemon morto/permissão revogada).
func (d *dockerHost) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	if d.cli == nil {
		return nil, errors.New("docker.host: client closed")
	}

	containers, err := d.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("docker.host: ContainerList: %w", err)
	}

	now := timestamppb.Now()
	var running, stopped int
	for _, c := range containers {
		if c.State == container.StateRunning {
			running++
		} else {
			stopped++
		}
	}

	out := make([]*collectorv1.Metric, 0, 2+running*26)
	out = append(out,
		d.metric(now, "docker.containers_running", float64(running), nil),
		d.metric(now, "docker.containers_stopped", float64(stopped), nil),
	)

	// Coleta stats em paralelo com semaphore=5 (Pitfall 8).
	cap := d.statsCap
	if cap <= 0 {
		cap = defaultDockerStatsCap
	}
	sem := semaphore.NewWeighted(cap)

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		perCtr []*collectorv1.Metric
	)
	for _, c := range containers {
		if c.State != container.StateRunning {
			continue
		}
		wg.Add(1)
		go func(c container.Summary) {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				return // ctx canceled — abandonar este container
			}
			defer sem.Release(1)

			metrics := d.collectContainerStats(ctx, now, c)
			if len(metrics) > 0 {
				mu.Lock()
				perCtr = append(perCtr, metrics...)
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()

	out = append(out, perCtr...)
	return out, nil
}

// collectContainerStats faz um ContainerStatsOneShot, decodifica JSON e
// produz as métricas por container. Retorna nil em qualquer erro (best-
// effort por Pitfall 8) — caller só agrega o que existir.
func (d *dockerHost) collectContainerStats(ctx context.Context, now *timestamppb.Timestamp, c container.Summary) []*collectorv1.Metric {
	rdr, err := d.cli.ContainerStatsOneShot(ctx, c.ID)
	if err != nil {
		return nil
	}
	if rdr.Body == nil {
		return nil
	}
	defer rdr.Body.Close()

	body, err := io.ReadAll(rdr.Body)
	if err != nil {
		return nil
	}

	var s container.StatsResponse
	if err := json.Unmarshal(body, &s); err != nil {
		return nil
	}

	name := containerDisplayName(c.Names, c.ID)
	tags := map[string]string{"container_name": name}

	// CPU%: cgroup formula. cpuDelta e systemDelta são uint64 — comparar
	// ordem antes de subtrair para evitar overflow em wrap (raro mas possível
	// após uptime longo).
	var cpuPct float64
	if s.CPUStats.CPUUsage.TotalUsage > s.PreCPUStats.CPUUsage.TotalUsage &&
		s.CPUStats.SystemUsage > s.PreCPUStats.SystemUsage {
		cpuDelta := s.CPUStats.CPUUsage.TotalUsage - s.PreCPUStats.CPUUsage.TotalUsage
		sysDelta := s.CPUStats.SystemUsage - s.PreCPUStats.SystemUsage
		cpus := s.CPUStats.OnlineCPUs
		if cpus == 0 {
			cpus = 1 // fallback — kernel sem online_cpus exporta 0
		}
		cpuPct = float64(cpuDelta) / float64(sysDelta) * float64(cpus) * 100.0
	}

	// Mem usage: subtrai cache para refletir RSS-ish. Em alguns kernels o
	// campo é "total_cache"; usar "cache" mantém alinhamento com docker stats CLI.
	memUsed := float64(s.MemoryStats.Usage)
	if cache, ok := s.MemoryStats.Stats["cache"]; ok && cache <= s.MemoryStats.Usage {
		memUsed = float64(s.MemoryStats.Usage - cache)
	}

	// Rede: somar rx/tx de todas as interfaces (eth0, eth1, etc.).
	var rxBytes, txBytes uint64
	for _, n := range s.Networks {
		rxBytes += n.RxBytes
		txBytes += n.TxBytes
	}

	out := []*collectorv1.Metric{
		d.metric(now, "docker.container.cpu_percent", cpuPct, tags),
		d.metric(now, "docker.container.mem_used_bytes", memUsed, tags),
		d.metric(now, "docker.container.network_rx_bytes", float64(rxBytes), tags),
		d.metric(now, "docker.container.network_tx_bytes", float64(txBytes), tags),
	}
	add := func(name string, v float64) { out = append(out, d.metric(now, name, v, tags)) }

	// CPU throttling (contadores; zero quando o container não tem quota CFS).
	add("docker.container.cpu_throttled_periods", float64(s.CPUStats.ThrottlingData.ThrottledPeriods))
	add("docker.container.cpu_throttled_seconds", float64(s.CPUStats.ThrottlingData.ThrottledTime)/1e9)

	// Memória: limite (0 = sem dado) e RSS/cache. cgroup v1 expõe rss/cache; v2 anon/file.
	if s.MemoryStats.Limit > 0 {
		add("docker.container.mem_limit_bytes", float64(s.MemoryStats.Limit))
	}
	if v, ok := firstStat(s.MemoryStats.Stats, "rss", "anon"); ok {
		add("docker.container.mem_rss_bytes", float64(v))
	}
	if v, ok := firstStat(s.MemoryStats.Stats, "cache", "file"); ok {
		add("docker.container.mem_cache_bytes", float64(v))
	}

	// Rede: pacotes, erros e descartes (soma das interfaces).
	var rxPk, txPk, rxErr, txErr, rxDrop, txDrop uint64
	for _, n := range s.Networks {
		rxPk += n.RxPackets
		txPk += n.TxPackets
		rxErr += n.RxErrors
		txErr += n.TxErrors
		rxDrop += n.RxDropped
		txDrop += n.TxDropped
	}
	add("docker.container.network_rx_packets", float64(rxPk))
	add("docker.container.network_tx_packets", float64(txPk))
	add("docker.container.network_rx_errors", float64(rxErr))
	add("docker.container.network_tx_errors", float64(txErr))
	add("docker.container.network_rx_dropped", float64(rxDrop))
	add("docker.container.network_tx_dropped", float64(txDrop))

	// Disco (blkio): bytes e operações de leitura/escrita, somando os dispositivos.
	rdB, wrB := blkioSum(s.BlkioStats.IoServiceBytesRecursive)
	add("docker.container.blkio_read_bytes", rdB)
	add("docker.container.blkio_write_bytes", wrB)
	if len(s.BlkioStats.IoServicedRecursive) > 0 {
		rdOp, wrOp := blkioSum(s.BlkioStats.IoServicedRecursive)
		add("docker.container.blkio_read_ops", rdOp)
		add("docker.container.blkio_write_ops", wrOp)
	}

	add("docker.container.pids", float64(s.PidsStats.Current))

	// Estado (Inspect, best-effort). Restart count só sai com dado real: antes era
	// um 0 fixo, o que escondia reinícios de verdade.
	if insp, err := d.cli.ContainerInspect(ctx, c.ID); err == nil && insp.ContainerJSONBase != nil {
		add("docker.container.restart_count", float64(insp.RestartCount))
		if st := insp.State; st != nil {
			oom := 0.0
			if st.OOMKilled {
				oom = 1
			}
			add("docker.container.oom_killed", oom)
			if started, err := time.Parse(time.RFC3339Nano, st.StartedAt); err == nil && !started.IsZero() && started.Year() > 1 {
				add("docker.container.uptime_seconds", time.Since(started).Seconds())
			}
			if st.Health != nil {
				switch st.Health.Status {
				case container.Healthy:
					add("docker.container.health_status", 1)
				case container.Unhealthy:
					add("docker.container.health_status", 0)
				}
			}
		}
	}

	// Identidade (estável): permite ao portal mostrar imagem, comando, portas e volumes.
	out = append(out, d.metric(now, "docker.container.info", 1, map[string]string{
		"container_name": name,
		"container_id":   shortID(c.ID),
		"image":          truncateTag(c.Image, 200),
		"command":        truncateTag(c.Command, 200),
		"ports":          truncateTag(formatPorts(c.Ports), 300),
		"mounts":         truncateTag(formatMounts(c.Mounts), 400),
		"created":        fmt.Sprintf("%d", c.Created),
	}))
	return out
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// truncateTag limita o tamanho de um valor de tag (label no VictoriaMetrics), sem cortar no meio de um rune.
func truncateTag(v string, max int) string {
	v = strings.TrimSpace(v)
	if len(v) <= max {
		return v
	}
	r := []rune(v)
	for len(string(r)) > max-1 {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// formatPorts: "6379→6379/tcp,127.0.0.1:9000→9000/tcp,5432/tcp". Publicações em 0.0.0.0 e :: (o Docker lista as duas)
// viram uma só, sem o IP; portas não publicadas aparecem só como porta/protocolo. Ordenado e sem repetição.
func formatPorts(ports []container.Port) string {
	seen := map[string]bool{}
	var list []string
	for _, p := range ports {
		var item string
		if p.PublicPort > 0 {
			ip := fmt.Sprint(p.IP)
			switch ip {
			case "", "0.0.0.0", "::", "invalid IP", "<invalid netip.Addr>":
				ip = ""
			default:
				if strings.Contains(ip, ":") {
					ip = "[" + ip + "]"
				}
				ip += ":"
			}
			item = fmt.Sprintf("%s%d→%d/%s", ip, p.PublicPort, p.PrivatePort, p.Type)
		} else {
			item = fmt.Sprintf("%d/%s", p.PrivatePort, p.Type)
		}
		if !seen[item] {
			seen[item] = true
			list = append(list, item)
		}
	}
	sort.Strings(list)
	return strings.Join(list, ",")
}

// formatMounts: "nome-ou-origem:destino" por montagem (o tipo bind/volume fica implícito pelo caminho).
func formatMounts(mounts []container.MountPoint) string {
	var list []string
	for _, m := range mounts {
		src := m.Name
		if src == "" {
			src = m.Source
		}
		list = append(list, src+":"+m.Destination)
	}
	sort.Strings(list)
	return strings.Join(list, ",")
}

// firstStat devolve o primeiro dos nomes que existir no mapa de stats de memória
// (cgroup v1 e v2 usam chaves diferentes para a mesma grandeza).
func firstStat(stats map[string]uint64, keys ...string) (uint64, bool) {
	for _, k := range keys {
		if v, ok := stats[k]; ok {
			return v, true
		}
	}
	return 0, false
}

// blkioSum soma leitura e escrita de todos os dispositivos. A API devolve "read"/"write"
// em cgroup v2 e "Read"/"Write" em v1; outras operações (sync, total…) são ignoradas.
func blkioSum(entries []container.BlkioStatEntry) (read, write float64) {
	for _, e := range entries {
		switch strings.ToLower(e.Op) {
		case "read":
			read += float64(e.Value)
		case "write":
			write += float64(e.Value)
		}
	}
	return read, write
}

// metric merge static_tags + extra (extra ganha em conflito).
func (d *dockerHost) metric(t *timestamppb.Timestamp, name string, val float64, extraTags map[string]string) *collectorv1.Metric {
	tags := make(map[string]string, len(d.staticTags)+len(extraTags))
	for k, v := range d.staticTags {
		tags[k] = v
	}
	for k, v := range extraTags {
		tags[k] = v
	}
	return &collectorv1.Metric{
		Time:       t,
		HostId:     d.hostID,
		MetricName: name,
		Value:      val,
		Tags:       tags,
		Source:     "docker.host",
	}
}

// containerDisplayName escolhe um nome humano: primeiro Name sem leading
// slash; fallback para 12-char ID. Docker API retorna nomes como "/web".
func containerDisplayName(names []string, id string) string {
	if len(names) > 0 {
		return strings.TrimPrefix(names[0], "/")
	}
	if len(id) >= 12 {
		return id[:12]
	}
	return id
}

// init auto-registra o factory em Default.
func init() {
	Default.Register("docker.host", newDockerHostCheck)
}
