// k8s_kubelet.go — Check "k8s.kubelet" (Phase k8s v1).
//
// Lê /stats/summary do kubelet local (mesma máquina onde o DaemonSet roda)
// e emite métricas de node + pods + containers pra VictoriaMetrics.
//
// Ciclo (1 Run) emite:
//
// Node-level (tag node=<nodeName>):
//   - k8s.node.cpu_usage_nanocores
//   - k8s.node.memory_working_set_bytes
//   - k8s.node.fs_used_bytes / k8s.node.fs_capacity_bytes
//   - k8s.node.network_rx_bytes / k8s.node.network_tx_bytes
//
// Pod-level (tags namespace, pod, node):
//   - k8s.pod.cpu_usage_nanocores
//   - k8s.pod.memory_working_set_bytes
//   - k8s.pod.network_rx_bytes / k8s.pod.network_tx_bytes
//
// Container-level (tags namespace, pod, container, node):
//   - k8s.container.cpu_usage_nanocores
//   - k8s.container.memory_working_set_bytes
//   - k8s.container.rootfs_used_bytes / k8s.container.rootfs_capacity_bytes
//   - k8s.container.logs_used_bytes
//
// Storage por pod (tags namespace, pod, node):
//   - k8s.pod.ephemeral_storage_used_bytes
//   - k8s.pod.ephemeral_storage_capacity_bytes
//
// Storage por volume (tags namespace, pod, volume, [pvc], node):
//   - k8s.volume.used_bytes / k8s.volume.capacity_bytes
//   - k8s.volume.inodes_used
//
// Decisões locked:
//   - Auth: Bearer token do SA mount padrão (/var/run/secrets/.../token).
//     Pode ser override via Params["token_file"].
//   - TLS: usa ca.crt do SA mount; se ausente, cai pra InsecureSkipVerify
//     (kubelet usa cert self-signed; SkipVerify é aceitável quando o
//     agent roda na mesma máquina).
//   - Endpoint: Params["kubelet_url"] (default https://localhost:10250).
//     DaemonSet com hostNetwork=true permite usar localhost; sem
//     hostNetwork seria ${HOST_IP}:10250 vindo de downward API.
//   - Best-effort: pod com payload corrompido é skipado silenciosamente;
//     restante ainda emite. Falha de HTTP/parse propaga como erro do Run
//     pra acionar circuit-breaker do scheduler.

package checks

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ispwatch/collector/internal/quarkus"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	defaultKubeletInterval = 15 * time.Second
	defaultKubeletURL      = "https://localhost:10250"
	defaultTokenFile       = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAFile          = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	kubeletReadTimeout     = 8 * time.Second
)

// kubeletSummary espelha o subset de /stats/summary que consumimos.
// Campos não mapeados são ignorados pelo json decoder.
type kubeletSummary struct {
	Node struct {
		NodeName string `json:"nodeName"`
		CPU      struct {
			UsageNanoCores *uint64 `json:"usageNanoCores"`
		} `json:"cpu"`
		Memory struct {
			WorkingSetBytes *uint64 `json:"workingSetBytes"`
		} `json:"memory"`
		Network struct {
			RxBytes *uint64 `json:"rxBytes"`
			TxBytes *uint64 `json:"txBytes"`
		} `json:"network"`
		Fs struct {
			UsedBytes     *uint64 `json:"usedBytes"`
			CapacityBytes *uint64 `json:"capacityBytes"`
		} `json:"fs"`
		Runtime *struct {
			ImageFs *kubeletFsStats `json:"imageFs"`
		} `json:"runtime,omitempty"`
		SystemContainers []struct {
			Name string `json:"name"`
			CPU  struct {
				UsageNanoCores *uint64 `json:"usageNanoCores"`
			} `json:"cpu"`
			Memory struct {
				RSSBytes   *uint64 `json:"rssBytes"`
				UsageBytes *uint64 `json:"usageBytes"`
			} `json:"memory"`
		} `json:"systemContainers"`
	} `json:"node"`
	Pods []kubeletPodSummary `json:"pods"`
}

type kubeletFsStats struct {
	UsedBytes      *uint64 `json:"usedBytes"`
	CapacityBytes  *uint64 `json:"capacityBytes"`
	InodesUsed     *uint64 `json:"inodesUsed"`
	AvailableBytes *uint64 `json:"availableBytes"`
	Inodes         *uint64 `json:"inodes"`
	InodesFree     *uint64 `json:"inodesFree"`
}

type kubeletVolumeStats struct {
	Name           string  `json:"name"`
	UsedBytes      *uint64 `json:"usedBytes"`
	CapacityBytes  *uint64 `json:"capacityBytes"`
	InodesUsed     *uint64 `json:"inodesUsed"`
	AvailableBytes *uint64 `json:"availableBytes"`
	Inodes         *uint64 `json:"inodes"`
	InodesFree     *uint64 `json:"inodesFree"`
	PVCRef         *struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"pvcRef,omitempty"`
}

type kubeletPodSummary struct {
	PodRef struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"podRef"`
	CPU struct {
		UsageNanoCores *uint64 `json:"usageNanoCores"`
	} `json:"cpu"`
	Memory struct {
		WorkingSetBytes *uint64 `json:"workingSetBytes"`
	} `json:"memory"`
	// Rede do pod (sandbox netns). No summary do kubelet vem populado no
	// TOPO (rxBytes/txBytes), diferente do node — que só traz por interface.
	Network *struct {
		Name    string  `json:"name"`
		RxBytes *uint64 `json:"rxBytes"`
		TxBytes *uint64 `json:"txBytes"`
	} `json:"network,omitempty"`
	Containers []struct {
		Name      string `json:"name"`
		StartTime string `json:"startTime"`
		CPU       struct {
			UsageNanoCores       *uint64 `json:"usageNanoCores"`
			UsageCoreNanoSeconds *uint64 `json:"usageCoreNanoSeconds"`
		} `json:"cpu"`
		Memory struct {
			WorkingSetBytes *uint64 `json:"workingSetBytes"`
			RSSBytes        *uint64 `json:"rssBytes"`
		} `json:"memory"`
		Rootfs *kubeletFsStats `json:"rootfs,omitempty"`
		Logs   *kubeletFsStats `json:"logs,omitempty"`
	} `json:"containers"`
	Volume           []kubeletVolumeStats `json:"volume,omitempty"`
	EphemeralStorage *kubeletFsStats      `json:"ephemeral-storage,omitempty"`
}

// kubeletFetcher é a interface seam — testes injetam fake; em prod
// usa httpKubeletFetcher real.
type kubeletFetcher interface {
	Summary(ctx context.Context) (*kubeletSummary, error)
}

type httpKubeletFetcher struct {
	url    string
	token  string
	client *http.Client
}

func newHTTPKubeletFetcher(url, tokenFile, caFile string, insecure bool) (*httpKubeletFetcher, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: insecure}
	if caFile != "" && !insecure {
		ca, err := os.ReadFile(caFile)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(ca) {
				tlsCfg = &tls.Config{RootCAs: pool}
			}
		}
		// se falhar lê CA, cai pra InsecureSkipVerify silenciosamente —
		// kubelet local quase sempre tem cert self-signed.
		if tlsCfg.RootCAs == nil {
			tlsCfg = &tls.Config{InsecureSkipVerify: true}
		}
	}

	var token string
	if tokenFile != "" {
		if b, err := os.ReadFile(tokenFile); err == nil {
			token = strings.TrimSpace(string(b))
		}
	}

	return &httpKubeletFetcher{
		url:   strings.TrimRight(url, "/") + "/stats/summary",
		token: token,
		client: &http.Client{
			Timeout: kubeletReadTimeout,
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				MaxIdleConnsPerHost: 2,
			},
		},
	}, nil
}

func (h *httpKubeletFetcher) Summary(ctx context.Context) (*kubeletSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return nil, fmt.Errorf("kubelet new req: %w", err)
	}
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kubelet GET %s: %w", h.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("kubelet GET %s: status %d body=%q",
			h.url, resp.StatusCode, body)
	}

	var sum kubeletSummary
	if err := json.NewDecoder(resp.Body).Decode(&sum); err != nil {
		return nil, fmt.Errorf("kubelet decode: %w", err)
	}
	return &sum, nil
}

type k8sKubeletCheck struct {
	containerCPU map[string]kubeletCPUSample
	cgroupRoot   string
	id           string
	hostID       string
	interval     time.Duration
	staticTags   map[string]string
	fetcher      kubeletFetcher
}

type kubeletCPUSample struct {
	value uint64
	time  time.Time
}

func kubeletContainerCPURate(previous, current kubeletCPUSample) (float64, bool) {
	elapsed := current.time.Sub(previous.time).Seconds()
	if previous.time.IsZero() || elapsed <= 0 || current.value < previous.value {
		return 0, false
	}
	return float64(current.value-previous.value) / elapsed, true
}

func newK8sKubeletCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()

	url := strings.TrimSpace(params["kubelet_url"])
	if url == "" {
		url = defaultKubeletURL
	}
	tokenFile := strings.TrimSpace(params["token_file"])
	if tokenFile == "" {
		tokenFile = defaultTokenFile
	}
	caFile := strings.TrimSpace(params["ca_file"])
	if caFile == "" {
		caFile = defaultCAFile
	}
	insecure := params["insecure_skip_verify"] == "true"

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = defaultKubeletInterval
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "k8s.kubelet-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	fetcher, err := newHTTPKubeletFetcher(url, tokenFile, caFile, insecure)
	if err != nil {
		return nil, fmt.Errorf("k8s.kubelet: %w", err)
	}

	return &k8sKubeletCheck{
		id:         id,
		hostID:     cfg.GetHostId(),
		interval:   interval,
		staticTags: tags,
		fetcher:    fetcher,
	}, nil
}

func (c *k8sKubeletCheck) ID() string              { return c.id }
func (c *k8sKubeletCheck) Interval() time.Duration { return c.interval }
func (c *k8sKubeletCheck) Tags() map[string]string { return c.staticTags }

func (c *k8sKubeletCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	sum, err := c.fetcher.Summary(ctx)
	if err != nil {
		return nil, err
	}

	now := timestamppb.Now()
	cpuObservedAt := time.Now()
	nextContainerCPU := make(map[string]kubeletCPUSample)
	out := make([]*collectorv1.Metric, 0, 64)

	nodeName := sum.Node.NodeName
	nodeTags := map[string]string{"node": nodeName}

	addNode := func(name string, p *uint64) {
		if p == nil {
			return
		}
		out = append(out, c.metric(now, name, float64(*p), nodeTags))
	}
	addNode("k8s.node.cpu_usage_nanocores", sum.Node.CPU.UsageNanoCores)
	addNode("k8s.node.memory_working_set_bytes", sum.Node.Memory.WorkingSetBytes)
	addNode("k8s.node.network_rx_bytes", sum.Node.Network.RxBytes)
	addNode("k8s.node.network_tx_bytes", sum.Node.Network.TxBytes)
	addNode("k8s.node.fs_used_bytes", sum.Node.Fs.UsedBytes)
	addNode("k8s.node.fs_capacity_bytes", sum.Node.Fs.CapacityBytes)
	addFsUsage := func(name string, used, capacity *uint64) {
		if used != nil && capacity != nil && *capacity > 0 {
			out = append(out, c.metric(now, name, float64(*used)/float64(*capacity), nodeTags))
		}
	}
	addFsUsage("k8s.node.fs_usage_fraction", sum.Node.Fs.UsedBytes, sum.Node.Fs.CapacityBytes)
	if sum.Node.Runtime != nil && sum.Node.Runtime.ImageFs != nil {
		addNode("k8s.node.image_fs_used_bytes", sum.Node.Runtime.ImageFs.UsedBytes)
		addNode("k8s.node.image_fs_capacity_bytes", sum.Node.Runtime.ImageFs.CapacityBytes)
		addFsUsage("k8s.node.image_fs_usage_fraction", sum.Node.Runtime.ImageFs.UsedBytes, sum.Node.Runtime.ImageFs.CapacityBytes)
	}
	for _, system := range sum.Node.SystemContainers {
		if system.Name != "kubelet" && system.Name != "runtime" {
			continue
		}
		addNode("k8s."+system.Name+".cpu_usage_nanocores", system.CPU.UsageNanoCores)
		addNode("k8s."+system.Name+".memory_rss_bytes", system.Memory.RSSBytes)
		addNode("k8s."+system.Name+".memory_usage_bytes", system.Memory.UsageBytes)
	}

	// pod count breakdown
	podCount := 0
	for _, p := range sum.Pods {
		if p.PodRef.Name == "" {
			continue
		}
		podCount++
		podTags := map[string]string{
			"node":      nodeName,
			"namespace": p.PodRef.Namespace,
			"pod":       p.PodRef.Name,
		}
		if p.CPU.UsageNanoCores != nil {
			out = append(out, c.metric(now, "k8s.pod.cpu_usage_nanocores",
				float64(*p.CPU.UsageNanoCores), podTags))
		}
		if p.Memory.WorkingSetBytes != nil {
			out = append(out, c.metric(now, "k8s.pod.memory_working_set_bytes",
				float64(*p.Memory.WorkingSetBytes), podTags))
		}
		// Tráfego de rede do pod (counters cumulativos rx/tx do netns) — o
		// backend aplica rate() pra virar bytes/s na lente de serviço.
		if p.Network != nil {
			networkTags := maps.Clone(podTags)
			if p.Network.Name != "" {
				networkTags["interface"] = p.Network.Name
			}
			if p.Network.RxBytes != nil {
				out = append(out, c.metric(now, "k8s.pod.network_rx_bytes",
					float64(*p.Network.RxBytes), networkTags))
			}
			if p.Network.TxBytes != nil {
				out = append(out, c.metric(now, "k8s.pod.network_tx_bytes",
					float64(*p.Network.TxBytes), networkTags))
			}
		}
		// Pod ephemeral storage (somatório de rootfs + logs + emptyDir local).
		if p.EphemeralStorage != nil {
			if p.EphemeralStorage.UsedBytes != nil {
				out = append(out, c.metric(now, "k8s.pod.ephemeral_storage_used_bytes",
					float64(*p.EphemeralStorage.UsedBytes), podTags))
			}
			if p.EphemeralStorage.CapacityBytes != nil {
				out = append(out, c.metric(now, "k8s.pod.ephemeral_storage_capacity_bytes",
					float64(*p.EphemeralStorage.CapacityBytes), podTags))
			}
		}
		// Volumes do pod — emptyDir, configMap, secret, PVC, etc.
		for _, vol := range p.Volume {
			if vol.Name == "" {
				continue
			}
			volTags := map[string]string{
				"node":      nodeName,
				"namespace": p.PodRef.Namespace,
				"pod":       p.PodRef.Name,
				"volume":    vol.Name,
			}
			if vol.PVCRef != nil && vol.PVCRef.Name != "" {
				volTags["pvc"] = vol.PVCRef.Name
			}
			if vol.UsedBytes != nil {
				out = append(out, c.metric(now, "k8s.volume.used_bytes",
					float64(*vol.UsedBytes), volTags))
			}
			if vol.CapacityBytes != nil {
				out = append(out, c.metric(now, "k8s.volume.capacity_bytes",
					float64(*vol.CapacityBytes), volTags))
			}
			if vol.InodesUsed != nil {
				out = append(out, c.metric(now, "k8s.volume.inodes_used",
					float64(*vol.InodesUsed), volTags))
			}
			for name, value := range map[string]*uint64{"available_bytes": vol.AvailableBytes, "inodes": vol.Inodes, "inodes_free": vol.InodesFree} {
				if value != nil {
					out = append(out, c.metric(now, "k8s.volume."+name, float64(*value), volTags))
				}
			}
		}
		for _, ct := range p.Containers {
			if ct.Name == "" {
				continue
			}
			ctTags := map[string]string{
				"node":      nodeName,
				"namespace": p.PodRef.Namespace,
				"pod":       p.PodRef.Name,
				"container": ct.Name,
			}
			if ct.CPU.UsageCoreNanoSeconds != nil {
				key := strings.Join([]string{nodeName, p.PodRef.Namespace, p.PodRef.Name, p.PodRef.UID, ct.Name, ct.StartTime}, "|")
				current := kubeletCPUSample{value: *ct.CPU.UsageCoreNanoSeconds, time: cpuObservedAt}
				if value, valid := kubeletContainerCPURate(c.containerCPU[key], current); valid {
					out = append(out, c.metric(now, "k8s.container.cpu_usage_nanocores", value, ctTags))
				}
				nextContainerCPU[key] = current
			} else if ct.CPU.UsageNanoCores != nil {
				out = append(out, c.metric(now, "k8s.container.cpu_usage_nanocores",
					float64(*ct.CPU.UsageNanoCores), ctTags))
			}
			if ct.Memory.WorkingSetBytes != nil {
				out = append(out, c.metric(now, "k8s.container.memory_working_set_bytes",
					float64(*ct.Memory.WorkingSetBytes), ctTags))
			}
			if ct.Memory.RSSBytes != nil {
				out = append(out, c.metric(now, "k8s.container.memory_rss_bytes", float64(*ct.Memory.RSSBytes), ctTags))
			}
			if ct.Rootfs != nil {
				if ct.Rootfs.UsedBytes != nil {
					out = append(out, c.metric(now, "k8s.container.rootfs_used_bytes",
						float64(*ct.Rootfs.UsedBytes), ctTags))
				}
				if ct.Rootfs.CapacityBytes != nil {
					out = append(out, c.metric(now, "k8s.container.rootfs_capacity_bytes",
						float64(*ct.Rootfs.CapacityBytes), ctTags))
				}
			}
			if ct.Logs != nil && ct.Logs.UsedBytes != nil {
				out = append(out, c.metric(now, "k8s.container.logs_used_bytes",
					float64(*ct.Logs.UsedBytes), ctTags))
			}
		}
	}
	c.containerCPU = nextContainerCPU
	out = append(out, c.metric(now, "k8s.node.pods_total", float64(podCount), nodeTags))
	if socket := strings.TrimSpace(os.Getenv("ISPWATCH_CRI_SOCKET")); socket != "" {
		images, err := c.runtimeImages(ctx, socket, nodeName)
		if err != nil {
			slog.Warn("inventário CRI indisponível", "error", err)
			out = append(out, c.metric(now, "k8s.node.runtime_inventory_up", 0, nodeTags))
		} else {
			out = append(out, images...)
			out = append(out, c.metric(now, "k8s.node.runtime_inventory_up", 1, nodeTags))
		}
	}
	if fetcher, ok := c.fetcher.(*httpKubeletFetcher); ok {
		additional, err := c.cadvisor(ctx, fetcher, nodeName)
		if err != nil {
			slog.Warn("kubelet cAdvisor indisponível; Summary preservado", "error", err)
			out = append(out, c.metric(now, "k8s.node.cadvisor_up", 0, nodeTags))
		} else {
			out = append(out, additional...)
			out = append(out, c.metric(now, "k8s.node.cadvisor_up", 1, nodeTags))
		}
		for path, coverage := range map[string]string{"/metrics": "kubelet_metrics_up", "/metrics/probes": "probes_up", "/metrics/slis": "slis_up"} {
			body, err := fetcher.prometheusBody(ctx, path)
			if err != nil {
				slog.Warn("kubelet endpoint indisponível", "endpoint", path, "error", err)
				out = append(out, c.metric(now, "k8s.node."+coverage, 0, nodeTags))
				continue
			}
			additional, err := c.parseOperational(strings.NewReader(string(body)), nodeName)
			if err != nil {
				out = append(out, c.metric(now, "k8s.node."+coverage, 0, nodeTags))
				continue
			}
			out = append(out, additional...)
			out = append(out, c.metric(now, "k8s.node."+coverage, 1, nodeTags))
		}
	}

	return out, nil
}

// cAdvisor supplies signals absent from Summary. Never emit Summary's CPU/WSS/RSS twice.
func (c *k8sKubeletCheck) cadvisor(ctx context.Context, fetcher *httpKubeletFetcher, node string) ([]*collectorv1.Metric, error) {
	body, err := fetcher.prometheusBody(ctx, "/metrics/cadvisor")
	if err != nil {
		return nil, err
	}
	return c.parseCadvisor(strings.NewReader(string(body)), node)
}

func (c *k8sKubeletCheck) parseCadvisor(body io.Reader, node string) ([]*collectorv1.Metric, error) {
	names := map[string]string{
		"container_cpu_cfs_periods_total":                  "cpu_cfs_periods_total",
		"container_cpu_cfs_throttled_periods_total":        "cpu_cfs_throttled_periods_total",
		"container_cpu_cfs_throttled_seconds_total":        "cpu_cfs_throttled_seconds_total",
		"container_cpu_user_seconds_total":                 "cpu_user_seconds_total",
		"container_cpu_system_seconds_total":               "cpu_system_seconds_total",
		"container_fs_reads_bytes_total":                   "fs_reads_bytes_total",
		"container_fs_writes_bytes_total":                  "fs_writes_bytes_total",
		"container_fs_reads_total":                         "fs_reads_total",
		"container_fs_writes_total":                        "fs_writes_total",
		"container_memory_usage_bytes":                     "memory_usage_bytes",
		"container_memory_cache":                           "memory_cache_bytes",
		"container_memory_swap":                            "memory_swap_bytes",
		"container_oom_events_total":                       "memory_oom_events_total",
		"container_file_descriptors":                       "open_file_descriptors",
		"container_threads":                                "threads",
		"container_threads_max":                            "threads_limit",
		"container_start_time_seconds":                     "start_time_seconds",
		"container_cpu_load_average_10s":                   "cpu_load_10s_avg",
		"container_spec_memory_limit_bytes":                "memory_runtime_limit_bytes",
		"container_spec_memory_swap_limit_bytes":           "memory_swap_limit_bytes",
		"container_network_receive_errors_total":           "network_rx_errors_total",
		"container_network_receive_packets_total":          "network_rx_packets_total",
		"container_network_transmit_packets_total":         "network_tx_packets_total",
		"container_network_transmit_errors_total":          "network_tx_errors_total",
		"container_network_receive_packets_dropped_total":  "network_rx_dropped_total",
		"container_network_transmit_packets_dropped_total": "network_tx_dropped_total",
	}
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 65536), 4<<20)
	var out []*collectorv1.Metric
	type memorySample struct {
		tags   map[string]string
		values map[string]float64
	}
	memory := map[string]*memorySample{}
	cgroups := map[string]bool{}
	now := timestamppb.Now()
	for scanner.Scan() {
		name, labels, value, valid := quarkus.ParseLine(scanner.Text())
		suffix, supported := names[name]
		if !valid || !supported || math.IsNaN(value) || math.IsInf(value, 0) || labels["pod"] == "" || labels["namespace"] == "" {
			continue
		}
		tags := map[string]string{"node": node, "namespace": labels["namespace"], "pod": labels["pod"]}
		scope := "container"
		if labels["container"] == "POD" || labels["container"] == "" {
			if !strings.HasPrefix(suffix, "network_") {
				continue
			}
			scope = "pod"
		} else {
			tags["container"] = labels["container"]
			if id := labels["id"]; !cgroups[id] {
				cgroups[id] = true
				for suffix, value := range c.containerCgroupMemory(id) {
					item := c.metric(now, "k8s.container."+suffix, value, tags)
					item.Source = "k8s.cgroup"
					out = append(out, item)
				}
			}
		}
		for _, key := range []string{"interface", "device"} {
			if labels[key] != "" {
				tags[key] = labels[key]
			}
		}
		item := c.metric(now, "k8s."+scope+"."+suffix, value, tags)
		item.Source = "k8s.cadvisor"
		out = append(out, item)
		if scope == "container" && suffix == "start_time_seconds" && value > 0 && value <= float64(now.Seconds) {
			uptime := c.metric(now, "k8s.container.uptime_seconds", float64(now.Seconds)+float64(now.Nanos)/1e9-value, tags)
			uptime.Source = "k8s.cadvisor"
			out = append(out, uptime)
		}
		if scope == "container" && strings.HasPrefix(suffix, "memory_") {
			key := tags["namespace"] + "/" + tags["pod"] + "/" + tags["container"]
			if memory[key] == nil {
				memory[key] = &memorySample{tags: tags, values: map[string]float64{}}
			}
			memory[key].values[suffix] = value
		}
	}
	for _, sample := range memory {
		for _, pair := range []struct{ usage, limit, metric string }{{"memory_usage_bytes", "memory_runtime_limit_bytes", "memory_usage_fraction"}, {"memory_swap_bytes", "memory_swap_limit_bytes", "memory_swap_usage_fraction"}} {
			usage, exists := sample.values[pair.usage]
			if limit := sample.values[pair.limit]; exists && limit > 0 {
				item := c.metric(now, "k8s.container."+pair.metric, usage/limit, sample.tags)
				item.Source = "k8s.cadvisor"
				out = append(out, item)
			}
		}
	}
	return out, scanner.Err()
}

func (c *k8sKubeletCheck) metric(t *timestamppb.Timestamp, name string, val float64, extraTags map[string]string) *collectorv1.Metric {
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
		Source:     "k8s.kubelet",
	}
}

// init auto-registra o factory. Mesma pattern dos outros checks.
func init() {
	Default.Register("k8s.kubelet", newK8sKubeletCheck)
}
