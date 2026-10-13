// Package langdetect detecta a LINGUAGEM de cada pod do nó pelo processo que
// está rodando por inspeção de processos e reporta por
// (namespace, pod) pro gateway. O backend usa isso pra decidir o que é
// instrumentável (ex: Java → mostra o botão de auto-injeção do webhook),
// mesmo num app caixa-preta que ainda não emite telemetria.
//
// Não usa palavra-chave da imagem (frágil): olha /proc/<pid>/exe + cmdline +
// maps. Requer hostPID (o DaemonSet já roda assim em k8s.node) pra enxergar os
// processos de todos os pods do nó. Mapeia pid→pod reusando o PodResolver
// (mesmo do carimbo por IP / eBPF).
package langdetect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// PodResolver mapeia um PID pro pod k8s. Implementado por internal/ebpf.PodResolverImpl.
type PodResolver interface {
	Resolve(pid uint32) (namespace string, pod string, ok bool)
}

// Pusher envia o payload JSON pro gateway. Implementado por otlp.IngestExporter.
type Pusher interface {
	PostRaw(ctx context.Context, signal, contentType string, body []byte) error
}

// Detector varre os processos do nó periodicamente e reporta a linguagem por pod.
type Detector struct {
	Cluster  string
	resolver PodResolver
	pusher   Pusher
	log      *slog.Logger
	interval time.Duration
	procRoot string
}

func New(resolver PodResolver, pusher Pusher, log *slog.Logger) *Detector {
	return &Detector{
		resolver: resolver,
		pusher:   pusher,
		log:      log,
		interval: 60 * time.Second,
		procRoot: "/proc",
	}
}

type podLang struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Language  string `json:"language"`
}

// Run bloqueia até ctx cancelar; reporta a cada interval (1º tick imediato).
func (d *Detector) Run(ctx context.Context) {
	t := time.NewTicker(d.interval)
	defer t.Stop()
	d.scanAndPush(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.scanAndPush(ctx)
		}
	}
}

func (d *Detector) scanAndPush(ctx context.Context) {
	entries, err := os.ReadDir(d.procRoot)
	if err != nil {
		d.log.Debug("langdetect: read /proc falhou", "err", err)
		return
	}
	// Melhor linguagem por pod (ns/pod). Um pod pode ter shell + runtime; o
	// rank prioriza o runtime real sobre genéricos.
	byPod := make(map[string]podLang, 32)
	byContainer := make(map[string]map[string]string)
	ambiguous := make(map[string]bool)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		lang := d.detectLang(pid)
		if lang == "" {
			continue
		}
		ns, pod, ok := d.resolver.Resolve(pid)
		if !ok || ns == "" || pod == "" {
			continue
		}
		key := ns + "/" + pod
		if resolver, ok := d.resolver.(interface {
			ResolveContainer(uint32) (string, string, string, string, bool)
		}); ok {
			_, _, container, image, found := resolver.ResolveContainer(pid)
			if found {
				containerKey := key + "/" + container
				if previous, exists := byContainer[containerKey]; exists && strings.TrimSuffix(previous["language"], "-unsupported") != lang {
					ambiguous[containerKey] = true
				}
				byContainer[containerKey] = map[string]string{"namespace": ns, "pod": pod, "container": container, "image": image, "language": d.containerLanguage(pid, lang)}
			}
		}
		if cur, exists := byPod[key]; !exists || rank(lang) > rank(cur.Language) {
			byPod[key] = podLang{Namespace: ns, Pod: pod, Language: lang}
		}
	}
	if len(byPod) == 0 {
		return
	}
	list := make([]podLang, 0, len(byPod))
	for _, v := range byPod {
		list = append(list, v)
	}
	body, err := json.Marshal(map[string]any{"pods": list})
	if err != nil {
		return
	}
	if err := d.pusher.PostRaw(ctx, "k8s/pod-languages", "application/json", body); err != nil {
		d.log.Debug("langdetect: push falhou", "err", err, "count", len(list))
		return
	}
	d.log.Info("langdetect: linguagens reportadas", "pods", len(list))
	if d.Cluster != "" && len(byContainer) > 0 {
		containers := []map[string]string{}
		for key, item := range byContainer {
			if ambiguous[key] {
				item["language"] = "ambiguous"
			}
			containers = append(containers, item)
		}
		body, err := json.Marshal(map[string]any{"cluster": d.Cluster, "containers": containers})
		if err == nil {
			if err := d.pusher.PostRaw(ctx, "k8s/runtime-languages", "application/json", body); err != nil {
				d.log.Debug("container language report failed", "err", err)
			}
		}
	}
}

// Bundled native dependencies must match the runtime actually mapped by the
// process. Unknown/other ABIs remain visible but cannot be selected for injection.
func (d *Detector) containerLanguage(pid uint32, language string) string {
	maps := filepath.Join(d.procRoot, strconv.FormatUint(uint64(pid), 10), "maps")
	switch language {
	case "dotnet":
		if runtime.GOARCH != "amd64" || !hasLib(maps, "/Microsoft.NETCore.App/8.") {
			return "dotnet-unsupported"
		}
	case "python":
		exe, _ := os.Readlink(filepath.Join(d.procRoot, strconv.FormatUint(uint64(pid), 10), "exe"))
		if runtime.GOARCH != "amd64" || (!hasLib(maps, "libpython3.13") && filepath.Base(exe) != "python3.13") || !hasLib(maps, "ld-musl-") {
			return "python-unsupported"
		}
	case "ruby":
		if runtime.GOARCH != "amd64" || !hasLib(maps, "libruby.so.3.3") || !hasLib(maps, "ld-musl-") {
			return "ruby-unsupported"
		}
	}
	return language
}

// detectLang olha exe → cmdline → maps (fallback p/ Java via libjvm.so).
// "" = kernel thread / processo sem runtime reconhecido.
func (d *Detector) detectLang(pid uint32) string {
	base := filepath.Join(d.procRoot, strconv.FormatUint(uint64(pid), 10))
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		if l := langFromName(filepath.Base(exe)); l != "" {
			return l
		}
	}
	raw, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err != nil || len(raw) == 0 {
		return "" // kernel thread ou processo já saiu
	}
	first := raw
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		first = raw[:i]
	}
	if l := langFromName(filepath.Base(string(first))); l != "" {
		return l
	}
	// Fallback p/ Java (alvo principal): wrappers podem esconder o `java`,
	// mas o processo carrega libjvm.so.
	if hasLib(filepath.Join(base, "maps"), "libjvm.so") {
		return "java"
	}
	if hasLib(filepath.Join(base, "maps"), "libcoreclr.so") {
		return "dotnet"
	}
	return ""
}

// langFromName reconhece o runtime pelo nome do executável.
func langFromName(name string) string {
	n := strings.ToLower(name)
	switch {
	case n == "java" || strings.HasPrefix(n, "java"):
		return "java"
	case n == "node" || n == "nodejs":
		return "node"
	case strings.HasPrefix(n, "python"):
		return "python"
	case n == "ruby":
		return "ruby"
	case n == "dotnet":
		return "dotnet"
	case n == "php" || strings.HasPrefix(n, "php-fpm"):
		return "php"
	}
	return ""
}

// rank: qual linguagem ganha quando o pod tem vários processos reconhecidos.
func rank(lang string) int {
	switch lang {
	case "java":
		return 5
	case "node":
		return 4
	case "python":
		return 3
	case "dotnet":
		return 2
	case "ruby":
		return 1
	}
	return 0
}

// hasLib procura uma lib carregada em /proc/<pid>/maps.
func hasLib(mapsPath, needle string) bool {
	f, err := os.Open(mapsPath)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.Contains(sc.Text(), needle) {
			return true
		}
	}
	return false
}
