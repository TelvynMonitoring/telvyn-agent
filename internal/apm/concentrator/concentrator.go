// Package concentrator agrega spans em APM stats por bucket de tempo, com
// DDSketch de latência — a peça-núcleo do trace-agent (espelha o concentrator
// com agregação DDSketch).
//
// Garantia-chave: hits/errors e os sketches são contados ANTES de qualquer
// sampling. Por isso as estatísticas (p50/p95/p99, throughput, error-rate) são
// EXATAS mesmo que o agent guarde só 1 trace cru em N. O backend recebe os
// sketches no encoding nativo flag-based (mesmo formato do sketches-java) e só
// faz merge por bucket — sem reler spans.
package concentrator

import (
	"encoding/json"
	"fmt"
	"github.com/ispwatch/collector/internal/apm/primarytags"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/DataDog/sketches-go/ddsketch"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	// BucketDuration é a janela de agregação.
	BucketDuration = 10 * time.Second
	// relativeAccuracy do DDSketch — PRECISA bater com a outra ponta (backend)
	// pro merge ser válido. 1%.
	relativeAccuracy = 0.01
)

// SourceAttr é o atributo de span (interno) que carimba a origem da telemetria:
// "ebpf" (zero-código, posto pelo sink do tracer) ou ausente → "otlp". Não é
// encaminhado em span cru — só alimenta o concentrator.
const SourceAttr = "telvyn.source"

// DatabaseMonitorIDAttr links an inbound PostgreSQL eBPF span to the immutable
// database monitor configured in the portal. It is intentionally absent for
// generic database spans and collection probes.
const DatabaseMonitorIDAttr = "telvyn.database_monitor_id"

// PrimaryTagPrefix is reserved for metadata verified by the local receiver,
// never attributes supplied by an SDK.
const PrimaryTagPrefix = "telvyn.verified_primary."

// GroupedStats é o snapshot de um grupo num bucket, pronto pro forwarder
// converter em ApmGroupedStats (proto). Os sketches já vêm serializados.
type GroupedStats struct {
	BucketStartUnixNano int64
	Env                 string
	Service             string
	Resource            string
	Operation           string
	SpanKind            int32
	HTTPStatusCode      int32
	Hits                uint64
	Errors              uint64
	DurationSumNano     uint64
	MaxDurationNano     uint64
	TopLevel            bool
	Source              string // "otlp" (instrumentado) | "ebpf" (zero-código)
	DbSystem            string // protocolo de datastore detectado (eBPF): postgresql/redis/… ou ""
	DatabaseMonitorID   string // monitor de banco que recebeu o workload eBPF; "" quando não atribuído
	Namespace           string // namespace do pod (serviços eBPF); "" se desconhecido
	Peer                string
	ServiceVersion      string
	PrimaryTags         map[string]string
	OkSummary           []byte // DDSketch (nanos) das latências OK; nil se vazio
	ErrorSummary        []byte // DDSketch (nanos) das latências de erro; nil se vazio
}

type bucketKey struct {
	env               string
	service           string
	resource          string
	operation         string
	spanKind          int32
	httpStatus        int32
	source            string
	dbSystem          string
	databaseMonitorID string
	peer              string
	serviceVersion    string
	primaryTags       string
}

type groupStats struct {
	hits            uint64
	errors          uint64
	durationSumNano uint64
	maxDurationNano uint64
	topLevel        bool
	// namespace do pod NÃO entra na bucketKey (é funcionalmente determinado pelo
	// service → não inflaria cardinalidade, mas mantê-lo fora da chave evita
	// dividir um mesmo service caso um span venha sem namespace). first-wins.
	namespace string
	okSketch  *ddsketch.DDSketch
	errSketch *ddsketch.DDSketch
}

// Concentrator acumula stats de forma thread-safe. Add roda no hot path (Push);
// Flush é chamado periodicamente pelo loop do trace-agent.
type Concentrator struct {
	mu          sync.Mutex
	buckets     map[int64]map[bucketKey]*groupStats
	log         *slog.Logger
	primaryKeys []string
}

func (c *Concentrator) ApplyPrimaryTags(keys []string) error {
	if len(keys) > 2 {
		return fmt.Errorf("at most two primary tags")
	}
	seen := map[string]bool{}
	for _, key := range keys {
		if seen[key] {
			return fmt.Errorf("duplicate primary tag")
		}
		if !primarytags.ValidKey(key) {
			return fmt.Errorf("unsupported primary tag")
		}
		seen[key] = true
	}
	c.mu.Lock()
	c.primaryKeys = append([]string(nil), keys...)
	c.mu.Unlock()
	return nil
}
func (c *Concentrator) PrimaryTagKeys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.primaryKeys...)
}

// New cria um concentrator vazio.
func New(log *slog.Logger) *Concentrator {
	if log == nil {
		log = slog.Default()
	}
	return &Concentrator{
		buckets: make(map[int64]map[bucketKey]*groupStats),
		log:     log.With("component", "apm-concentrator"),
	}
}

// Add contabiliza um span. Seguro no hot path. Spans inválidos são ignorados.
func (c *Concentrator) Add(s *collectorv1.Span) {
	if s == nil || s.StartUnixNano <= 0 || s.EndUnixNano < s.StartUnixNano {
		return
	}
	dur := s.EndUnixNano - s.StartUnixNano
	bucketStart := s.StartUnixNano - (s.StartUnixNano % int64(BucketDuration))
	k := bucketKey{
		env:               s.Attributes["deployment.environment"],
		service:           s.ServiceName,
		resource:          resourceOf(s),
		operation:         s.Name,
		spanKind:          s.Kind,
		httpStatus:        httpStatusOf(s.Attributes),
		source:            spanSource(s),
		dbSystem:          s.Attributes["db.system"],
		databaseMonitorID: s.Attributes[DatabaseMonitorIDAttr],
		peer:              peerOf(s),
		serviceVersion:    s.Attributes["service.version"],
	}
	if k.env == "" {
		k.env = s.Attributes["deployment.environment.name"]
	}
	namespace := s.Namespace
	// Outbound eBPF spans retain the destination as query owner. Map statistics
	// must attribute the call to the observed client instead of dropping a self-loop.
	if k.source == "ebpf" && s.Kind == 3 && s.Attributes["client.pod"] != "" {
		k.service = s.Attributes["client.pod"]
		namespace = s.Attributes["client.namespace"]
	}
	isErr := s.StatusCode == 2 // OTLP ERROR

	c.mu.Lock()
	defer c.mu.Unlock()
	tags := map[string]string{}
	for _, key := range c.primaryKeys {
		if value := s.Attributes[PrimaryTagPrefix+key]; value != "" {
			tags[key] = value
		}
	}
	encoded, _ := json.Marshal(tags)
	k.primaryTags = string(encoded)
	groups := c.buckets[bucketStart]
	if groups == nil {
		groups = make(map[bucketKey]*groupStats)
		c.buckets[bucketStart] = groups
	}
	g := groups[k]
	if g == nil {
		g = &groupStats{
			okSketch:  newSketch(),
			errSketch: newSketch(),
			topLevel:  s.Kind == 2 || s.Kind == 5, // SERVER ou CONSUMER = span de entrada
			namespace: namespace,
		}
		groups[k] = g
	} else if g.namespace == "" && namespace != "" {
		// Preenche o namespace se o 1º span do grupo veio sem ele (é o mesmo
		// service, logo o mesmo pod/namespace).
		g.namespace = namespace
	}
	g.hits++
	g.durationSumNano += uint64(dur)
	if uint64(dur) > g.maxDurationNano {
		g.maxDurationNano = uint64(dur)
	}
	if isErr {
		g.errors++
		_ = g.errSketch.Add(float64(dur))
	} else {
		_ = g.okSketch.Add(float64(dur))
	}
}

// Flush devolve todos os buckets acumulados e zera o estado. Reemitir o mesmo
// bucket (parcial) entre flushes é seguro: o backend mescla por bucket_start.
func (c *Concentrator) Flush() []GroupedStats {
	c.mu.Lock()
	buckets := c.buckets
	c.buckets = make(map[int64]map[bucketKey]*groupStats)
	c.mu.Unlock()

	var out []GroupedStats
	for bucketStart, groups := range buckets {
		for k, g := range groups {
			var tags map[string]string
			_ = json.Unmarshal([]byte(k.primaryTags), &tags)
			out = append(out, GroupedStats{
				BucketStartUnixNano: bucketStart,
				Env:                 k.env,
				Service:             k.service,
				Resource:            k.resource,
				Operation:           k.operation,
				SpanKind:            k.spanKind,
				HTTPStatusCode:      k.httpStatus,
				Hits:                g.hits,
				Errors:              g.errors,
				DurationSumNano:     g.durationSumNano,
				MaxDurationNano:     g.maxDurationNano,
				TopLevel:            g.topLevel,
				Source:              k.source,
				DbSystem:            k.dbSystem,
				DatabaseMonitorID:   k.databaseMonitorID,
				Namespace:           g.namespace,
				Peer:                k.peer,
				ServiceVersion:      k.serviceVersion,
				PrimaryTags:         tags,
				OkSummary:           encodeSketch(g.okSketch),
				ErrorSummary:        encodeSketch(g.errSketch),
			})
		}
	}
	return out
}

func newSketch() *ddsketch.DDSketch {
	s, _ := ddsketch.NewDefaultDDSketch(relativeAccuracy)
	return s
}

// Peer is a service or endpoint, never a URL path/query or SQL statement.
func peerOf(s *collectorv1.Span) string {
	if s.Kind != 3 && s.Kind != 4 {
		return ""
	}
	for _, key := range []string{"server.pod", "peer.service"} {
		if value := s.Attributes[key]; value != "" {
			return value
		}
	}
	var host string
	for _, key := range []string{"server.address", "net.peer.name", "net.peer.ip"} {
		if host = s.Attributes[key]; host != "" {
			break
		}
	}
	if host == "" {
		return s.Attributes["db.system"]
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return ""
	}
	port := s.Attributes["server.port"]
	if port == "" {
		port = s.Attributes["net.peer.port"]
	}
	if port != "" && port != "0" {
		return net.JoinHostPort(host, port)
	}
	return host
}

func encodeSketch(s *ddsketch.DDSketch) []byte {
	if s == nil || s.GetCount() == 0 {
		return nil
	}
	var b []byte
	s.Encode(&b, false) // false = inclui o index mapping (backend decoda sem saber o accuracy)
	return b
}

// resourceOf deriva o resource de baixa cardinalidade. Pra HTTP usa method+route;
// senão cai no nome da operação. (Normalização fina de path fica pro obfuscator.)
func resourceOf(s *collectorv1.Span) string {
	if resource := s.Attributes["resource.name"]; resource != "" {
		return resource
	}
	method := s.Attributes["http.request.method"]
	if method == "" {
		method = s.Attributes["http.method"]
	}
	route := s.Attributes["http.route"]
	if method != "" && route != "" {
		return method + " " + route
	}
	return s.Name
}

// spanSource lê o carimbo de origem do span (APM instrumentado vs eBPF). O sink
// do eBPF marca "telvyn.source"="ebpf"; spans OTLP instrumentados não têm o
// atributo → "otlp". Vira coluna no backend e badge no catálogo.
func spanSource(s *collectorv1.Span) string {
	if v := s.Attributes[SourceAttr]; v != "" {
		return v
	}
	return "otlp"
}

func httpStatusOf(attrs map[string]string) int32 {
	v := attrs["http.response.status_code"]
	if v == "" {
		v = attrs["http.status_code"]
	}
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return int32(n)
}
