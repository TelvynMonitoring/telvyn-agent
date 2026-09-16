// ingest.go — modo certless: manda telemetria pro gateway OTLP do
// Telvyn (/api/ingest/v1) autenticando com um Bearer token reusável (iwI_),
// sobre HTTP simples. SEM mTLS, sem cert por agent, sem enrollment.
//
// Dois caminhos:
//   - PostRaw: encaminha o corpo OTLP cru recebido pelo receiver (spans,
//     logs, metrics de apps) — zero conversão.
//   - PostMetrics: converte as métricas nativas do host (CPU/mem/disco/rede
//     dos self-checks) pra OTLP metrics e manda pro /metrics.
//
// Usa token Bearer + HTTPS; o
// servidor identifica o tenant pelo token.

package otlp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ispwatch/collector/internal/sendbuf"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/encoding/protojson"

	metricscolpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// IngestExporter envia OTLP pro gateway com Bearer token.
type IngestExporter struct {
	base        string // ex: http://telvyn.host/api/ingest/v1 (sem barra final)
	token       string
	hostID      string
	clusterName string
	version     string // versão do binário (ldflags) — vai no registro, base do aviso de atualização
	client      *http.Client
	log         *slog.Logger
	// UUID do noc_collector deste agente (SetCollectorID). Vai no header
	// X-Ispwatch-Collector — o gateway valida (∈ tenant) e carimba as
	// self-metrics com o collector_id REAL em vez do sintético por token.
	// atomic: setado depois que goroutines de envio já podem estar rodando.
	collectorID atomic.Value
	// Política de coleção entregue pelo backend no config-pull. Antes da primeira
	// sincronização preserva compatibilidade; depois, sinais opcionais são fail-closed.
	enabledModules atomic.Value // map[string]bool
	// Retenção das métricas nativas do host quando o backend está fora
	// (rollout/rede). Só métricas: spans/logs de app que passam pelo PostRaw
	// já têm backpressure próprio (o receiver devolve 502 e o SDK reenvia).
	metricsPending *sendbuf.Queue
	// Provider agregado do scheduler. Setado no startup e lido somente no
	// heartbeat; não coloca I/O nem serialização no caminho de cada check.
	runtimeStatsProvider atomic.Value // func() CollectorRuntimeStats
}

// CollectorRuntimeStats é o contrato sem segredos enviado no heartbeat.
type CollectorRuntimeStats struct {
	ActiveChecks          int64  `json:"active_checks"`
	PollRuns              int64  `json:"poll_runs"`
	PollSuccesses         int64  `json:"poll_successes"`
	PollFailures          int64  `json:"poll_failures"`
	PollTimeouts          int64  `json:"poll_timeouts"`
	LastPollDurationMS    int64  `json:"last_poll_duration_ms"`
	AveragePollDurationMS int64  `json:"avg_poll_duration_ms"`
	MaxPollDurationMS     int64  `json:"max_poll_duration_ms"`
	PendingPayloads       int64  `json:"pending_payloads"`
	PendingBytes          int64  `json:"pending_bytes"`
	RetryAttempts         int64  `json:"retry_attempts"`
	RetrySuccesses        int64  `json:"retry_successes"`
	DroppedPayloads       int64  `json:"dropped_payloads"`
	IngestBlocked         bool   `json:"ingest_blocked"`
	LastPollAt            string `json:"last_poll_at,omitempty"`
	LastPollSuccessAt     string `json:"last_poll_success_at,omitempty"`
	LastPollFailureAt     string `json:"last_poll_failure_at,omitempty"`
}

// SetCollectorRuntimeStatsProvider liga o scheduler ao heartbeat sem criar
// dependência do pacote OTLP sobre checks.Runtime.
func (e *IngestExporter) SetCollectorRuntimeStatsProvider(provider func() CollectorRuntimeStats) {
	if provider != nil {
		e.runtimeStatsProvider.Store(provider)
	}
}

// SetEnabledModules aplica imediatamente a política do tenant sem reiniciar o agent.
func (e *IngestExporter) SetEnabledModules(modules []string) {
	enabled := make(map[string]bool, len(modules))
	for _, module := range modules {
		enabled[strings.ToUpper(strings.TrimSpace(module))] = true
	}
	e.enabledModules.Store(enabled)
}

func (e *IngestExporter) signalAllowed(signal string) bool {
	modules, ok := e.enabledModules.Load().(map[string]bool)
	if !ok {
		return true
	} // backend anterior ao contrato de entitlement
	switch signal {
	case "traces", "apm/stats", "profile":
		return modules["APM"]
	case "logs":
		return modules["LOGS"]
	case "snmptrap", "device-metadata", "ncm/config":
		return modules["REDE_SNMP"]
	case "topology":
		return modules["REDE_SNMP"]
	case "sbom":
		return modules["VULNERABILIDADES"]
	case "k8s/events", "k8s/pod-languages":
		return modules["KUBERNETES"]
	case "k8s/resources":
		return modules["KUBERNETES"]
	case "host/services":
		return modules["INFRAESTRUTURA"]
	case "db/query-stats":
		return modules["BANCOS_DADOS"]
	case "db/catalog":
		return modules["BANCOS_DADOS"]
	case "db/explain":
		return modules["BANCOS_DADOS"]
	default:
		return true
	}
}

// NewIngestExporter. base = URL do gateway (com ou sem /api/ingest/v1 — a
// gente normaliza). token = ingest token iwI_. hostID/cluster viram resource
// attrs nas métricas convertidas. version = build da flag -ldflags (main.Version).
func NewIngestExporter(base, token, hostID, clusterName, version string, log *slog.Logger) *IngestExporter {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if !strings.HasSuffix(base, "/api/ingest/v1") {
		base = base + "/api/ingest/v1"
	}
	return &IngestExporter{
		base:           base,
		token:          strings.TrimSpace(token),
		hostID:         hostID,
		clusterName:    clusterName,
		version:        version,
		client:         &http.Client{Timeout: 20 * time.Second},
		log:            log.With("component", "ingest-exporter"),
		metricsPending: sendbuf.New("host-metrics", 8<<20, log),
	}
}

// PostRaw encaminha um corpo já codificado pro signal indicado
// ("traces" | "metrics" | "logs" | "db/catalog" | "db/explain"), preservando
// o Content-Type original.
func (e *IngestExporter) PostRaw(ctx context.Context, signal, contentType string, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	if !e.signalAllowed(signal) {
		return nil
	}
	url := e.base + "/" + signal
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if contentType == "" {
		contentType = "application/x-protobuf"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+e.token)
	if cid, _ := e.collectorID.Load().(string); cid != "" {
		req.Header.Set("X-Ispwatch-Collector", cid)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// Token revogado/inválido: loga a mensagem clara (rate-limited) pra
		// TODOS os sinais que passam por aqui — sem isso o operador só via
		// um "HTTP 401" genérico em loop, sem saber que era o token.
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			e.metricsPending.NoteAuthFailure(resp.StatusCode)
		}
		return fmt.Errorf("ingest %s: %w", signal, &sendbuf.StatusError{Code: resp.StatusCode})
	}
	return nil
}

// PostMetrics converte métricas nativas → OTLP Gauge e manda pro /metrics.
func (e *IngestExporter) PostMetrics(ctx context.Context, metrics []*collectorv1.Metric) error {
	if len(metrics) == 0 {
		return nil
	}
	dps := make([]*metricspb.Metric, 0, len(metrics))
	for _, m := range metrics {
		if m == nil || m.GetMetricName() == "" {
			continue
		}
		var tsNano uint64
		if m.GetTime() != nil {
			tsNano = uint64(m.GetTime().AsTime().UnixNano())
		} else {
			tsNano = uint64(time.Now().UnixNano())
		}
		attrs := make([]*commonpb.KeyValue, 0, len(m.GetTags())+3)
		for k, v := range m.GetTags() {
			attrs = append(attrs, kv(k, v))
		}
		if h := m.GetHostId(); h != "" {
			attrs = append(attrs, kv("host.id", h))
		}
		if iface := m.GetInterfaceName(); iface != "" {
			attrs = append(attrs, kv("interface", iface))
		}
		if src := m.GetSource(); src != "" {
			attrs = append(attrs, kv("source", src))
		}
		dps = append(dps, &metricspb.Metric{
			Name: m.GetMetricName(),
			Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{
				DataPoints: []*metricspb.NumberDataPoint{{
					TimeUnixNano: tsNano,
					Attributes:   attrs,
					Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: m.GetValue()},
				}},
			}},
		})
	}
	if len(dps) == 0 {
		return nil
	}
	res := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		kv("service.name", "telvyn-agent"),
		kv("host.name", e.hostID),
	}}
	if e.clusterName != "" {
		res.Attributes = append(res.Attributes, kv("k8s.cluster.name", e.clusterName))
	}
	reqMsg := &metricscolpb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource:     res,
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: dps}},
		}},
	}
	// Gateway OTLP do Telvyn é JSON-only (igual /traces) — manda protojson.
	body, err := protojson.Marshal(reqMsg)
	if err != nil {
		return err
	}
	// Falha de rede/5xx retém o corpo pra reenvio no próximo lote (os pontos
	// têm timestamp — chegar atrasado no VM não corrompe nada). 401/429
	// descartam com aviso claro via sendbuf.
	if e.metricsPending.Blocked() {
		return nil
	}
	e.metricsPending.Flush(ctx, func(fctx context.Context, b []byte) error {
		return e.PostRaw(fctx, "metrics", "application/json", b)
	})
	if err := e.PostRaw(ctx, "metrics", "application/json", body); err != nil {
		e.metricsPending.Offer(body, err)
		return err
	}
	return nil
}

// PostSnmpTrap encaminha um SNMP trap já parseado pro backend (noc_device_event).
// O backend mapeia source_ip→host e classifica o trap_oid (severity + mensagem).
func (e *IngestExporter) PostSnmpTrap(ctx context.Context, trap map[string]any) error {
	if len(trap) == 0 {
		return nil
	}
	body, err := json.Marshal(trap)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "snmptrap", "application/json", body)
}

// PostK8sEvents encaminha um lote de eventos do Kubernetes pro gateway
// (noc_k8s_event, Cluster Agent F2). O payload já vem no shape do endpoint
// {"cluster": ..., "events": [{...}]}; o backend deriva o tenant do token e
// deduplica por (cluster, namespace, pod, reason, involved_name) agregando o
// count nativo do k8s. Molde de PostSnmpTrap — JSON + Bearer, check 2xx.
func (e *IngestExporter) PostK8sEvents(ctx context.Context, payload map[string]any) error {
	if len(payload) == 0 {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "k8s/events", "application/json", body)
}

// PostK8sResources envia um snapshot do inventário Kubernetes. O backend
// mantém identidade/estado separado das métricas do kubelet.
func (e *IngestExporter) PostK8sResources(ctx context.Context, payload map[string]any) error {
	if len(payload) == 0 {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "k8s/resources", "application/json", body)
}

// PostHostServices encaminha os serviços descobertos numa máquina (processos que
// escutam porta, com CPU/mem) pro gateway (noc_host_service — o "o que roda aqui"
// da lente de Máquina). Payload {"host_id": N, "services": [{...}]}; o backend
// deriva o tenant do token e faz replace-snapshot por host. Molde de PostK8sEvents.
func (e *IngestExporter) PostHostServices(ctx context.Context, payload map[string]any) error {
	if len(payload) == 0 {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "host/services", "application/json", body)
}

// DatabaseQueryStatsPayload é o agregado de uma janela de pg_stat_statements.
// Os valores das linhas são deltas, não contadores cumulativos.
type DatabaseQueryStatsPayload struct {
	DBServer      string              `json:"db_server"`
	DBName        string              `json:"db_name"`
	WindowSeconds int                 `json:"window_seconds"`
	Queries       []DatabaseQueryStat `json:"queries"`
}

type DatabaseQueryStat struct {
	QueryID string  `json:"query_id"`
	Text    string  `json:"text"`
	Calls   int64   `json:"calls"`
	TotalMS float64 `json:"total_ms"`
	MeanMS  float64 `json:"mean_ms"`
	Rows    int64   `json:"rows"`
}

// PostDatabaseQueryStats publica uma janela no sinal próprio de banco. Query
// stats são agregados e não devem virar uma série por consulta no VM.
func (e *IngestExporter) PostDatabaseQueryStats(ctx context.Context, payload DatabaseQueryStatsPayload) error {
	if len(payload.Queries) == 0 {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "db/query-stats", "application/json", body)
}

// DatabaseCatalogPayload é um snapshot de metadados. Não contém linhas de
// negócio: apenas estrutura e estatísticas agregadas do banco.
type DatabaseCatalogPayload struct {
	DBServer          string                 `json:"db_server"`
	DBName            string                 `json:"db_name"`
	ServerVersion     string                 `json:"server_version"`
	DatabaseSizeBytes int64                  `json:"database_size_bytes"`
	Fingerprint       string                 `json:"fingerprint"`
	Truncated         bool                   `json:"truncated"`
	Tables            []DatabaseCatalogTable `json:"tables"`
}

type DatabaseCatalogTable struct {
	SchemaName      string                      `json:"schema_name"`
	TableName       string                      `json:"table_name"`
	TableKind       string                      `json:"table_kind"`
	TotalSizeBytes  int64                       `json:"total_size_bytes"`
	TableSizeBytes  int64                       `json:"table_size_bytes"`
	IndexSizeBytes  int64                       `json:"index_size_bytes"`
	EstimatedRows   int64                       `json:"estimated_rows"`
	SeqScans        int64                       `json:"seq_scans"`
	IndexScans      int64                       `json:"index_scans"`
	DeadRows        int64                       `json:"dead_rows"`
	LastVacuum      string                      `json:"last_vacuum"`
	LastAutoVacuum  string                      `json:"last_autovacuum"`
	LastAnalyze     string                      `json:"last_analyze"`
	LastAutoAnalyze string                      `json:"last_autoanalyze"`
	Columns         []DatabaseCatalogColumn     `json:"columns"`
	Indexes         []DatabaseCatalogIndex      `json:"indexes"`
	Constraints     []DatabaseCatalogConstraint `json:"constraints"`
}

type DatabaseCatalogColumn struct {
	Name       string `json:"name"`
	Ordinal    int    `json:"ordinal"`
	DataType   string `json:"data_type"`
	Nullable   bool   `json:"nullable"`
	HasDefault bool   `json:"has_default"`
}

type DatabaseCatalogIndex struct {
	Name          string `json:"name"`
	Definition    string `json:"definition"`
	Unique        bool   `json:"unique"`
	Primary       bool   `json:"primary"`
	Scans         int64  `json:"scans"`
	TuplesRead    int64  `json:"tuples_read"`
	TuplesFetched int64  `json:"tuples_fetched"`
	SizeBytes     int64  `json:"size_bytes"`
}

type DatabaseCatalogConstraint struct {
	Name           string `json:"name"`
	ConstraintType string `json:"type"`
	Definition     string `json:"definition"`
}

// PostDatabaseCatalog publica o snapshot no sinal próprio de banco. Os
// metadados são mantidos separados do fluxo de métricas para não explodir
// cardinalidade no VictoriaMetrics.
func (e *IngestExporter) PostDatabaseCatalog(ctx context.Context, payload DatabaseCatalogPayload) error {
	if payload.DBServer == "" || payload.DBName == "" {
		return fmt.Errorf("database catalog: db_server e db_name são obrigatórios")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "db/catalog", "application/json", body)
}

// DatabaseExplainPayload é o resultado de uma solicitação pontual de plano.
// O plano é JSON do PostgreSQL; EXPLAIN sem ANALYZE nunca executa a consulta.
type DatabaseExplainPayload struct {
	RequestID string `json:"request_id"`
	CheckID   string `json:"check_id"`
	DBServer  string `json:"db_server"`
	DBName    string `json:"db_name"`
	PlanJSON  string `json:"plan_json,omitempty"`
	Error     string `json:"error,omitempty"`
}

// PostDatabaseExplain publica um único plano de execução no canal dedicado.
func (e *IngestExporter) PostDatabaseExplain(ctx context.Context, payload DatabaseExplainPayload) error {
	if payload.RequestID == "" || payload.CheckID == "" || payload.DBServer == "" || payload.DBName == "" {
		return fmt.Errorf("database explain: identidade é obrigatória")
	}
	if payload.PlanJSON == "" && payload.Error == "" {
		return fmt.Errorf("database explain: plan_json ou error é obrigatório")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "db/explain", "application/json", body)
}

// ---- Logs (OTLP JSON) -------------------------------------------------

// Shapes JSON do OTLP logs export (resourceLogs → scopeLogs → logRecords).
// Construímos à mão (sem dep do proto otlp/logs) porque o gateway Quarkus
// parseia via Jackson — só precisa do shape, não do protobuf. Espelha o que
// parseOtlpJsonLogs espera: service.name/host.name/k8s.* em resource attrs,
// body.stringValue, timeUnixNano como string, severityNumber como número.
type otlpLogsPayload struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	Resource  otlpLogResource `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpLogResource struct {
	Attributes []otlpLogKV `json:"attributes"`
}

type otlpScopeLogs struct {
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpLogRecord struct {
	TimeUnixNano   string       `json:"timeUnixNano"`
	SeverityNumber int          `json:"severityNumber,omitempty"`
	SeverityText   string       `json:"severityText,omitempty"`
	Body           otlpLogValue `json:"body"`
	TraceID        string       `json:"traceId,omitempty"`
	SpanID         string       `json:"spanId,omitempty"`
	Attributes     []otlpLogKV  `json:"attributes,omitempty"`
}

// otlpLogKV / otlpLogValue: shapes próprios dos logs (o http.go já tem um
// otlpKeyValue do receiver de spans, com Value inline — por isso prefixo Log).
type otlpLogKV struct {
	Key   string       `json:"key"`
	Value otlpLogValue `json:"value"`
}

type otlpLogValue struct {
	StringValue string `json:"stringValue"`
}

func logKV(k, v string) otlpLogKV {
	return otlpLogKV{Key: k, Value: otlpLogValue{StringValue: v}}
}

// PostLogs converte LogRecords internos → OTLP JSON e manda pro /logs com
// Bearer. Agrupa por (service, namespace, pod) em ResourceLogs distintos —
// o backend lê service.name do resource attr e namespace/pod do attr mesclado,
// então o agrupamento dá service_name correto por pod. k8s.container.name e
// outros attrs ficam no log record (variam por linha dentro do pod).
func (e *IngestExporter) PostLogs(ctx context.Context, records []LogRecord) error {
	if len(records) == 0 {
		return nil
	}
	var payload otlpLogsPayload
	groups := make(map[string]int, 8) // chave → índice em payload.ResourceLogs
	for _, r := range records {
		ns := r.Attributes["k8s.namespace.name"]
		pod := r.Attributes["k8s.pod.name"]
		svc := r.ServiceName
		host := r.Hostname
		if host == "" {
			host = e.hostID
		}
		key := svc + "\x00" + ns + "\x00" + pod + "\x00" + host
		idx, ok := groups[key]
		if !ok {
			resAttrs := make([]otlpLogKV, 0, 5)
			if svc != "" {
				resAttrs = append(resAttrs, logKV("service.name", svc))
			}
			if host != "" {
				resAttrs = append(resAttrs, logKV("host.name", host))
			}
			if ns != "" {
				resAttrs = append(resAttrs, logKV("k8s.namespace.name", ns))
			}
			if pod != "" {
				resAttrs = append(resAttrs, logKV("k8s.pod.name", pod))
			}
			if e.clusterName != "" {
				resAttrs = append(resAttrs, logKV("k8s.cluster.name", e.clusterName))
			}
			payload.ResourceLogs = append(payload.ResourceLogs, otlpResourceLogs{
				Resource:  otlpLogResource{Attributes: resAttrs},
				ScopeLogs: []otlpScopeLogs{{}},
			})
			idx = len(payload.ResourceLogs) - 1
			groups[key] = idx
		}
		// Attrs do record: tudo menos os que viraram resource attr (evita dup).
		recAttrs := make([]otlpLogKV, 0, len(r.Attributes))
		for k, v := range r.Attributes {
			switch k {
			case "k8s.namespace.name", "k8s.pod.name", "service.name", "host.name":
				continue
			}
			recAttrs = append(recAttrs, logKV(k, v))
		}
		rec := otlpLogRecord{
			TimeUnixNano:   strconv.FormatInt(r.TimestampUnixNano, 10),
			SeverityNumber: r.SeverityNumber,
			SeverityText:   r.SeverityText,
			Body:           otlpLogValue{StringValue: r.Body},
			TraceID:        r.TraceID,
			SpanID:         r.SpanID,
			Attributes:     recAttrs,
		}
		sl := &payload.ResourceLogs[idx].ScopeLogs[0]
		sl.LogRecords = append(sl.LogRecords, rec)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "logs", "application/json", body)
}

// PostCheckStatus envia o resultado de uma execução de check.
//
// Antes disto o motivo só existia no log desta máquina: o agente publicava um
// contador ispwatch.check.errors{check_id} e a tela do equipamento mostrava
// "warning" sem dizer nada. Agora o backend grava a mensagem em
// noc_hostcheck.last_error e a página do equipamento explica sozinha.
//
// Chamado a cada execução para que o backend consiga distinguir um check
// realmente recente de uma simples ausência de mudança de estado.
func (e *IngestExporter) PostCheckStatus(ctx context.Context, checkID string, ok bool, message string) error {
	if strings.TrimSpace(checkID) == "" {
		return nil
	}
	status := map[string]any{"check_id": checkID, "ok": ok}
	if !ok && message != "" {
		status["message"] = message
	}
	body, err := json.Marshal(map[string]any{"statuses": []any{status}})
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "check-status", "application/json", body)
}

// PostTopology envia um lote LLDP/CDP em JSON protobuf para o gateway HTTP.
// A topologia não passa pelo canal gRPC: o agente de produção usa somente o
// transporte certless/Bearer de ingestão.
func (e *IngestExporter) PostTopology(ctx context.Context, report *collectorv1.TopologyReport) error {
	if report == nil || len(report.GetEdges()) == 0 {
		return nil
	}
	if collectorID, _ := e.collectorID.Load().(string); collectorID != "" && report.GetCollectorId() == "" {
		report.CollectorId = collectorID
	}
	body, err := protojson.Marshal(report)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "topology", "application/json", body)
}

// PostDeviceMetadata envia a identidade do device (metadata.device) pro gateway,
// que faz upsert no noc_device usando metadata.device.
func (e *IngestExporter) PostDeviceMetadata(ctx context.Context, hostID string, device map[string]string) error {
	if len(device) == 0 {
		return nil
	}
	payload := map[string]any{
		"host_id": hostID,
		"device":  device,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "device-metadata", "application/json", body)
}

// PostDeviceConfig envia a running-config coletada por SSH pro gateway (NCM),
// que sanitiza → versiona por hash em noc_device_config. v1 é SÓ LEITURA — o
// agente nunca reescreve o equipamento. host_id é o bigint do noc_host (string;
// o backend coage). vendor orienta a sanitização de linhas voláteis no backend.
func (e *IngestExporter) PostDeviceConfig(ctx context.Context, hostID, vendor, source, rawText, hostKey string) error {
	if rawText == "" {
		return nil
	}
	payload := map[string]any{
		"host_id":  hostID,
		"vendor":   vendor,
		"source":   source,
		"raw_text": rawText,
	}
	// TOFU: reporta a host key SSH observada pro backend fixar (só no 1º backup).
	if hostKey != "" {
		payload["host_key"] = hostKey
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "ncm/config", "application/json", body)
}

// RegisterK8sNode registra o nó no backend (POST /k8s/register, Bearer) →
// cria o noc_host + check k8s.kubelet (faz o nó aparecer em "Aplicações").
// Devolve o host_id (bigint como string) pra taggear as métricas de pod.
func (e *IngestExporter) RegisterK8sNode(ctx context.Context, cluster, node, nodeIP, k8sVersion string) (string, error) {
	payload := map[string]string{
		"cluster": cluster, "node": node, "node_ip": nodeIP, "k8s_version": k8sVersion,
		// Nó roda em container → machine-id do HOST (montado em /host), nunca o do
		// container. É o mesmo /etc/machine-id que o agente Linux do box lê → funde.
		"machine_id": machineID(true),
		// Versão do próprio agente — grava em noc_app_host.agent_version, base do
		// aviso de "desatualizado" na tela Servidores.
		"agent_version": e.version,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/k8s/register", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("k8s register: HTTP %d", resp.StatusCode)
	}
	var out struct {
		HostID json.Number `json:"host_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.HostID.String(), nil
}

// SetCollectorID guarda o UUID do noc_collector deste agente — todo POST
// subsequente leva o header X-Ispwatch-Collector (o gateway valida e usa
// pra carimbar o collector_id real nas self-metrics).
func (e *IngestExporter) SetCollectorID(id string) {
	if id = strings.TrimSpace(id); id != "" {
		e.collectorID.Store(id)
	}
}

// RegisterDockerHost registra a MÁQUINA docker no backend (POST /host/register,
// Bearer) → cria o noc_app_host (install_mode=docker) + check docker.host, e
// amarra o collector deste agente à máquina (self-metrics dela). Devolve o
// host_id (bigint como string) pra taggear as métricas de container.
//
// Princípio (David): a máquina é INVENTÁRIO/contexto — a aplicação segue
// identificada pelo serviço, nunca pela máquina.
func (e *IngestExporter) RegisterDockerHost(ctx context.Context, hostname, collectorID string) (string, error) {
	return e.registerHost(ctx, hostname, "docker", collectorID)
}

// RegisterLinuxHost registra a MÁQUINA Linux pura (systemd) no backend
// (install_mode=linux) → cria o noc_app_host + check linux.system. Mesmo
// contrato do RegisterDockerHost; muda só o modo. Idem princípio: a máquina é
// inventário/contexto; a aplicação segue identificada pelo serviço.
func (e *IngestExporter) RegisterLinuxHost(ctx context.Context, hostname, collectorID string) (string, error) {
	return e.registerHost(ctx, hostname, "linux", collectorID)
}

// machineID lê o id ESTÁVEL da máquina física (dedup por alias no backend: 2
// agentes no mesmo box → 1 máquina). No systemd (Linux direto no host) é o
// /etc/machine-id. Em CONTAINER (docker/k8s) o /etc/machine-id é o do container e
// fundiria nós diferentes por engano — então só vale o host montado em
// /host/etc/machine-id (o DaemonSet/compose monta read-only). Vazio se não achar:
// o backend degrada (host fica sozinho na lista), nunca funde errado.
func machineID(containerized bool) string {
	paths := []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
	if containerized {
		paths = []string{"/host/etc/machine-id"}
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	return ""
}

// registerHost é o corpo comum do POST /host/register (Bearer): cria/atualiza o
// noc_app_host da máquina no modo dado e devolve o host_id (bigint como string).
func (e *IngestExporter) registerHost(ctx context.Context, hostname, installMode, collectorID string) (string, error) {
	payload := map[string]string{
		"hostname": hostname, "install_mode": installMode, "collector_id": collectorID,
		// docker roda em container; linux (systemd) roda direto no host.
		"machine_id": machineID(installMode != "linux"),
		// Versão do próprio agente — grava em noc_app_host.agent_version, base do
		// aviso de "desatualizado" na tela Servidores.
		"agent_version": e.version,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/host/register", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("host register: HTTP %d", resp.StatusCode)
	}
	var out struct {
		HostID json.Number `json:"host_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.HostID.String(), nil
}

// RegisterCollector registra/atualiza o collector deste agente no backend
// (POST /collector/register, Bearer) → upsert em noc_collector por (tenant,
// name). Devolve o collector_id (UUID) + tenant, que o agente usa no
// config-pull (Bearer) pra puxar as checagens agendadas que o usuário criou.
func (e *IngestExporter) RegisterCollector(ctx context.Context, name string, capabilities []string, installMode string) (string, string, error) {
	if capabilities == nil {
		capabilities = []string{}
	}
	payload := map[string]any{
		"name":          name,
		"agent_version": e.version,
		"capabilities":  capabilities,
		"install_mode":  installMode,
	}
	if provider, ok := e.runtimeStatsProvider.Load().(func() CollectorRuntimeStats); ok {
		runtime := provider()
		queue := e.metricsPending.Snapshot()
		runtime.PendingPayloads = int64(queue.Pending)
		runtime.PendingBytes = int64(queue.Bytes)
		runtime.RetryAttempts = queue.RetryAttempts
		runtime.RetrySuccesses = queue.RetrySuccesses
		runtime.DroppedPayloads = queue.DroppedTotal
		runtime.IngestBlocked = queue.Blocked
		payload["runtime"] = runtime
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/collector/register", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := e.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("collector register: HTTP %d", resp.StatusCode)
	}
	var out struct {
		CollectorID string `json:"collector_id"`
		Tenant      string `json:"tenant"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	return out.CollectorID, out.Tenant, nil
}

func kv(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   k,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}},
	}
}
