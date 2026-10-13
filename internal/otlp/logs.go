// logs.go — bridge journald → backend HTTP logs export.
//
// Pattern espelhado do Forwarder de spans (forwarder.go) só que:
//   • Não passa por gRPC StreamSpans — saída é direto via HTTP POST
//     pro endpoint /api/collector/v1/logs do Quarkus (porta 8444 mTLS).
//   • Payload é JSON simples (1 array de records). Optamos pra JSON sobre
//     OTLP/proto pra evitar pull de dep nova no backend Quarkus — o REST
//     resource consome direto via Jackson. Mantemos as semantics OTLP
//     (severity_number, body, attributes) e os field names canônicos.
//   • Batch send a cada 2s OU a cada 100 records, o que vier primeiro.
//
// WAL bbolt antes de liberar o leitor; retry mantém registros até confirmação.
// shortcut: entrega at-least-once; resposta perdida pode duplicar até existir deduplicação no intake.

package otlp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ispwatch/collector/internal/sendbuf"
)

const (
	// LogsBatchMaxRecords — max records por POST. Mantemos baixo (100) pra
	// evitar requests grandes; backend persiste por linha mesmo, então
	// não compensa empacotar 1000.
	LogsBatchMaxRecords = 100

	// LogsBatchFlushInterval — flush periódico mesmo com pouco volume,
	// pra UI ver logs com latência ≤ 2s.
	LogsBatchFlushInterval = 2 * time.Second

	// LogsRequestTimeout — request HTTP tem cap de 10s. Mais que isso é
	// problema de saúde do backend; o lote permanece no WAL para retry.
	LogsRequestTimeout = 10 * time.Second
)

// LogRecord é o shape interno que callers (journald reader) entregam ao
// LogsExporter. Conversão pra OTLP é feita dentro do Push em batch.
type LogRecord struct {
	TimestampUnixNano int64
	ServiceName       string            // mapeia pra Resource.attributes service.name
	Hostname          string            // host.name
	SeverityNumber    int               // OTel severity 1-24
	SeverityText      string            // "INFO" | "WARN" | "ERROR" | ...
	Body              string            // mensagem
	TraceID           string            // hex32, vazio se a linha não trouxe — liga o log ao trace
	SpanID            string            // hex16, vazio se ausente
	Attributes        map[string]string // attrs do log record
}

// LogsExporter agrega LogRecords, faz batch e POST OTLP pro backend.
// Single struct atomicamente safe; instanciado uma vez no main.
type LogsExporter struct {
	collectorID string
	endpoint    string // ex: https://quarkus:8444 (modo mTLS)
	tenantID    string
	httpClient  *http.Client
	log         *slog.Logger

	// ingest != nil ⇒ modo certless: em vez do POST mTLS pro
	// /api/collector/v1/logs, cada batch sai como OTLP JSON + Bearer pro
	// gateway /api/ingest/v1/logs. Toda a maquinaria de buffer/flush
	// é reusada — só o transporte do sendBatch muda.
	ingest *IngestExporter

	mu         sync.Mutex
	pending    *sendbuf.Queue
	retryAt    time.Time
	retryDelay time.Duration

	// Counters — drenados pelo publisher de self-metrics.
	linesTotal   atomic.Int64
	bytesTotal   atomic.Int64
	droppedTotal atomic.Int64
	sentBatches  atomic.Int64
	sendFailures atomic.Int64
}

// NewLogsExporter constrói o exporter. endpoint = https://host:port (sem
// path). certPath/keyPath/trustPath = mesmos paths do gRPC e config pull.
// Se algum path é vazio, ativa InsecureSkipVerify pra dev sem cert (o
// servidor com mTLS rejeita o handshake — caller verá no log).
func NewLogsExporter(endpoint, tenantID, collectorID string, certPath, keyPath, trustPath string, log *slog.Logger) (*LogsExporter, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if certPath != "" && keyPath != "" {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load client cert (%s, %s): %w", certPath, keyPath, err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	} else {
		tlsCfg.InsecureSkipVerify = true
	}
	if trustPath != "" {
		pem, err := os.ReadFile(trustPath)
		if err != nil {
			return nil, fmt.Errorf("read trust bundle %s: %w", trustPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("trust bundle %s contained no PEM certs", trustPath)
		}
		tlsCfg.RootCAs = pool
	}
	pending, err := sendbuf.NewDurable("logs", 64<<20, sendbuf.DefaultDir(), log)
	if err != nil {
		return nil, err
	}
	return &LogsExporter{
		pending:     pending,
		collectorID: collectorID,
		endpoint:    strings.TrimRight(endpoint, "/"),
		tenantID:    tenantID,
		httpClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			Timeout:   LogsRequestTimeout,
		},
		log: log.With("component", "otlp-logs"),
	}, nil
}

// NewIngestLogsExporter constrói um LogsExporter no modo certless: os batches
// são enviados via ingest.PostLogs (OTLP JSON + Bearer) em vez do canal mTLS.
// Reusa Push/Run/flush/Stats do exporter mTLS.
func NewIngestLogsExporter(ingest *IngestExporter, log *slog.Logger) (*LogsExporter, error) {
	pending, err := sendbuf.NewDurable("logs", 64<<20, sendbuf.DefaultDir(), log)
	if err != nil {
		return nil, err
	}
	return &LogsExporter{
		pending:    pending,
		ingest:     ingest,
		httpClient: &http.Client{Timeout: LogsRequestTimeout},
		log:        log.With("component", "otlp-logs-ingest"),
	}, nil
}

type pendingLog struct {
	Record      *LogRecord `json:"record,omitempty"`
	ContentType string     `json:"content_type,omitempty"`
	Body        []byte     `json:"body,omitempty"`
}

// EnqueueRaw confirma ao SDK somente depois de persistir; fila cheia devolve erro ao receiver.
func (e *LogsExporter) EnqueueRaw(contentType string, body []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	payload, err := json.Marshal(pendingLog{ContentType: contentType, Body: body})
	if err != nil {
		return err
	}
	return e.pending.OfferDurable(payload)
}

// Push persiste antes de liberar o leitor e seu cursor. Disco cheio pausa a leitura.
func (e *LogsExporter) Push(rec LogRecord) {
	e.mu.Lock()
	defer e.mu.Unlock()
	body, err := json.Marshal(pendingLog{Record: &rec})
	if err != nil {
		panic(err)
	} // LogRecord contém apenas tipos JSON serializáveis.
	var lastWarning time.Time
	for {
		if err := e.pending.OfferDurable(body); err == nil {
			break
		} else if time.Since(lastWarning) >= time.Minute {
			e.log.Error("logs WAL indisponível ou cheio; leitura aguardando espaço", "err", err)
			lastWarning = time.Now()
		}
		e.flushLocked(context.Background())
		time.Sleep(LogsBatchFlushInterval)
	}
	e.linesTotal.Add(1)
	e.bytesTotal.Add(int64(len(rec.Body)))
	if e.pending.Snapshot().Pending >= LogsBatchMaxRecords {
		e.flushLocked(context.Background())
	}
}

// Run também reenvia o WAL recuperado, mesmo sem novas linhas na origem.
func (e *LogsExporter) Run(ctx context.Context) {
	ticker := time.NewTicker(LogsBatchFlushInterval)
	defer ticker.Stop()
	e.flush(ctx)
	for {
		select {
		case <-ctx.Done():
			return // registros já persistidos serão retomados no próximo processo.
		case <-ticker.C:
			e.flush(ctx)
		}
	}
}

func (e *LogsExporter) flush(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flushLocked(ctx)
}

func (e *LogsExporter) flushLocked(ctx context.Context) {
	if time.Now().Before(e.retryAt) {
		return
	}
	recovering := e.retryDelay > 0
	// Limita cada ciclo para não monopolizar os leitores durante a recuperação.
	ctx, cancel := context.WithTimeout(ctx, LogsRequestTimeout)
	defer cancel()
	err := e.pending.FlushBatch(ctx, LogsBatchMaxRecords, func(ctx context.Context, bodies [][]byte) error {
		var records []LogRecord
		sendRecords := func() error {
			if len(records) == 0 {
				return nil
			}
			if err := e.sendBatch(ctx, records); err != nil {
				return err
			}
			e.sentBatches.Add(1)
			records = nil
			return nil
		}
		for _, body := range bodies {
			var item pendingLog
			if err := json.Unmarshal(body, &item); err != nil {
				return err
			}
			if item.Record != nil {
				records = append(records, *item.Record)
				continue
			}
			if err := sendRecords(); err != nil {
				return err
			}
			if e.ingest == nil || !e.ingest.signalAllowed("logs") {
				return fmt.Errorf("logs intake indisponível; WAL preservado")
			}
			if err := e.ingest.PostRaw(ctx, "logs", item.ContentType, item.Body); err != nil {
				return err
			}
			e.sentBatches.Add(1)
		}
		return sendRecords()
	})
	if err != nil {
		e.sendFailures.Add(1)
		if e.retryDelay == 0 {
			e.retryDelay = LogsBatchFlushInterval
		} else {
			e.retryDelay *= 2
		}
		if e.retryDelay > 30*time.Second {
			e.retryDelay = 30 * time.Second
		}
		e.retryAt = time.Now().Add(e.retryDelay)
		e.log.Warn("logs retidos no WAL; envio será repetido", "pending", e.pending.Snapshot().Pending, "retry_in", e.retryDelay, "err", err)
		return
	}
	if recovering {
		e.log.Info("logs WAL recuperado; fila entregue")
	}
	e.retryDelay = 0
	e.retryAt = time.Time{}
}

// logBatchWire é o shape JSON enviado em cada POST. Campos espelham OTLP
// LogRecord sem o overhead protobuf — backend Quarkus parseia via Jackson
// sem deps OTel extras. Quando precisarmos full OTLP (clientes 3rd party
// mandando ExportLogsServiceRequest), trocar pra OTLP proto sem mudar a
// rota: este é só o canal interno agent→backend.
type logBatchWire struct {
	CollectorID string          `json:"collector_id"`
	Hostname    string          `json:"hostname"`
	Records     []logRecordWire `json:"records"`
}

type logRecordWire struct {
	TimeUnixNano   int64             `json:"time_unix_nano"`
	ServiceName    string            `json:"service_name"`
	SeverityNumber int               `json:"severity_number"`
	SeverityText   string            `json:"severity_text"`
	Body           string            `json:"body"`
	TraceID        string            `json:"trace_id,omitempty"`
	SpanID         string            `json:"span_id,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

// sendBatch monta o JSON batch e POSTa.
func (e *LogsExporter) sendBatch(ctx context.Context, batch []LogRecord) error {
	if e.ingest != nil {
		if !e.ingest.signalAllowed("logs") {
			return fmt.Errorf("logs desabilitados pela política; WAL preservado")
		}
		return e.ingest.PostLogs(ctx, batch)
	}
	if e.endpoint == "" {
		return fmt.Errorf("logs exporter endpoint not configured")
	}
	wire := logBatchWire{
		CollectorID: e.collectorID,
		Records:     make([]logRecordWire, 0, len(batch)),
	}
	for _, r := range batch {
		if wire.Hostname == "" && r.Hostname != "" {
			wire.Hostname = r.Hostname
		}
		wire.Records = append(wire.Records, logRecordWire{
			TimeUnixNano:   r.TimestampUnixNano,
			ServiceName:    r.ServiceName,
			SeverityNumber: r.SeverityNumber,
			SeverityText:   r.SeverityText,
			Body:           r.Body,
			TraceID:        r.TraceID,
			SpanID:         r.SpanID,
			Attributes:     r.Attributes,
		})
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return fmt.Errorf("marshal logs request: %w", err)
	}

	// Endpoint: /api/collector/v1/logs (com query params do mTLS filter).
	url := fmt.Sprintf("%s/api/collector/v1/logs?tenant_id=%s&collector_id=%s",
		e.endpoint, e.tenantID, e.collectorID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("backend %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// LogsStats — snapshot consumido pelo publisher de self-metrics.
type LogsStats struct {
	LinesTotal   int64
	BytesTotal   int64
	DroppedTotal int64
	SentBatches  int64
	SendFailures int64
}

func (e *LogsExporter) Stats() LogsStats {
	return LogsStats{
		LinesTotal:   e.linesTotal.Load(),
		BytesTotal:   e.bytesTotal.Load(),
		DroppedTotal: e.droppedTotal.Load(),
		SentBatches:  e.sentBatches.Load(),
		SendFailures: e.sendFailures.Load(),
	}
}
