// Package sendbuf — retenção limitada por bytes de payloads que falharam no
// envio pro gateway certless, pra reenviar no próximo tick ou após restart.
//
// Por que existe: o modo mTLS tem WAL em disco, mas o modo ingest não tinha
// NADA — backend fora do ar (rollout, rede) descartava o bucket de apm_stats e
// as métricas do intervalo. A fila agora usa bbolt quando o agent está no modo
// instalado; queda longa degrada com drop-oldest dentro do teto de bytes — nunca
// cresce sem limite. O restart conserva os payloads ainda não confirmados.
//
// Também dá tratamento honesto a duas falhas que retry NÃO conserta:
//   - 401/403: token de ingest inválido/revogado → descarta, entra em
//     cool-down e loga ERRO claro (rate-limited) apontando o env var;
//   - 429: franquia de telemetria do plano estourada → descarta, cool-down
//     maior e aviso claro (o backend corta por 7 dias rolantes — martelar
//     não ajuda).
package sendbuf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// StatusError marca falha HTTP com o código — deixa a fila distinguir
// problema de rede (retém) de auth/franquia (descarta com aviso).
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d", e.Code) }

const (
	authCooldown   = 1 * time.Minute
	budgetCooldown = 5 * time.Minute
	logInterval    = 1 * time.Minute
)

var (
	payloadsBucket = []byte("payloads")
	metaBucket     = []byte("meta")
	metaNext       = []byte("next")
	metaCount      = []byte("count")
	metaBytes      = []byte("bytes")
	metaRetained   = []byte("retained")
	metaRetries    = []byte("retries")
	metaRetryOK    = []byte("retry_ok")
	metaDropped    = []byte("dropped")
)

// Queue é o outbox de UM tipo de payload (ex.: apm-stats). Uso: chame Offer
// antes do POST e depois Flush com a função que transmite o item mais antigo.
type Queue struct {
	mu          sync.Mutex
	name        string
	maxBytes    int
	items       [][]byte
	bytes       int
	blockedTil  time.Time
	lastAuthLog time.Time
	log         *slog.Logger
	retained    int64
	retryCalls  int64
	retryOK     int64
	dropped     int64
	// unflushedOffers counts payloads added by the current send cycle. They
	// must not be reported as retries: new payloads are queued before the POST
	// so a process restart during the request cannot lose them.
	unflushedOffers int
	db              *bolt.DB
}

// Stats é um snapshot lock-safe usado no heartbeat operacional do collector.
// Não contém corpo de payload nem informação sensível.
type Stats struct {
	Pending        int
	Bytes          int
	RetainedTotal  int64
	RetryAttempts  int64
	RetrySuccesses int64
	DroppedTotal   int64
	Blocked        bool
}

// New cria a fila. maxBytes limita a soma dos payloads retidos (drop-oldest).
func New(name string, maxBytes int, log *slog.Logger) *Queue {
	if log == nil {
		log = slog.Default()
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	return &Queue{name: name, maxBytes: maxBytes, log: log.With("sendbuf", name)}
}

// NewPersistent creates a durable queue in dir. If the path cannot be opened,
// the agent keeps running with the previous in-memory behavior but emits an
// explicit error so the operator knows restart retention is degraded.
func NewPersistent(name string, maxBytes int, dir string, log *slog.Logger) *Queue {
	q := New(name, maxBytes, log)
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return q
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		q.log.Error("fila durável indisponível; usando memória", "dir", dir, "err", err)
		return q
	}
	path := filepath.Join(dir, safeName(name)+".bolt")
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		q.log.Error("não foi possível abrir fila durável; usando memória", "path", path, "err", err)
		return q
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(payloadsBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(metaBucket)
		return err
	}); err != nil {
		_ = db.Close()
		q.log.Error("não foi possível inicializar fila durável; usando memória", "path", path, "err", err)
		return q
	}
	q.db = db
	q.log.Info("fila durável habilitada", "path", path, "limite_bytes", maxBytes)
	return q
}

// DefaultDir resolves the agent state directory. The systemd installer and
// Helm chart set ISPWATCH_STATE_DIR explicitly; the Linux fallback also keeps
// manual binary executions durable.
func DefaultDir() string {
	if dir := strings.TrimSpace(os.Getenv("ISPWATCH_STATE_DIR")); dir != "" {
		return filepath.Join(dir, "sendbuf")
	}
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/var/lib/ispwatch/sendbuf"
}

// Close closes the durable queue. Normal process shutdown does not need to
// call it, but it is useful for controlled shutdowns and tests.
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.db == nil {
		return nil
	}
	err := q.db.Close()
	q.db = nil
	return err
}

func safeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "queue"
	}
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func u64(value uint64) []byte {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, value)
	return key
}

func readMeta(bucket *bolt.Bucket, key []byte) uint64 {
	value := bucket.Get(key)
	if len(value) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(value)
}

func writeMeta(bucket *bolt.Bucket, key []byte, value uint64) error {
	return bucket.Put(key, u64(value))
}

// Blocked = cool-down ativo (token inválido ou franquia estourada); enviar
// agora só repetiria o erro.
func (q *Queue) Blocked() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return time.Now().Before(q.blockedTil)
}

// Flush reenvia o retido (mais antigo primeiro) até esvaziar ou falhar de
// novo. Falha de auth/franquia no meio do flush descarta o item e ativa o
// cool-down (os demais ficam pra próxima janela válida).
func (q *Queue) Flush(ctx context.Context, post func(context.Context, []byte) error) error {
	if q.Blocked() {
		return nil
	}
	// Capture the queue state atomically with the offer marker. Anything that
	// was already pending before this cycle is a real retry; the offers made by
	// the current cycle are ordinary sends and should not produce a retry log.
	q.mu.Lock()
	unflushedOffers := q.unflushedOffers
	q.unflushedOffers = 0
	initialPending := q.pendingLocked()
	q.mu.Unlock()
	retainedToLog := initialPending - unflushedOffers
	if retainedToLog < 0 {
		retainedToLog = 0
	}
	retainedLogged := 0
	for {
		body, ok := q.peek()
		if !ok {
			return nil
		}
		q.incrementRetry()

		if err := post(ctx, body); err != nil {
			if q.noteTerminal(err) {
				q.popFront(true) // auth/franquia: reenviar não conserta
			}
			return err
		}
		q.incrementRetrySuccess()
		q.popFront(false)
		if retainedLogged < retainedToLog {
			q.log.Info("payload retido reenviado com sucesso", "restantes", q.pending())
			retainedLogged++
		}
	}
}

// Offer coloca um payload no outbox. err é usado para classificar chamadas
// legadas que já falharam: auth/franquia → descarta; demais → retém. Chamadas
// novas passam nil e enfileiram antes do POST, garantindo sobrevivência a
// restart mesmo quando a queda acontece durante a requisição.
func (q *Queue) Offer(body []byte, err error) error {
	if q.noteTerminal(err) {
		q.mu.Lock()
		q.incrementDroppedLocked()
		q.mu.Unlock()
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.db != nil {
		return q.offerPersistentLocked(body)
	}
	q.items = append(q.items, body)
	q.unflushedOffers++
	q.bytes += len(body)
	q.retained++
	dropped := 0
	for q.bytes > q.maxBytes && len(q.items) > 1 {
		q.bytes -= len(q.items[0])
		q.items = q.items[1:]
		dropped++
	}
	if dropped > 0 {
		q.dropped += int64(dropped)
		q.log.Warn("fila de reenvio cheia — payloads mais antigos descartados",
			"descartados", dropped, "retidos", len(q.items), "bytes", q.bytes)
	} else {
		q.log.Debug("payload enfileirado no outbox",
			"retidos", len(q.items), "bytes", q.bytes)
	}
	return nil
}

// Snapshot devolve os contadores cumulativos e o tamanho atual da fila.
func (q *Queue) Snapshot() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.db != nil {
		return q.snapshotPersistentLocked()
	}
	return Stats{
		Pending:        len(q.items),
		Bytes:          q.bytes,
		RetainedTotal:  q.retained,
		RetryAttempts:  q.retryCalls,
		RetrySuccesses: q.retryOK,
		DroppedTotal:   q.dropped,
		Blocked:        time.Now().Before(q.blockedTil),
	}
}

func (q *Queue) peek() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.db == nil {
		if len(q.items) == 0 {
			return nil, false
		}
		return append([]byte(nil), q.items[0]...), true
	}

	var body []byte
	err := q.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(payloadsBucket)
		if bucket == nil {
			return fmt.Errorf("payload bucket ausente")
		}
		_, value := bucket.Cursor().First()
		if value != nil {
			body = append([]byte(nil), value...)
		}
		return nil
	})
	if err != nil {
		q.log.Error("falha ao ler fila durável", "err", err)
		return nil, false
	}
	return body, body != nil
}

func (q *Queue) pending() int {
	return q.Snapshot().Pending
}

func (q *Queue) pendingLocked() int {
	if q.db == nil {
		return len(q.items)
	}
	var pending uint64
	err := q.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		if meta == nil {
			return fmt.Errorf("meta bucket ausente")
		}
		pending = readMeta(meta, metaCount)
		return nil
	})
	if err != nil {
		q.log.Error("falha ao contar fila durável", "err", err)
		return 0
	}
	return int(pending)
}

func (q *Queue) incrementRetry() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.db == nil {
		q.retryCalls++
		return
	}
	q.updateCounterLocked(metaRetries)
}

func (q *Queue) incrementRetrySuccess() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.db == nil {
		q.retryOK++
		return
	}
	q.updateCounterLocked(metaRetryOK)
}

func (q *Queue) updateCounterLocked(key []byte) {
	err := q.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		if meta == nil {
			return fmt.Errorf("meta bucket ausente")
		}
		return writeMeta(meta, key, readMeta(meta, key)+1)
	})
	if err != nil {
		q.log.Error("falha ao atualizar contador da fila durável", "err", err)
	}
}

func (q *Queue) incrementDroppedLocked() {
	if q.db == nil {
		q.dropped++
		return
	}
	q.updateCounterLocked(metaDropped)
}

func (q *Queue) snapshotPersistentLocked() Stats {
	stats := Stats{Blocked: time.Now().Before(q.blockedTil)}
	err := q.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		if meta == nil {
			return fmt.Errorf("meta bucket ausente")
		}
		stats.Pending = int(readMeta(meta, metaCount))
		stats.Bytes = int(readMeta(meta, metaBytes))
		stats.RetainedTotal = int64(readMeta(meta, metaRetained))
		stats.RetryAttempts = int64(readMeta(meta, metaRetries))
		stats.RetrySuccesses = int64(readMeta(meta, metaRetryOK))
		stats.DroppedTotal = int64(readMeta(meta, metaDropped))
		return nil
	})
	if err != nil {
		q.log.Error("falha ao ler estatísticas da fila durável", "err", err)
	}
	return stats
}

func (q *Queue) offerPersistentLocked(body []byte) error {
	droppedCount := uint64(0)
	err := q.db.Update(func(tx *bolt.Tx) error {
		payloads := tx.Bucket(payloadsBucket)
		meta := tx.Bucket(metaBucket)
		if payloads == nil || meta == nil {
			return fmt.Errorf("buckets da fila ausentes")
		}
		next := readMeta(meta, metaNext)
		if err := payloads.Put(u64(next), body); err != nil {
			return err
		}
		if err := writeMeta(meta, metaNext, next+1); err != nil {
			return err
		}
		bytes := readMeta(meta, metaBytes) + uint64(len(body))
		count := readMeta(meta, metaCount) + 1
		retained := readMeta(meta, metaRetained) + 1
		dropped := uint64(0)
		for bytes > uint64(q.maxBytes) && count > 1 {
			key, value := payloads.Cursor().First()
			if key == nil {
				break
			}
			if err := payloads.Delete(key); err != nil {
				return err
			}
			bytes -= uint64(len(value))
			count--
			dropped++
		}
		droppedCount = dropped
		if err := writeMeta(meta, metaBytes, bytes); err != nil {
			return err
		}
		if err := writeMeta(meta, metaCount, count); err != nil {
			return err
		}
		if err := writeMeta(meta, metaRetained, retained); err != nil {
			return err
		}
		return writeMeta(meta, metaDropped, readMeta(meta, metaDropped)+dropped)
	})
	if err != nil {
		q.log.Error("falha ao persistir payload na fila durável", "err", err)
		return err
	}
	q.unflushedOffers++
	stats := q.snapshotPersistentLocked()
	if droppedCount > 0 {
		q.log.Warn("fila de reenvio cheia — payloads mais antigos descartados",
			"descartados", droppedCount, "retidos", stats.Pending, "bytes", stats.Bytes)
	} else {
		q.log.Debug("payload enfileirado no outbox",
			"retidos", stats.Pending, "bytes", stats.Bytes)
	}
	return nil
}

// NoteAuthFailure permite a caminhos sem retenção (ex.: PostRaw de sinais de
// banco) registrarem respostas terminais. Apenas 401 bloqueia a fila inteira:
// 403 pode ser uma rejeição de escopo ou identidade de um único sinal e não
// significa que a credencial compartilhada foi revogada.
func (q *Queue) NoteAuthFailure(code int) {
	q.noteTerminal(&StatusError{Code: code})
}

// noteTerminal devolve true quando o payload atual não deve ser reenviado.
// Falhas realmente globais (401/franquia) ativam o cool-down compartilhado;
// uma rejeição 403 descarta somente o payload recusado.
func (q *Queue) noteTerminal(err error) bool {
	var se *StatusError
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code {
	case 401:
		q.mu.Lock()
		q.blockedTil = time.Now().Add(authCooldown)
		shouldLog := time.Since(q.lastAuthLog) >= logInterval
		if shouldLog {
			q.lastAuthLog = time.Now()
		}
		q.mu.Unlock()
		if shouldLog {
			q.log.Error("token de ingest INVÁLIDO ou REVOGADO — telemetria sendo descartada; "+
				"verifique ISPWATCH_INGEST_TOKEN (gere outro em Monitores → instalar agent)",
				"status", se.Code)
		}
		return true
	case 403:
		q.mu.Lock()
		shouldLog := time.Since(q.lastAuthLog) >= logInterval
		if shouldLog {
			q.lastAuthLog = time.Now()
		}
		q.mu.Unlock()
		if shouldLog {
			q.log.Warn("payload de telemetria recusado pelo backend — verifique o escopo e a identidade do sinal",
				"status", se.Code)
		}
		return true
	case 429:
		q.mu.Lock()
		q.blockedTil = time.Now().Add(budgetCooldown)
		shouldLog := time.Since(q.lastAuthLog) >= logInterval
		if shouldLog {
			q.lastAuthLog = time.Now()
		}
		q.mu.Unlock()
		if shouldLog {
			q.log.Warn("franquia de telemetria do plano EXCEDIDA (HTTP 429) — dados descartados " +
				"até a janela de 7 dias rolar ou o plano subir de tier")
		}
		return true
	}
	return false
}

func (q *Queue) popFront(dropped bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.db != nil {
		err := q.db.Update(func(tx *bolt.Tx) error {
			payloads := tx.Bucket(payloadsBucket)
			meta := tx.Bucket(metaBucket)
			if payloads == nil || meta == nil {
				return fmt.Errorf("buckets da fila ausentes")
			}
			key, value := payloads.Cursor().First()
			if key == nil {
				return nil
			}
			if err := payloads.Delete(key); err != nil {
				return err
			}
			bytes := readMeta(meta, metaBytes)
			if size := uint64(len(value)); size >= bytes {
				bytes = 0
			} else {
				bytes -= uint64(len(value))
			}
			count := readMeta(meta, metaCount)
			if count > 0 {
				count--
			}
			if err := writeMeta(meta, metaBytes, bytes); err != nil {
				return err
			}
			if err := writeMeta(meta, metaCount, count); err != nil {
				return err
			}
			if dropped {
				return writeMeta(meta, metaDropped, readMeta(meta, metaDropped)+1)
			}
			return nil
		})
		if err != nil {
			q.log.Error("falha ao remover payload da fila durável", "err", err)
		}
		return
	}
	if len(q.items) == 0 {
		return
	}
	if dropped {
		q.dropped++
	}
	q.bytes -= len(q.items[0])
	q.items = q.items[1:]
}
