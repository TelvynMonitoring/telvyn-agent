package sendbuf

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// maxDeliveryErrorLen limita o texto do último erro de envio que vai no heartbeat.
const maxDeliveryErrorLen = 200

// Delivery descreve a saúde do ENVIO de uma fila: quando deu certo pela última vez e,
// se está falhando, desde quando e por quê. Não contém corpo de payload nem segredo:
// o erro vem do cliente HTTP (DNS, conexão, timeout, código HTTP) e é truncado.
type Delivery struct {
	LastError     string
	LastErrorAt   time.Time
	FailingSince  time.Time
	LastSuccessAt time.Time
}

// NamedStats é o retrato de uma fila para o heartbeat e para as métricas do agent.
type NamedStats struct {
	Name string
	Stats
	Delivery
}

var registry sync.Map // nome → *Queue

// register torna a fila visível em Queues. Duas filas com o mesmo nome (reinício em
// processo, testes) ficam com a mais recente.
func register(q *Queue) { registry.Store(q.name, q) }

// Queues devolve o retrato de todas as filas abertas, ordenado por nome. Nunca bloqueia
// em um envio em andamento: uma fila ocupada devolve o último retrato conhecido.
func Queues() []NamedStats {
	var out []NamedStats
	registry.Range(func(_, value any) bool {
		q := value.(*Queue)
		out = append(out, NamedStats{Name: q.name, Stats: q.snapshotNoWait(), Delivery: q.Delivery()})
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Delivery devolve o estado do último envio da fila.
func (q *Queue) Delivery() Delivery {
	q.dmu.Lock()
	defer q.dmu.Unlock()
	return q.delivery
}

// recordDelivery anota o resultado de um POST da fila. Sucesso encerra a falha corrente;
// o primeiro erro depois de um sucesso marca o começo da falha.
func (q *Queue) recordDelivery(err error) {
	now := time.Now()
	q.dmu.Lock()
	defer q.dmu.Unlock()
	if err == nil {
		q.delivery.LastSuccessAt = now
		q.delivery.FailingSince = time.Time{}
		return
	}
	if q.delivery.FailingSince.IsZero() {
		q.delivery.FailingSince = now
	}
	q.delivery.LastErrorAt = now
	q.delivery.LastError = truncateError(err.Error())
}

func truncateError(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > maxDeliveryErrorLen {
		return message[:maxDeliveryErrorLen]
	}
	return message
}

// snapshotNoWait é Snapshot sem esperar o lock da fila: FlushBatch segura o lock durante
// o POST, e o heartbeat não pode ficar preso atrás de um envio lento.
func (q *Queue) snapshotNoWait() Stats {
	if !q.mu.TryLock() {
		q.dmu.Lock()
		defer q.dmu.Unlock()
		return q.lastStats
	}
	var stats Stats
	if q.db != nil {
		stats = q.snapshotPersistentLocked()
	} else {
		stats = Stats{
			Pending:        len(q.items),
			Bytes:          q.bytes,
			RetainedTotal:  q.retained,
			RetryAttempts:  q.retryCalls,
			RetrySuccesses: q.retryOK,
			DroppedTotal:   q.dropped,
			Blocked:        time.Now().Before(q.blockedTil),
		}
	}
	q.mu.Unlock()
	q.dmu.Lock()
	q.lastStats = stats
	q.dmu.Unlock()
	return stats
}
