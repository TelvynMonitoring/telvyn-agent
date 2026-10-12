// icmp_rtt.go — RTT medido com relógio monotônico do agente.
//
// O pro-bing (v0.8.0) grava o instante de envio DENTRO do payload como
// UnixNano (relógio de parede) e calcula Rtt = chegada - instante_decodificado.
// A serialização descarta a leitura monotônica do Go, então um ajuste do
// relógio do sistema (NTP, sync de VM) entre envio e resposta entra inteiro
// no RTT: observamos -10507 ms e +10720 ms em produção de laboratório.
//
// Aqui o envio é anotado por número de sequência em OnSend e o RTT sai de
// time.Since na resposta — time.Now() carrega leitura monotônica, imune a
// saltos de relógio. A perda continua vindo das estatísticas do pinger
// (contagem de pacotes, não depende de relógio).
package checks

import (
	"math"
	"sync"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// rttTracker coleta RTTs monotônicos de um pinger. OnSend e OnRecv rodam em
// goroutines diferentes do pro-bing, por isso o mutex.
type rttTracker struct {
	mu   sync.Mutex
	now  func() time.Time
	sent map[int]time.Time
	rtts []time.Duration
}

func newRTTTracker() *rttTracker {
	return &rttTracker{now: time.Now, sent: make(map[int]time.Time)}
}

// attach liga o tracker aos callbacks do pinger. Duplicatas não chamam OnRecv
// (o pro-bing usa OnDuplicateRecv), então cada sequência conta uma vez.
func (t *rttTracker) attach(p *probing.Pinger) {
	p.OnSend = func(pkt *probing.Packet) { t.onSend(pkt.Seq) }
	p.OnRecv = func(pkt *probing.Packet) { t.onRecv(pkt.Seq) }
}

func (t *rttTracker) onSend(seq int) {
	t.mu.Lock()
	t.sent[seq] = t.now()
	t.mu.Unlock()
}

func (t *rttTracker) onRecv(seq int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	sentAt, ok := t.sent[seq]
	if !ok {
		return // resposta sem envio conhecido: não inventa RTT
	}
	delete(t.sent, seq)
	rtt := t.now().Sub(sentAt)
	if rtt < 0 {
		return // impossível com leitura monotônica; defesa contra relógio injetado
	}
	t.rtts = append(t.rtts, rtt)
}

// rttSummary são as mesmas estatísticas que o pro-bing expunha.
type rttSummary struct {
	min, max, avg, stdDev time.Duration
	count                 int
}

// summary calcula min/max/média e desvio padrão populacional (mesma fórmula
// do pro-bing, para não mudar a semântica de icmp.rtt_stddev_ms).
func (t *rttTracker) summary() rttSummary {
	t.mu.Lock()
	defer t.mu.Unlock()
	return summarizeRTTs(t.rtts)
}

func summarizeRTTs(rtts []time.Duration) rttSummary {
	if len(rtts) == 0 {
		return rttSummary{}
	}
	s := rttSummary{min: rtts[0], max: rtts[0], count: len(rtts)}
	var sum float64
	for _, r := range rtts {
		if r < s.min {
			s.min = r
		}
		if r > s.max {
			s.max = r
		}
		sum += float64(r)
	}
	mean := sum / float64(len(rtts))
	var sq float64
	for _, r := range rtts {
		d := float64(r) - mean
		sq += d * d
	}
	s.avg = time.Duration(mean)
	s.stdDev = time.Duration(math.Sqrt(sq / float64(len(rtts))))
	return s
}
