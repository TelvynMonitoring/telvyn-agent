package selfmetrics

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/telvynmonitoring/telvyn-agent/internal/agentstats"
	"github.com/telvynmonitoring/telvyn-agent/internal/sendbuf"
	collectorv1 "github.com/telvynmonitoring/telvyn-agent/proto/v1"
)

// StartAgentStats emite, a cada interval, as filas de envio e o consumo do processo do
// próprio agent como métricas próprias (viram `agent_host_metric_agent_*` no backend,
// com o collector_id). É o histórico que a tela do agente desenha: o heartbeat só traz
// o valor de agora. As métricas passam pela mesma fila de envio; se o envio está parado,
// elas chegam depois, com o horário original, e mostram o trecho em que a fila travou.
func StartAgentStats(ctx context.Context, log *slog.Logger, out chan<- []*collectorv1.Metric, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	clog := log.With("component", "selfmetrics", "check", "agent.stats")
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			batch := agentStatsMetrics(time.Now())
			select {
			case out <- batch:
			default:
				clog.Warn("agent-stats out channel full, dropping batch", "count", len(batch))
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func agentStatsMetrics(now time.Time) []*collectorv1.Metric {
	ts := timestamppb.New(now)
	metric := func(name string, value float64, extra map[string]string) *collectorv1.Metric {
		tags := map[string]string{SelfTag: "true"}
		for k, v := range extra {
			tags[k] = v
		}
		return &collectorv1.Metric{Time: ts, HostId: "self", MetricName: name, Value: value, Tags: tags, Source: "agent.stats"}
	}
	var out []*collectorv1.Metric
	for _, q := range sendbuf.Queues() {
		tag := map[string]string{"queue": q.Name}
		blocked := 0.0
		if q.Blocked {
			blocked = 1
		}
		out = append(out,
			metric("agent.queue.pending_payloads", float64(q.Pending), tag),
			metric("agent.queue.pending_bytes", float64(q.Bytes), tag),
			metric("agent.queue.retry_attempts", float64(q.RetryAttempts), tag),
			metric("agent.queue.dropped_payloads", float64(q.DroppedTotal), tag),
			metric("agent.queue.blocked", blocked, tag),
		)
	}
	p := agentstats.Read(sendbuf.DefaultDir())
	out = append(out,
		metric("agent.process.goroutines", float64(p.Goroutines), nil),
		metric("agent.process.heap_bytes", float64(p.HeapAllocBytes), nil),
		metric("agent.process.sys_bytes", float64(p.SysBytes), nil),
		metric("agent.process.queue_disk_bytes", float64(p.QueueDiskBytes), nil),
	)
	if p.CPUSeconds != nil {
		out = append(out, metric("agent.process.cpu_seconds", *p.CPUSeconds, nil))
	}
	return out
}
