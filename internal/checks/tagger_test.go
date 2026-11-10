package checks

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/telvynmonitoring/telvyn-agent/proto/v1"
)

// mkMetric constrói uma Metric simples para os testes do tagger.
func mkMetric(host, name string, tags map[string]string) *collectorv1.Metric {
	return &collectorv1.Metric{
		Time:       timestamppb.Now(),
		HostId:     host,
		MetricName: name,
		Value:      1.0,
		Tags:       tags,
		Source:     "test",
	}
}

// TestTagger_Filter_UnderBudget garante que Filter passa todas as métricas
// quando a quantidade de séries únicas por host está dentro do budget.
func TestTagger_Filter_UnderBudget(t *testing.T) {
	tg := NewTagger(3, slog.Default())

	in := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth1"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth2"}),
	}
	kept, drops := tg.Filter(in)
	if len(kept) != 3 {
		t.Errorf("kept: want 3, got %d", len(kept))
	}
	if len(drops) != 0 {
		t.Errorf("drops: want 0, got %d", len(drops))
	}
}

// TestTagger_Filter_OverBudget_DropsExcedente verifica que séries acima do
// budget são dropadas e geram meta-métrica telvyn.tagger.dropped.
func TestTagger_Filter_OverBudget_DropsExcedente(t *testing.T) {
	tg := NewTagger(3, slog.Default())

	// Primeiro lote enche o budget.
	first := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth1"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth2"}),
	}
	if kept, _ := tg.Filter(first); len(kept) != 3 {
		t.Fatalf("setup: expected 3 kept, got %d", len(kept))
	}

	// Quarta série deve ser dropada.
	second := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth3"}),
	}
	kept, drops := tg.Filter(second)
	if len(kept) != 0 {
		t.Errorf("kept: want 0, got %d", len(kept))
	}
	drops = onlyDropped(drops)
	if len(drops) != 1 {
		t.Fatalf("drops: want 1, got %d", len(drops))
	}
	d := drops[0]
	if d.GetMetricName() != "telvyn.tagger.dropped" {
		t.Errorf("drop metric name: want telvyn.tagger.dropped, got %q", d.GetMetricName())
	}
	if d.GetTags()["host"] != "hostA" {
		t.Errorf("drop tag host: want hostA, got %q", d.GetTags()["host"])
	}
	if d.GetTags()["metric"] != "snmp.iface.in" {
		t.Errorf("drop tag metric: want snmp.iface.in, got %q", d.GetTags()["metric"])
	}
}

// TestTagger_Filter_RepeatSerie_NaoIncrementaCardinality verifica que repetir
// uma série existente não consome novo slot e ainda atualiza lastSeen.
func TestTagger_Filter_RepeatSerie_NaoIncrementaCardinality(t *testing.T) {
	tg := NewTagger(2, slog.Default())

	in := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth1"}),
	}
	if kept, _ := tg.Filter(in); len(kept) != 2 {
		t.Fatalf("setup: expected 2 kept, got %d", len(kept))
	}

	// Repete eth0 — deve passar sem drop e sem ocupar novo slot.
	repeat := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
	}
	kept, drops := tg.Filter(repeat)
	if len(kept) != 1 || len(drops) != 0 {
		t.Errorf("repeat: kept=%d drops=%d, want 1/0", len(kept), len(drops))
	}

	// Como cardinality continua em 2 (e budget=2), uma série nova deve dropar.
	nova := []*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth9"}),
	}
	_, drops = tg.Filter(nova)
	drops = onlyDropped(drops)
	if len(drops) != 1 {
		t.Errorf("nova depois de repeat: drops=%d, want 1", len(drops))
	}
}

// TestTagger_Filter_BudgetPorHost_IsolaHosts verifica que budgets são contados
// por host — encher hostA não afeta hostB.
func TestTagger_Filter_BudgetPorHost_IsolaHosts(t *testing.T) {
	tg := NewTagger(1, slog.Default())

	// Enche hostA.
	if kept, _ := tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
	}); len(kept) != 1 {
		t.Fatalf("setup hostA: kept=%d, want 1", len(kept))
	}

	// hostB deve passar mesmo com hostA cheio.
	kept, drops := tg.Filter([]*collectorv1.Metric{
		mkMetric("hostB", "snmp.iface.in", map[string]string{"iface": "eth0"}),
	})
	if len(kept) != 1 || len(drops) != 0 {
		t.Errorf("hostB: kept=%d drops=%d, want 1/0", len(kept), len(drops))
	}
}

// TestTagger_Filter_MetaMetric_FastPath verifica que meta-métricas
// (telvyn.tagger.* e telvyn.check.*) bypassam o budget — Pitfall 4.
func TestTagger_Filter_MetaMetric_FastPath(t *testing.T) {
	tg := NewTagger(1, slog.Default())

	// Enche o budget de hostA com uma série regular.
	tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
	})

	// Meta-métricas devem passar mesmo com budget cheio.
	in := []*collectorv1.Metric{
		mkMetric("hostA", "telvyn.tagger.dropped", map[string]string{"metric": "x"}),
		mkMetric("hostA", "telvyn.check.errors", map[string]string{"check_id": "y"}),
	}
	kept, drops := tg.Filter(in)
	if len(kept) != 2 {
		t.Errorf("fast-path: kept=%d, want 2", len(kept))
	}
	if len(drops) != 0 {
		t.Errorf("fast-path: drops=%d, want 0", len(drops))
	}
}

// TestTagger_Filter_LazyGC_RemoveEntriesStale verifica que séries não vistas
// há mais que a janela (24h) são purgadas quando o budget aperta.
func TestTagger_Filter_LazyGC_RemoveEntriesStale(t *testing.T) {
	tg := NewTagger(2, slog.Default())

	// Enche o budget.
	tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth1"}),
	})

	// Marca eth0 como stale (> 24h atrás) para forçar GC.
	tg.mu.Lock()
	for k := range tg.seen["hostA"] {
		if strings.Contains(k, "eth0") {
			tg.seen["hostA"][k] = time.Now().Add(-25 * time.Hour)
		}
	}
	tg.mu.Unlock()

	// Nova série deve entrar — eth0 será purgado pelo GC lazy.
	kept, drops := tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth9"}),
	})
	if len(kept) != 1 || len(drops) != 0 {
		t.Errorf("GC: kept=%d drops=%d, want 1/0", len(kept), len(drops))
	}
}

// TestTagger_Filter_LogEstruturado_TemCamposObrigatorios verifica que o log
// emitido em drop tem host_id, metric, current_cardinality e budget.
func TestTagger_Filter_LogEstruturado_TemCamposObrigatorios(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	tg := NewTagger(1, logger)

	// Enche.
	tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
	})
	// Provoca drop.
	tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth1"}),
	})

	// Lê última linha do buffer (JSON por linha).
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) == 0 {
		t.Fatal("no log lines captured")
	}
	last := lines[len(lines)-1]

	var entry map[string]any
	if err := json.Unmarshal([]byte(last), &entry); err != nil {
		t.Fatalf("log line is not JSON: %v — line=%s", err, last)
	}
	for _, field := range []string{"host_id", "top_metrics", "current_cardinality", "budget"} {
		if _, ok := entry[field]; !ok {
			t.Errorf("log entry missing field %q — entry=%v", field, entry)
		}
	}
	if entry["host_id"] != "hostA" {
		t.Errorf("log host_id: want hostA, got %v", entry["host_id"])
	}
}

// TestTagger_Filter_IsencaoSaudeSNMP garante que snmp.collector.* e
// snmp.device.* passam com o orçamento cheio e as demais são descartadas.
func TestTagger_Filter_IsencaoSaudeSNMP(t *testing.T) {
	tg := NewTagger(1, slog.Default())
	tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.iface.in", map[string]string{"iface": "eth0"}),
	})

	kept, drops := tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "snmp.collector.up", map[string]string{"target": "a"}),
		mkMetric("hostA", "snmp.device.reachable", map[string]string{"target": "b"}),
		mkMetric("hostA", "snmp.iface.out", map[string]string{"iface": "eth9"}),
		mkMetric("hostA", "cpu.usage", nil),
	})
	if len(kept) != 2 {
		t.Errorf("kept: want 2 (saúde SNMP), got %d", len(kept))
	}
	drops = onlyDropped(drops)
	if len(drops) != 2 {
		t.Errorf("drops: want 2 (snmp.iface.out e cpu.usage), got %d", len(drops))
	}
}

// TestTagger_Filter_DropAgregadoPorMetrica garante uma meta-métrica por
// host/métrica com Value igual à quantidade descartada.
func TestTagger_Filter_DropAgregadoPorMetrica(t *testing.T) {
	tg := NewTagger(1, slog.Default())
	tg.Filter([]*collectorv1.Metric{mkMetric("hostA", "m", map[string]string{"i": "0"})})

	_, drops := tg.Filter([]*collectorv1.Metric{
		mkMetric("hostA", "m", map[string]string{"i": "1"}),
		mkMetric("hostA", "m", map[string]string{"i": "2"}),
		mkMetric("hostA", "m", map[string]string{"i": "3"}),
	})
	drops = onlyDropped(drops)
	if len(drops) != 1 {
		t.Fatalf("drops: want 1, got %d", len(drops))
	}
	if drops[0].GetValue() != 3 || drops[0].GetTags()["metric"] != "m" {
		t.Errorf("drop: value=%v tags=%v, want 3 / metric=m", drops[0].GetValue(), drops[0].GetTags())
	}
}

// TestTagger_Filter_AvisoAgregadoUmPorJanela garante no máximo um Warn por
// host a cada 5 minutos, com a contagem acumulada na janela.
func TestTagger_Filter_AvisoAgregadoUmPorJanela(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	tg := NewTagger(1, logger)
	clock := time.Now()
	tg.now = func() time.Time { return clock }

	tg.Filter([]*collectorv1.Metric{mkMetric("hostA", "m", map[string]string{"i": "0"})})
	drop := func(i string) {
		tg.Filter([]*collectorv1.Metric{mkMetric("hostA", "m", map[string]string{"i": i})})
	}
	warns := func() []map[string]any {
		var out []map[string]any
		for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if l == "" {
				continue
			}
			var e map[string]any
			if err := json.Unmarshal([]byte(l), &e); err != nil {
				t.Fatalf("log não é JSON: %v", err)
			}
			out = append(out, e)
		}
		return out
	}

	drop("1")
	clock = clock.Add(time.Minute)
	drop("2")
	drop("3")
	if n := len(warns()); n != 1 {
		t.Fatalf("na janela: want 1 aviso, got %d", n)
	}

	clock = clock.Add(5 * time.Minute)
	drop("4")
	w := warns()
	if len(w) != 2 {
		t.Fatalf("nova janela: want 2 avisos, got %d", len(w))
	}
	if w[1]["dropped_series"] != float64(3) {
		t.Errorf("dropped_series: want 3, got %v", w[1]["dropped_series"])
	}
}

// Dois equipamentos sob o mesmo host_id não dividem o orçamento.
func TestTagger_FilterScoped_DevicesNaoSePrejudicam(t *testing.T) {
	tg := NewTagger(2, slog.Default())
	a := []*collectorv1.Metric{
		mkMetric("h", "snmp.if.in", map[string]string{"i": "1"}),
		mkMetric("h", "snmp.if.in", map[string]string{"i": "2"}),
		mkMetric("h", "snmp.if.in", map[string]string{"i": "3"}),
	}
	kept, drops := tg.FilterScoped("a@1.1.1.1", "sw-a", a)
	if len(kept) != 2 {
		t.Fatalf("device A kept=%d, want 2", len(kept))
	}
	var over *collectorv1.Metric
	for _, d := range drops {
		if d.MetricName == "telvyn.tagger.over_budget" {
			over = d
		}
	}
	if over == nil || over.Value != 1 || over.Tags["device"] != "sw-a" || over.Tags["top_metrics"] != "snmp.if.in=1" {
		t.Fatalf("over_budget inesperada: %v", over)
	}
	kept, drops = tg.FilterScoped("b@2.2.2.2", "sw-b", a[:2])
	if len(kept) != 2 || len(drops) != 0 {
		t.Fatalf("device B kept=%d drops=%d, want 2/0", len(kept), len(drops))
	}
	tg.ForgetScope("h", "a@1.1.1.1")
	kept, _ = tg.FilterScoped("a@1.1.1.1", "sw-a", a[2:])
	if len(kept) != 1 {
		t.Fatalf("após ForgetScope kept=%d, want 1", len(kept))
	}
}

func TestTagger_BudgetPadrao50k(t *testing.T) {
	if got := NewTagger(0, nil).Budget(); got != 50000 {
		t.Fatalf("default = %d", got)
	}
}

func TestApplyDropTags_AgregaPorSoma(t *testing.T) {
	in := []*collectorv1.Metric{
		mkMetric("h", "snmp.storage.used", map[string]string{"row_index": "1", "storage_descr": "a", "k": "x"}),
		mkMetric("h", "snmp.storage.used", map[string]string{"row_index": "2", "storage_descr": "b", "k": "x"}),
		mkMetric("h", "snmp.other", map[string]string{"row_index": "1"}),
	}
	out := applyDropTags(in, map[string][]string{"snmp.storage.used": {"row_index", "storage_descr"}})
	if len(out) != 2 || out[0].Value != 2 || len(out[0].Tags) != 1 || out[1].Tags["row_index"] != "1" {
		t.Fatalf("resultado inesperado: %v", out)
	}
}

// onlyDropped separa as telvyn.tagger.dropped da telvyn.tagger.over_budget.
func onlyDropped(in []*collectorv1.Metric) []*collectorv1.Metric {
	var out []*collectorv1.Metric
	for _, m := range in {
		if m.MetricName == "telvyn.tagger.dropped" {
			out = append(out, m)
		}
	}
	return out
}
