package sendbuf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestFreshOfferIsNotLoggedAsRetained(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	q := New("test", 1<<20, log)

	if err := q.Offer([]byte("new-payload"), nil); err != nil {
		t.Fatalf("enfileirar payload novo: %v", err)
	}
	if err := q.Flush(context.Background(), func(_ context.Context, _ []byte) error { return nil }); err != nil {
		t.Fatalf("enviar payload novo: %v", err)
	}
	if strings.Contains(logs.String(), "payload retido reenviado com sucesso") {
		t.Fatalf("payload novo não deveria ser registrado como retido: %s", logs.String())
	}
}

// Payloads retidos precisam sobreviver ao processo que os enfileirou. Isso
// cobre a queda de backend seguida de restart do agent.
func TestPersistentQueueSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	q := NewPersistent("test", 1<<20, dir, nil)
	q.Offer([]byte("metric-a"), errors.New("connection refused"))
	if got := q.Snapshot().Pending; got != 1 {
		t.Fatalf("esperava 1 payload pendente antes do restart, veio %d", got)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("fechar fila: %v", err)
	}

	q = NewPersistent("test", 1<<20, dir, nil)
	defer q.Close()
	var sent []string
	q.Flush(context.Background(), func(_ context.Context, body []byte) error {
		sent = append(sent, string(body))
		return nil
	})
	if len(sent) != 1 || sent[0] != "metric-a" {
		t.Fatalf("esperava reenvio do payload persistido, veio %v", sent)
	}
	if got := q.Snapshot().Pending; got != 0 {
		t.Fatalf("esperava fila vazia após reenvio, veio %d", got)
	}
}

// Falha de rede retém; flush posterior reenvia na ordem.
func TestRetainAndFlush(t *testing.T) {
	q := New("test", 1<<20, nil)
	q.Offer([]byte("a"), errors.New("connection refused"))
	q.Offer([]byte("b"), errors.New("connection refused"))

	var sent []string
	q.Flush(context.Background(), func(_ context.Context, b []byte) error {
		sent = append(sent, string(b))
		return nil
	})
	if len(sent) != 2 || sent[0] != "a" || sent[1] != "b" {
		t.Fatalf("esperava reenvio [a b] em ordem, veio %v", sent)
	}
	// fila vazia depois do flush
	q.Flush(context.Background(), func(_ context.Context, _ []byte) error {
		t.Fatal("fila deveria estar vazia")
		return nil
	})
}

// Estourou o teto de bytes → descarta o mais antigo, nunca cresce sem limite.
func TestDropOldestOnOverflow(t *testing.T) {
	q := New("test", 10, nil) // teto de 10 bytes
	q.Offer([]byte("11111"), errors.New("net"))
	q.Offer([]byte("22222"), errors.New("net"))
	q.Offer([]byte("33333"), errors.New("net")) // 15 bytes → dropa "11111"

	var sent []string
	q.Flush(context.Background(), func(_ context.Context, b []byte) error {
		sent = append(sent, string(b))
		return nil
	})
	if len(sent) != 2 || sent[0] != "22222" || sent[1] != "33333" {
		t.Fatalf("esperava [22222 33333], veio %v", sent)
	}
}

// 401 é terminal: descarta (não retém) e ativa o cool-down.
func TestAuthFailureDropsAndBlocks(t *testing.T) {
	q := New("test", 1<<20, nil)
	q.Offer([]byte("x"), fmt.Errorf("ingest traces: %w", &StatusError{Code: 401}))
	if !q.Blocked() {
		t.Fatal("401 deveria ativar o cool-down")
	}
	q.Flush(context.Background(), func(_ context.Context, _ []byte) error {
		t.Fatal("payload de 401 não deveria ter sido retido")
		return nil
	})
}

// 429 (franquia) também é terminal e bloqueia.
func TestBudgetFailureBlocks(t *testing.T) {
	q := New("test", 1<<20, nil)
	q.Offer([]byte("x"), &StatusError{Code: 429})
	if !q.Blocked() {
		t.Fatal("429 deveria ativar o cool-down")
	}
}

// Falha no meio do flush: item que falhou por REDE continua retido.
func TestFlushStopsOnNetworkError(t *testing.T) {
	q := New("test", 1<<20, nil)
	q.Offer([]byte("a"), errors.New("net"))
	q.Offer([]byte("b"), errors.New("net"))

	calls := 0
	q.Flush(context.Background(), func(_ context.Context, _ []byte) error {
		calls++
		return errors.New("still down")
	})
	if calls != 1 {
		t.Fatalf("flush deveria parar na 1ª falha, tentou %d", calls)
	}
	// os 2 itens seguem retidos
	var sent []string
	q.Flush(context.Background(), func(_ context.Context, b []byte) error {
		sent = append(sent, string(b))
		return nil
	})
	if len(sent) != 2 {
		t.Fatalf("esperava 2 retidos, veio %d", len(sent))
	}
}

func TestSnapshotReportsQueueRetriesAndDrops(t *testing.T) {
	q := New("test", 10, nil)
	q.Offer([]byte("11111"), errors.New("net"))
	q.Offer([]byte("22222"), errors.New("net"))
	q.Offer([]byte("33333"), errors.New("net"))

	before := q.Snapshot()
	if before.Pending != 2 || before.Bytes != 10 || before.RetainedTotal != 3 || before.DroppedTotal != 1 {
		t.Fatalf("snapshot antes do flush inesperado: %+v", before)
	}

	q.Flush(context.Background(), func(_ context.Context, _ []byte) error { return nil })
	after := q.Snapshot()
	if after.Pending != 0 || after.RetryAttempts != 2 || after.RetrySuccesses != 2 {
		t.Fatalf("snapshot depois do flush inesperado: %+v", after)
	}
}
