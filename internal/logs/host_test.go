package logs

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/telvynmonitoring/telvyn-agent/internal/otlp"
)

func newTestTailer(t *testing.T, dir string, got *[]otlp.LogRecord) *hostFileTailer {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &hostFileTailer{log: log, hostname: "h1", globs: []string{filepath.Join(dir, "*.log"), filepath.Join(dir, "*", "*.log")},
		exclude: []string{"skip.log"}, push: func(r otlp.LogRecord) { *got = append(*got, r) },
		cursors: NewCursorStore(filepath.Join(dir, "cursors.json"), log), files: map[string]*hostFile{}}
}

func appendFile(t *testing.T, p, text string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

func tick(tl *hostFileTailer) {
	for _, f := range tl.files {
		tl.read(f)
	}
}

func TestHostFilesPrimeiraVarreduraComecaDoFim(t *testing.T) {
	dir := t.TempDir()
	var got []otlp.LogRecord
	tl := newTestTailer(t, dir, &got)
	app := filepath.Join(dir, "app.log")
	appendFile(t, app, "linha antiga\n")
	tl.discover()
	tick(tl)
	if len(got) != 0 {
		t.Fatalf("histórico do disco não deve ser reenviado: %d", len(got))
	}
	appendFile(t, app, "pedido ok\nERROR falha no pagamento\nlinha parcial")
	tick(tl)
	if len(got) != 2 {
		t.Fatalf("esperava 2 linhas completas, veio %d", len(got))
	}
	if got[0].ServiceName != "app" || got[0].SeverityText != "INFO" || got[0].Hostname != "h1" {
		t.Fatalf("registro inesperado: %+v", got[0])
	}
	if got[1].SeverityText != "ERROR" || got[1].Attributes["log.file.path"] != filepath.ToSlash(app) {
		t.Fatalf("registro inesperado: %+v", got[1])
	}
	appendFile(t, app, " completa\n")
	tick(tl)
	if len(got) != 3 || got[2].Body != "linha parcial completa" {
		t.Fatalf("a linha parcial deveria fechar: %+v", got)
	}
}

func TestHostFilesArquivoNovoLidoDoComecoEExclusoes(t *testing.T) {
	dir := t.TempDir()
	var got []otlp.LogRecord
	tl := newTestTailer(t, dir, &got)
	tl.discover()
	if err := os.MkdirAll(filepath.Join(dir, "nginx"), 0o755); err != nil {
		t.Fatal(err)
	}
	appendFile(t, filepath.Join(dir, "nginx", "access.log"), "GET / 200\n")
	appendFile(t, filepath.Join(dir, "skip.log"), "ignorar\n")
	tl.discover()
	tick(tl)
	if len(got) != 1 || got[0].Body != "GET / 200" {
		t.Fatalf("esperava 1 linha do nginx: %+v", got)
	}
}

func TestServiceForFile(t *testing.T) {
	for p, want := range map[string]string{"/var/log/nginx/access.log": "nginx", "/var/log/app.log": "app", "/srv/x/api.log": "api"} {
		if got := serviceForFile(p); got != want {
			t.Errorf("%s: %s, esperado %s", p, got, want)
		}
	}
}

func TestHostFilesRotacaoETruncamento(t *testing.T) {
	dir := t.TempDir()
	var got []otlp.LogRecord
	tl := newTestTailer(t, dir, &got)
	app := filepath.Join(dir, "app.log")
	appendFile(t, app, "x\n")
	tl.discover()
	appendFile(t, app, "antes da rotação\n")
	if err := os.Rename(app, app+".1"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, app, "depois da rotação\n")
	tick(tl)
	tick(tl)
	var bodies []string
	for _, r := range got {
		bodies = append(bodies, r.Body)
	}
	if strings.Join(bodies, "|") != "antes da rotação|depois da rotação" {
		t.Fatalf("rotação perdeu ou duplicou linhas: %v", bodies)
	}
	if err := os.Truncate(app, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, app, "após truncar\n")
	tick(tl)
	if got[len(got)-1].Body != "após truncar" {
		t.Fatalf("truncamento não foi seguido: %v", got[len(got)-1])
	}
}

func TestHostFilesRetomaPeloCursor(t *testing.T) {
	dir := t.TempDir()
	var got []otlp.LogRecord
	tl := newTestTailer(t, dir, &got)
	app := filepath.Join(dir, "app.log")
	appendFile(t, app, "a\n")
	tl.discover()
	appendFile(t, app, "b\n")
	tick(tl)
	tl.cursors.Flush()
	tl.closeAll()
	appendFile(t, app, "c\n") // chegou com o agente parado

	var again []otlp.LogRecord
	tl2 := newTestTailer(t, dir, &again)
	tl2.discover()
	tick(tl2)
	if len(again) != 1 || again[0].Body != "c" {
		t.Fatalf("deveria retomar do cursor e enviar só 'c': %+v", again)
	}
}

func TestLineSeverity(t *testing.T) {
	cases := map[string]string{
		`{"level":"error","msg":"x"}`: "ERROR",
		`{"level":"warn"}`:            "WARN",
		"WARNING disco cheio":         "WARN",
		"tudo bem":                    "INFO",
		"panic: nil":                  "ERROR",
		"DEBUG detalhe":               "DEBUG",
	}
	for line, want := range cases {
		if _, got := lineSeverity(line); got != want {
			t.Errorf("%q: %s, esperado %s", line, got, want)
		}
	}
}
