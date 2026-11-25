package logs

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
)

// fakeLogsAPI simula o daemon: lista containers e devolve os bytes de log pré-montados.
type fakeLogsAPI struct {
	mu        sync.Mutex
	list      []container.Summary
	streams   map[string][]byte // container id → bytes devolvidos por ContainerLogs
	tty       map[string]bool
	logsCalls int
	lastSince string
}

func (f *fakeLogsAPI) ContainerList(context.Context, container.ListOptions) ([]container.Summary, error) {
	return f.list, nil
}

func (f *fakeLogsAPI) ContainerLogs(_ context.Context, id string, opts container.LogsOptions) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logsCalls++
	f.lastSince = opts.Since
	return io.NopCloser(bytes.NewReader(f.streams[id])), nil
}

func (f *fakeLogsAPI) ContainerInspect(_ context.Context, id string) (container.InspectResponse, error) {
	return container.InspectResponse{Config: &container.Config{Tty: f.tty[id]}}, nil
}

func (f *fakeLogsAPI) Close() error { return nil }

func (f *fakeLogsAPI) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logsCalls
}

// frame monta um frame multiplexado do daemon (stdout=1, stderr=2).
func frame(stream byte, text string) []byte {
	b := make([]byte, 8+len(text))
	b[0] = stream
	binary.BigEndian.PutUint32(b[4:8], uint32(len(text)))
	copy(b[8:], text)
	return b
}

// future devolve um timestamp RFC3339Nano à frente do relógio, para passar do "a partir de agora" do reader.
func future(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339Nano) }

func newDockerTestTailer(t *testing.T, api *fakeLogsAPI, dir, source string) *DockerLogsTailer {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newDockerLogsTailer(api, nil, filepath.Join(t.TempDir(), "cursors.json"), log, dir, source)
}

func stopReaders(t *DockerLogsTailer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, h := range t.readers {
		close(h.done)
		delete(t.readers, id)
	}
}

func nextEntry(t *testing.T, ch <-chan LogEntry) LogEntry {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("nenhum log recebido")
		return LogEntry{}
	}
}

const testID = "0123456789abcdef0123456789abcdef"

func runningWeb() []container.Summary {
	return []container.Summary{{ID: testID, Names: []string{"/web"}, Image: "nginx:1", State: container.StateRunning}}
}

// Sem arquivo json-file legível, o modo auto usa a API do Docker.
func TestDockerTailer_AutoFallsBackToAPIWithoutFile(t *testing.T) {
	api := &fakeLogsAPI{list: runningWeb(), streams: map[string][]byte{
		testID: append(frame(1, future(time.Hour)+" hello out\n"), frame(2, future(time.Hour+time.Second)+" boom err\n")...),
	}}
	tl := newDockerTestTailer(t, api, t.TempDir(), LogSourceAuto)
	defer stopReaders(tl)
	tl.discover()

	if _, ok := tl.readers[testID].reader.(*DockerAPIReader); !ok {
		t.Fatalf("esperava DockerAPIReader, veio %T", tl.readers[testID].reader)
	}
	a, b := nextEntry(t, tl.entryCh), nextEntry(t, tl.entryCh)
	if a.Body != "hello out" || a.Stream != "stdout" || a.Meta.ContainerName != "web" {
		t.Errorf("primeira linha inesperada: %+v", a)
	}
	if b.Body != "boom err" || b.Stream != "stderr" {
		t.Errorf("segunda linha inesperada: %+v", b)
	}
	if api.lastSince == "" {
		t.Error("ContainerLogs deveria receber Since")
	}
}

// Com o arquivo presente, o modo auto lê o arquivo e nem chama a API de logs.
func TestDockerTailer_AutoPrefersFileWhenPresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, testID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, testID, testID+"-json.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	api := &fakeLogsAPI{list: runningWeb()}
	tl := newDockerTestTailer(t, api, dir, LogSourceAuto)
	defer stopReaders(tl)
	tl.discover()

	if _, ok := tl.readers[testID].reader.(*JSONFileReader); !ok {
		t.Fatalf("esperava JSONFileReader, veio %T", tl.readers[testID].reader)
	}
	if api.calls() != 0 {
		t.Errorf("a API de logs não deveria ser usada com o arquivo disponível (chamadas=%d)", api.calls())
	}
}

// Modo file sem arquivo: não lê nada. Modo api: ignora o arquivo mesmo existindo.
func TestDockerTailer_ForcedSources(t *testing.T) {
	api := &fakeLogsAPI{list: runningWeb(), streams: map[string][]byte{testID: nil}}

	onlyFile := newDockerTestTailer(t, api, t.TempDir(), LogSourceFile)
	onlyFile.discover()
	if n := len(onlyFile.readers); n != 0 {
		t.Errorf("modo file sem arquivo deveria não ter readers, tem %d", n)
	}

	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, testID), 0o755)
	_ = os.WriteFile(filepath.Join(dir, testID, testID+"-json.log"), nil, 0o644)
	onlyAPI := newDockerTestTailer(t, api, dir, LogSourceAPI)
	defer stopReaders(onlyAPI)
	onlyAPI.discover()
	if _, ok := onlyAPI.readers[testID].reader.(*DockerAPIReader); !ok {
		t.Errorf("modo api deveria usar DockerAPIReader mesmo com arquivo, veio %T", onlyAPI.readers[testID].reader)
	}
}

// Container com TTY: o daemon devolve texto cru, sem frames multiplexados.
func TestDockerAPIReader_TTYRawStream(t *testing.T) {
	api := &fakeLogsAPI{
		list:    runningWeb(),
		tty:     map[string]bool{testID: true},
		streams: map[string][]byte{testID: []byte(future(time.Hour) + " tty line\r\n")},
	}
	tl := newDockerTestTailer(t, api, t.TempDir(), LogSourceAPI)
	defer stopReaders(tl)
	tl.discover()
	if e := nextEntry(t, tl.entryCh); e.Body != "tty line" || e.Stream != "stdout" {
		t.Errorf("linha TTY inesperada: %+v", e)
	}
}

// Ao reconectar, a API devolve de novo desde o último timestamp: nada pode sair duplicado.
func TestDockerAPIReader_NoDuplicatesAfterReconnect(t *testing.T) {
	ts1, ts2 := future(time.Hour), future(time.Hour+time.Second)
	api := &fakeLogsAPI{list: runningWeb(), streams: map[string][]byte{
		testID: append(frame(1, ts1+" one\n"), frame(1, ts2+" two\n")...),
	}}
	tl := newDockerTestTailer(t, api, t.TempDir(), LogSourceAPI)
	defer stopReaders(tl)
	tl.discover()

	got := []string{nextEntry(t, tl.entryCh).Body, nextEntry(t, tl.entryCh).Body}
	if got[0] != "one" || got[1] != "two" {
		t.Fatalf("linhas inesperadas: %v", got)
	}
	deadline := time.Now().Add(3 * time.Second)
	for api.calls() < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if api.calls() < 2 {
		t.Fatal("o reader deveria ter reconectado")
	}
	time.Sleep(200 * time.Millisecond)
	select {
	case e := <-tl.entryCh:
		t.Errorf("linha duplicada após reconexão: %+v", e)
	default:
	}
}

func TestSourceFromEnv(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for env, want := range map[string]string{"": LogSourceAuto, "auto": LogSourceAuto, "FILE": LogSourceFile, " api ": LogSourceAPI, "xyz": LogSourceAuto} {
		t.Setenv("TELVYN_DOCKER_LOGS_SOURCE", env)
		if got := sourceFromEnv(log); got != want {
			t.Errorf("TELVYN_DOCKER_LOGS_SOURCE=%q → %q, esperava %q", env, got, want)
		}
	}
}
