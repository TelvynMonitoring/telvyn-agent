// docker_api_reader.go — lê os logs de um container Docker pela API do daemon (ContainerLogs),
// sem depender do arquivo json-file em /var/lib/docker/containers.
//
// É a alternativa do JSONFileReader: funciona quando o agent não enxerga o diretório de logs
// (Docker Desktop, Podman, rootless, outro log driver legível pela API) e basta o docker.sock.
// O DockerLogsTailer escolhe entre os dois (TELVYN_DOCKER_LOGS_SOURCE=auto|file|api).
package logs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
)

const (
	// maxAPILogLine — linha sem quebra acima disso é enviada truncada (evita crescer o buffer sem limite).
	maxAPILogLine = 1 << 20
	// apiReconnectMax — teto do intervalo entre reconexões do stream.
	apiReconnectMax = 30 * time.Second
)

// DockerAPIReader segue (Follow) os logs de um container pela API do Docker.
type DockerAPIReader struct {
	api  dockerLogsAPI
	meta ContainerMeta
	log  *slog.Logger
	out  chan<- LogEntry

	rateLimitBytesPerSec int64
	bytesThisWindow      int64
	windowStart          time.Time
	droppedLines         atomic.Int64

	cursorStore *CursorStore
	lastNano    atomic.Int64 // timestamp da última linha lida (base do Since ao reconectar)
	lastBody    string       // última linha enviada, para não duplicar na reconexão (Since é inclusivo)
}

// NewDockerAPIReader cria o reader. Sem cursor salvo começa de agora (não reenvia o histórico do container),
// igual ao JSONFileReader que começa do fim do arquivo.
func NewDockerAPIReader(api dockerLogsAPI, meta ContainerMeta, cursorStore *CursorStore, rateLimitBytesPerSec int64, out chan<- LogEntry, log *slog.Logger) *DockerAPIReader {
	r := &DockerAPIReader{
		api:                  api,
		meta:                 meta,
		log:                  log.With("component", "docker-api-reader", "container", meta.ContainerName),
		out:                  out,
		rateLimitBytesPerSec: rateLimitBytesPerSec,
		cursorStore:          cursorStore,
		windowStart:          time.Now(),
	}
	if entry, ok := cursorStore.Get(meta.ContainerID); ok && entry.SinceNano > 0 {
		r.lastNano.Store(entry.SinceNano)
	} else {
		r.lastNano.Store(time.Now().UnixNano())
		r.log.Info("sem cursor anterior, lendo logs a partir de agora")
	}
	return r
}

// Run mantém o stream aberto, reconectando com espera crescente, até done fechar.
func (r *DockerAPIReader) Run(done <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()

	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := r.stream(ctx)
		r.saveCursor()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			r.log.Debug("stream de logs encerrado, reconectando", "err", err)
		}
		if time.Since(started) > apiReconnectMax {
			backoff = time.Second // ficou conectado um bom tempo: recomeça a espera curta
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < apiReconnectMax {
			backoff *= 2
		}
	}
}

// DroppedLines retorna o total de linhas descartadas (rate limit ou canal cheio).
func (r *DockerAPIReader) DroppedLines() int64 { return r.droppedLines.Load() }

func (r *DockerAPIReader) saveCursor() {
	r.cursorStore.Set(r.meta.ContainerID, CursorEntry{SinceNano: r.lastNano.Load()})
}

// stream abre uma conexão de logs desde o último timestamp e a consome até o fim ou erro.
func (r *DockerAPIReader) stream(ctx context.Context) error {
	tty := false
	if insp, err := r.api.ContainerInspect(ctx, r.meta.ContainerID); err == nil && insp.Config != nil {
		tty = insp.Config.Tty // com TTY o daemon não multiplexa stdout/stderr
	}
	since := r.lastNano.Load()
	rc, err := r.api.ContainerLogs(ctx, r.meta.ContainerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Timestamps: true,
		Since:      fmt.Sprintf("%d.%09d", since/1e9, since%1e9),
	})
	if err != nil {
		return err
	}
	defer rc.Close()

	stdout := &lineSplitter{emit: func(line string) { r.handle("stdout", line) }}
	if tty {
		_, err = io.Copy(stdout, rc)
		return err
	}
	stderr := &lineSplitter{emit: func(line string) { r.handle("stderr", line) }}
	_, err = stdcopy.StdCopy(stdout, stderr, rc)
	return err
}

// handle interpreta "<timestamp RFC3339Nano> <mensagem>" e entrega a linha ao canal.
func (r *DockerAPIReader) handle(stream, line string) {
	ts := time.Now()
	body := line
	if i := strings.IndexByte(line, ' '); i > 0 {
		if t, err := time.Parse(time.RFC3339Nano, line[:i]); err == nil {
			ts, body = t, line[i+1:]
		}
	}
	n := ts.UnixNano()
	last := r.lastNano.Load()
	if n < last || (n == last && body == r.lastBody) {
		return // já enviada antes da reconexão
	}
	r.lastNano.Store(n)
	r.lastBody = body
	if body == "" {
		return
	}

	if r.rateLimitBytesPerSec > 0 {
		now := time.Now()
		if now.Sub(r.windowStart) >= time.Second {
			r.bytesThisWindow = 0
			r.windowStart = now
		}
		size := int64(len(body)) + 1
		if r.bytesThisWindow+size > r.rateLimitBytesPerSec {
			r.droppedLines.Add(1)
			return
		}
		r.bytesThisWindow += size
	}

	select {
	case r.out <- LogEntry{TimestampUnixNano: n, Body: body, Stream: stream, Meta: r.meta}:
	default:
		r.droppedLines.Add(1) // canal cheio: descarta em vez de travar o stream
	}
}

// lineSplitter junta os pedaços escritos pelo stdcopy e emite uma chamada por linha completa.
type lineSplitter struct {
	buf  []byte
	emit func(line string)
}

func (w *lineSplitter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.emit(strings.TrimRight(string(w.buf[:i]), "\r"))
		w.buf = w.buf[i+1:]
	}
	if len(w.buf) > maxAPILogLine {
		w.emit(string(w.buf))
		w.buf = w.buf[:0]
	}
	return len(p), nil
}
