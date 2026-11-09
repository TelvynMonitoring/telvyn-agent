// host.go — logs de um host Linux comum (sem Kubernetes): journald e arquivos em /var/log.
//
// O leitor de pods CRI (cri_tailer.go) só enxerga /var/log/pods. Num servidor Linux comum, onde a aplicação
// roda como serviço systemd, pm2, nginx etc., os logs estão no journal e em arquivos. Este arquivo liga os dois
// ao mesmo exportador (WAL durável): Push só retorna depois de persistir, então o cursor de arquivo nunca
// avança antes da gravação.
package logs

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/telvynmonitoring/telvyn-agent/internal/checks"
	"github.com/telvynmonitoring/telvyn-agent/internal/otlp"
)

const (
	hostFilePollInterval      = time.Second
	hostFileDiscoveryInterval = 10 * time.Second
	hostFileMaxLine           = 16 * 1024
	hostFileMaxReadPerTick    = 1 << 20
	hostFileMaxFiles          = 200
)

// DefaultHostLogGlobs: arquivos de log de aplicação/serviços. Syslog, auth e kernel já vêm pelo journald.
var DefaultHostLogGlobs = []string{"/var/log/*.log", "/var/log/*/*.log"}

// SyslogFileGlobs: syslog clássico (sem extensão .log). Só entram quando não há journald para entregá-los.
var SyslogFileGlobs = []string{"/var/log/syslog", "/var/log/messages", "/var/log/secure"}

// journalDuplicates são arquivos que o journald já entrega (rsyslog espelha o journal neles).
var journalDuplicates = []string{"auth.log", "kern.log", "dpkg.log", "alternatives.log", "cloud-init.log", "cloud-init-output.log", "ubuntu-advantage.log", "bootstrap.log", "unattended-upgrades.log"}

// HostLogsConfig configura a coleta de logs do host.
type HostLogsConfig struct {
	Hostname     string
	Journald     bool     // lê o journal via journalctl
	Files        []string // globs de arquivos; vazio desliga
	ExcludeGlobs []string // globs a ignorar (caminho completo ou nome do arquivo)
	CursorPath   string   // arquivo de cursores dos arquivos lidos
}

// RunHostLogs liga o leitor de journald e o de arquivos. Bloqueia até ctx terminar.
func RunHostLogs(ctx context.Context, log *slog.Logger, cfg HostLogsConfig, push func(otlp.LogRecord)) {
	log = log.With("component", "host-logs")
	journald := false
	if cfg.Journald {
		if _, err := exec.LookPath("journalctl"); err != nil {
			log.Info("host logs: journalctl não encontrado; journald não será lido")
		} else {
			journald = true
			go runHostJournald(ctx, log, cfg.Hostname, push)
		}
	}
	files := cfg.Files
	if !journald && strings.Join(files, ",") == strings.Join(DefaultHostLogGlobs, ",") {
		// Sem journald (host sem systemd ou journal desligado) e com os globs padrão: o syslog clássico vira a fonte do sistema.
		files = append(append([]string{}, files...), SyslogFileGlobs...)
	}
	if len(files) > 0 {
		exclude := append([]string{"/var/log/telvyn*", "/var/log/telvyn-agent*", "/var/log/pods/*", "/var/log/containers/*", "/var/log/journal/*"}, cfg.ExcludeGlobs...)
		if journald {
			exclude = append(exclude, journalDuplicates...)
		}
		t := &hostFileTailer{log: log, hostname: cfg.Hostname, globs: files, exclude: exclude, push: push,
			cursors: NewCursorStore(cfg.CursorPath, log), files: map[string]*hostFile{}}
		t.run(ctx)
		return
	}
	<-ctx.Done()
}

// ---- journald -----------------------------------------------------------------------------------------------

func runHostJournald(ctx context.Context, log *slog.Logger, hostname string, push func(otlp.LogRecord)) {
	reader := checks.NewJournaldReader(log)
	go reader.Run(ctx)
	log.Info("host logs: lendo o journald (journalctl -f)")
	for rec := range reader.Out() {
		unit := strings.TrimSuffix(rec.Unit, ".service")
		if strings.HasPrefix(unit, "telvyn-agent") { // evita laço: o log do próprio agente
			continue
		}
		attrs := map[string]string{"log.source": "journald", "systemd.unit": rec.Unit}
		if rec.PID != "" {
			attrs["process.pid"] = rec.PID
		}
		push(otlp.LogRecord{TimestampUnixNano: rec.TimestampUnixNano, ServiceName: unit, Hostname: hostname,
			SeverityNumber: checks.PriorityToSeverityNumber(rec.Priority), SeverityText: checks.PriorityToSeverityText(rec.Priority),
			Body: rec.Body, Attributes: attrs})
	}
}

// ---- arquivos -----------------------------------------------------------------------------------------------

type hostFile struct {
	path    string
	file    *os.File
	inode   uint64
	offset  int64
	partial []byte
}

type hostFileTailer struct {
	log      *slog.Logger
	hostname string
	globs    []string
	exclude  []string
	push     func(otlp.LogRecord)
	cursors  *CursorStore
	files    map[string]*hostFile
	started  bool // depois da primeira varredura, arquivo novo é lido do começo
}

func (t *hostFileTailer) run(ctx context.Context) {
	t.log.Info("host logs: lendo arquivos", "globs", strings.Join(t.globs, ","))
	poll := time.NewTicker(hostFilePollInterval)
	discover := time.NewTicker(hostFileDiscoveryInterval)
	flush := time.NewTicker(5 * time.Second)
	defer poll.Stop()
	defer discover.Stop()
	defer flush.Stop()
	t.discover()
	for {
		select {
		case <-ctx.Done():
			t.closeAll()
			t.cursors.Flush()
			return
		case <-discover.C:
			t.discover()
		case <-poll.C:
			for _, f := range t.files {
				t.read(f)
			}
		case <-flush.C:
			t.cursors.Flush()
		}
	}
}

func (t *hostFileTailer) closeAll() {
	for _, f := range t.files {
		if f.file != nil {
			f.file.Close()
		}
	}
}

func (t *hostFileTailer) excluded(p string) bool {
	for _, g := range t.exclude {
		if ok, _ := path.Match(g, p); ok {
			return true
		}
		if ok, _ := path.Match(g, path.Base(p)); ok {
			return true
		}
	}
	return false
}

// discover abre arquivos novos. Na primeira varredura começa do fim (não reenvia o histórico do disco);
// arquivos que aparecem depois (rotação, serviço novo) são lidos do começo. Com cursor salvo e mesmo inode, retoma.
func (t *hostFileTailer) discover() {
	seen := map[string]bool{}
	for _, g := range t.globs {
		matches, err := filepath.Glob(g)
		if err != nil {
			continue
		}
		for _, p := range matches {
			p = filepath.ToSlash(p)
			if seen[p] || t.excluded(p) {
				continue
			}
			seen[p] = true
			if _, ok := t.files[p]; ok || len(t.files) >= hostFileMaxFiles {
				continue
			}
			t.open(p, !t.started)
		}
	}
	for p, f := range t.files { // arquivo apagado: fecha depois de ler o que sobrou
		if !seen[p] {
			t.read(f)
			if f.file != nil {
				f.file.Close()
			}
			t.cursors.Remove(p)
			delete(t.files, p)
		}
	}
	t.started = true
}

func (t *hostFileTailer) open(p string, fromEnd bool) {
	fh, err := os.Open(p)
	if err != nil {
		return // sem permissão ou sumiu; tenta de novo na próxima varredura
	}
	info, err := fh.Stat()
	if err != nil || !info.Mode().IsRegular() {
		fh.Close()
		return
	}
	inode := inodeOf(info)
	var offset int64
	if c, ok := t.cursors.Get(p); ok && c.Inode == inode && c.Offset <= info.Size() {
		offset = c.Offset
	} else if fromEnd {
		offset = info.Size()
	}
	if _, err := fh.Seek(offset, 0); err != nil {
		fh.Close()
		return
	}
	t.files[p] = &hostFile{path: p, file: fh, inode: inode, offset: offset}
	t.log.Debug("host logs: arquivo aberto", "path", p, "offset", offset)
}

// read lê o que há de novo, cuidando de rotação (inode mudou) e truncamento.
func (t *hostFileTailer) read(f *hostFile) {
	if f.file == nil {
		return
	}
	t.drain(f)
	info, err := os.Stat(f.path)
	if err != nil {
		return
	}
	if inodeOf(info) != f.inode { // rotacionado: o descritor antigo já foi lido até o fim; segue o novo arquivo
		f.file.Close()
		delete(t.files, f.path)
		t.cursors.Remove(f.path)
		t.open(f.path, false)
		return
	}
	if info.Size() < f.offset { // truncado
		f.offset = 0
		f.partial = nil
		f.file.Seek(0, 0)
		t.drain(f)
	}
}

func (t *hostFileTailer) drain(f *hostFile) {
	buf := make([]byte, 64*1024)
	var read int
	for read < hostFileMaxReadPerTick {
		n, err := f.file.Read(buf)
		if n > 0 {
			read += n
			f.offset += int64(n)
			t.lines(f, buf[:n])
		}
		if err != nil || n == 0 {
			break
		}
	}
	t.cursors.Set(f.path, CursorEntry{Offset: f.offset - int64(len(f.partial)), Inode: f.inode})
}

func (t *hostFileTailer) lines(f *hostFile, data []byte) {
	f.partial = append(f.partial, data...)
	for {
		i := indexByte(f.partial, '\n')
		if i < 0 {
			if len(f.partial) > hostFileMaxLine { // linha sem fim: envia o pedaço
				t.emit(f, string(f.partial[:hostFileMaxLine]))
				f.partial = f.partial[hostFileMaxLine:]
			}
			return
		}
		t.emit(f, string(f.partial[:i]))
		f.partial = f.partial[i+1:]
	}
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func (t *hostFileTailer) emit(f *hostFile, line string) {
	line = strings.TrimRight(line, "\r")
	if strings.TrimSpace(line) == "" {
		return
	}
	if len(line) > hostFileMaxLine {
		line = line[:hostFileMaxLine]
	}
	num, text := lineSeverity(line)
	t.push(otlp.LogRecord{TimestampUnixNano: time.Now().UnixNano(), ServiceName: serviceForFile(f.path), Hostname: t.hostname,
		SeverityNumber: num, SeverityText: text, Body: line,
		Attributes: map[string]string{"log.source": "file", "log.file.path": f.path}})
}

// serviceForFile: /var/log/nginx/access.log → nginx; /var/log/app.log → app.
func serviceForFile(p string) string {
	if path.Dir(path.Dir(p)) == "/var/log" {
		return path.Base(path.Dir(p))
	}
	return strings.TrimSuffix(path.Base(p), ".log")
}

var (
	reErr  = regexp.MustCompile(`(?i)\b(fatal|panic|critical|error|err)\b`)
	reWarn = regexp.MustCompile(`(?i)\b(warn|warning)\b`)
	reDbg  = regexp.MustCompile(`(?i)\b(debug|trace)\b`)
)

// lineSeverity: nível do JSON ("level") quando a linha é JSON; senão palavra-chave; padrão INFO.
func lineSeverity(line string) (int, string) {
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			for _, k := range []string{"level", "severity", "lvl"} {
				if v, ok := m[k].(string); ok {
					return levelText(v)
				}
			}
		}
	}
	switch {
	case reErr.MatchString(line):
		return 17, "ERROR"
	case reWarn.MatchString(line):
		return 13, "WARN"
	case reDbg.MatchString(line):
		return 5, "DEBUG"
	}
	return 9, "INFO"
}

func levelText(v string) (int, string) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "fatal", "panic", "critical", "crit", "emerg", "alert":
		return 21, "FATAL"
	case "error", "err":
		return 17, "ERROR"
	case "warn", "warning":
		return 13, "WARN"
	case "debug", "trace":
		return 5, "DEBUG"
	}
	return 9, "INFO"
}
