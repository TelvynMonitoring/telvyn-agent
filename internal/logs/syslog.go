package logs

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ispwatch/collector/internal/checks"
	"github.com/ispwatch/collector/internal/otlp"
)

// ParseSyslog keeps the original RFC3164/RFC5424 message and receiver timestamp.
// The device identity comes from the UDP peer, never the claimed header hostname.
func ParseSyslog(data []byte, source string, received time.Time) (otlp.LogRecord, error) {
	message := strings.TrimSpace(string(data))
	end := strings.IndexByte(message, '>')
	if !strings.HasPrefix(message, "<") || end < 2 || end > 4 {
		return otlp.LogRecord{}, fmt.Errorf("missing syslog PRI")
	}
	priority, err := strconv.Atoi(message[1:end])
	if err != nil || priority < 0 || priority > 191 {
		return otlp.LogRecord{}, fmt.Errorf("invalid syslog PRI")
	}
	if net.ParseIP(source) == nil || len(message[end+1:]) == 0 {
		return otlp.LogRecord{}, fmt.Errorf("invalid syslog source/message")
	}
	severity := priority % 8
	return otlp.LogRecord{TimestampUnixNano: received.UnixNano(), ServiceName: "syslog", Hostname: source,
		SeverityNumber: checks.PriorityToSeverityNumber(severity), SeverityText: checks.PriorityToSeverityText(severity), Body: message[end+1:],
		Attributes: map[string]string{"log.source": "syslog", "source.ip": source, "syslog.facility": strconv.Itoa(priority / 8), "syslog.severity": strconv.Itoa(severity)}}, nil
}

// RunSyslog is opt-in. Bind the configured address only; exporter reuses ingest auth/batching.
func RunSyslog(ctx context.Context, address string, push func(otlp.LogRecord)) error {
	connection, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	defer connection.Close()
	go func() { <-ctx.Done(); connection.Close() }()
	buffer := make([]byte, 65535)
	for {
		n, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ip, _, err := net.SplitHostPort(peer.String())
		if err != nil {
			continue
		}
		record, err := ParseSyslog(buffer[:n], ip, time.Now())
		if err == nil {
			push(record)
		}
	}
}
