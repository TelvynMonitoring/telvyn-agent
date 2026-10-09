package logs

import (
	"testing"
	"time"
)

func TestParseSyslogPeerIdentity(t *testing.T) {
	now := time.Unix(100, 0)
	for _, body := range []string{"<165>1 2026-10-07T20:00:00Z forged.example app - - - link changed", "<165>Oct  7 20:00:00 forged.example link changed"} {
		r, err := ParseSyslog([]byte(body), "192.0.2.5", now)
		if err != nil || r.Hostname != "192.0.2.5" || r.Attributes["source.ip"] != "192.0.2.5" || r.ServiceName != "syslog" || r.TimestampUnixNano != now.UnixNano() || r.SeverityText != "INFO" {
			t.Fatalf("record=%+v error=%v", r, err)
		}
	}
	for _, body := range []string{"missing PRI", "<999>bad", "<x>bad", "<165>"} {
		if _, err := ParseSyslog([]byte(body), "192.0.2.5", now); err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
}
