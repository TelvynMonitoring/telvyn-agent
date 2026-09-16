//go:build linux

package clock

import (
	"context"
	"encoding/binary"
	"math"
	"net"
	"os"
	"strings"
	"time"
)

const (
	ntpPacketSize  = 48
	ntpEpochOffset = 2208988800
	ntpTimeout     = 2 * time.Second
)

var defaultServers = []string{
	"0.pool.ntp.org:123",
	"1.pool.ntp.org:123",
	"2.pool.ntp.org:123",
}

// OffsetSeconds measures the local clock offset against an NTP server using
// the unprivileged SNTP exchange. It never changes the host clock, executes a
// subprocess, or requires CAP_SYS_TIME.
func OffsetSeconds(ctx context.Context) (float64, bool) {
	for _, server := range ntpServers(os.Getenv("ISPWATCH_NTP_SERVERS")) {
		if offset, ok := query(ctx, server); ok {
			return offset, true
		}
	}
	return 0, false
}

func ntpServers(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return defaultServers
	}
	servers := make([]string, 0, 3)
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value != "" {
			servers = append(servers, withNTPPort(value))
		}
	}
	if len(servers) == 0 {
		return defaultServers
	}
	return servers
}

func withNTPPort(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	if strings.HasPrefix(server, "[") && strings.HasSuffix(server, "]") {
		server = strings.TrimSuffix(strings.TrimPrefix(server, "["), "]")
	}
	return net.JoinHostPort(server, "123")
}

func query(ctx context.Context, server string) (float64, bool) {
	dialer := net.Dialer{Timeout: ntpTimeout}
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return 0, false
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(ntpTimeout)); err != nil {
		return 0, false
	}

	packet := make([]byte, ntpPacketSize)
	// LI=0, VN=4, Mode=3 (client request).
	packet[0] = 0x23
	t1 := time.Now()
	putTimestamp(packet[40:48], t1)
	if _, err := conn.Write(packet); err != nil {
		return 0, false
	}

	n, err := conn.Read(packet)
	t4 := time.Now()
	if err != nil || n < ntpPacketSize {
		return 0, false
	}
	// Mode 4 is server response; stratum 0 is a Kiss-o'-Death packet.
	if packet[0]&0x7 != 4 || packet[1] == 0 {
		return 0, false
	}

	t2, ok2 := parseTimestamp(packet[32:40])
	t3, ok3 := parseTimestamp(packet[40:48])
	if !ok2 || !ok3 || t3.Before(t2) {
		return 0, false
	}

	// NTP offset = ((server receive - client send) +
	// (server transmit - client receive)) / 2.
	offset := t2.Sub(t1).Seconds() + t3.Sub(t4).Seconds()
	offset /= 2
	if math.IsNaN(offset) || math.IsInf(offset, 0) || math.Abs(offset) > 86400 {
		return 0, false
	}
	return offset, true
}

func putTimestamp(dst []byte, t time.Time) {
	seconds := uint64(t.Unix() + ntpEpochOffset)
	fraction := uint64(t.Nanosecond()) * (1 << 32) / 1_000_000_000
	binary.BigEndian.PutUint32(dst[0:4], uint32(seconds))
	binary.BigEndian.PutUint32(dst[4:8], uint32(fraction))
}

func parseTimestamp(src []byte) (time.Time, bool) {
	seconds := binary.BigEndian.Uint32(src[0:4])
	fraction := binary.BigEndian.Uint32(src[4:8])
	if seconds == 0 && fraction == 0 {
		return time.Time{}, false
	}
	nanos := uint64(fraction) * 1_000_000_000 / (1 << 32)
	return time.Unix(int64(seconds)-ntpEpochOffset, int64(nanos)), true
}
