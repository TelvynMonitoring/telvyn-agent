//go:build linux

package clock

import (
	"context"
	"math"
	"net"
	"strings"
	"testing"
	"time"
)

func TestQueryMeasuresUnprivilegedSNTPOffset(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const expectedOffset = 150 * time.Millisecond
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		request := make([]byte, ntpPacketSize)
		n, client, err := conn.ReadFromUDP(request)
		if err != nil || n < ntpPacketSize {
			return
		}
		received := time.Now()
		response := make([]byte, ntpPacketSize)
		response[0] = 0x24 // LI=0, VN=4, Mode=4 (server response).
		response[1] = 1    // stratum 1.
		copy(response[24:32], request[40:48])
		putTimestamp(response[32:40], received.Add(expectedOffset))
		putTimestamp(response[40:48], received.Add(expectedOffset+time.Millisecond))
		_, _ = conn.WriteToUDP(response, client)
	}()

	offset, ok := query(context.Background(), conn.LocalAddr().String())
	if !ok {
		t.Fatal("query returned no valid NTP sample")
	}
	<-serverDone
	if math.Abs(offset-expectedOffset.Seconds()) > 0.03 {
		t.Fatalf("offset = %.3fs, want about %.3fs", offset, expectedOffset.Seconds())
	}
}

func testServer(t *testing.T, offset time.Duration, alter func([]byte)) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		request := make([]byte, ntpPacketSize)
		_, client, err := conn.ReadFromUDP(request)
		if err != nil {
			return
		}
		response := make([]byte, ntpPacketSize)
		response[0], response[1] = 0x24, 1
		copy(response[24:32], request[40:48])
		putTimestamp(response[32:40], time.Now().Add(offset))
		putTimestamp(response[40:48], time.Now().Add(offset))
		if alter != nil {
			alter(response)
		}
		conn.WriteToUDP(response, client)
	}()
	return conn.LocalAddr().String()
}

func TestOffsetSecondsUsesMedian(t *testing.T) {
	servers := []string{testServer(t, 100*time.Millisecond, nil), testServer(t, 300*time.Millisecond, nil), testServer(t, 200*time.Millisecond, nil)}
	t.Setenv("ISPWATCH_NTP_SERVERS", strings.Join(servers, ","))
	offset, ok := OffsetSeconds(context.Background())
	if !ok || math.Abs(offset-.2) > .03 {
		t.Fatalf("median offset=%v, ok=%v", offset, ok)
	}
}

func TestQueryRejectsInvalidServerResponses(t *testing.T) {
	for name, alter := range map[string]func([]byte){
		"unsynchronized":    func(p []byte) { p[0] |= 0xc0 },
		"bad stratum":       func(p []byte) { p[1] = 16 },
		"unrelated request": func(p []byte) { p[24] ^= 1 },
		"kiss of death":     func(p []byte) { p[1] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := query(context.Background(), testServer(t, 0, alter)); ok {
				t.Fatal("accepted invalid NTP response")
			}
		})
	}
}

func TestNtpServersAddsDefaultPort(t *testing.T) {
	servers := ntpServers("time.example, [2001:db8::1]:123")
	if got, want := servers[0], "time.example:123"; got != want {
		t.Fatalf("server = %q, want %q", got, want)
	}
	if got, want := servers[1], "[2001:db8::1]:123"; got != want {
		t.Fatalf("IPv6 server = %q, want %q", got, want)
	}
}
