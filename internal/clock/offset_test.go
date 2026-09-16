//go:build linux

package clock

import (
	"context"
	"math"
	"net"
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

func TestNtpServersAddsDefaultPort(t *testing.T) {
	servers := ntpServers("time.example, [2001:db8::1]:123")
	if got, want := servers[0], "time.example:123"; got != want {
		t.Fatalf("server = %q, want %q", got, want)
	}
	if got, want := servers[1], "[2001:db8::1]:123"; got != want {
		t.Fatalf("IPv6 server = %q, want %q", got, want)
	}
}
