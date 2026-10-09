//go:build linux

package checks

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ispwatch/collector/internal/clock"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func TestNodeSystemPublishesNTPUnderNodeIdentity(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	t.Setenv("ISPWATCH_NTP_SERVERS", server.LocalAddr().String())
	go func() {
		request := make([]byte, 48)
		_, client, err := server.ReadFromUDP(request)
		if err != nil {
			return
		}
		response := make([]byte, 48)
		response[0], response[1] = 0x24, 1
		copy(response[24:32], request[40:48])
		for _, start := range []int{32, 40} {
			now := time.Now()
			binary.BigEndian.PutUint32(response[start:start+4], uint32(now.Unix()+2208988800))
			binary.BigEndian.PutUint32(response[start+4:start+8], uint32(uint64(now.Nanosecond())*(1<<32)/1_000_000_000))
		}
		server.WriteToUDP(response, client)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan []*collectorv1.Metric, 4)
	StartNodeSystem(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), out, "node-test", "/proc", time.Hour)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case metrics := <-out:
			for _, metric := range metrics {
				if metric.MetricName != "ntp.offset" {
					continue
				}
				if metric.HostId != "node-test" || metric.Source != "ntp" || math.IsNaN(metric.Value) || math.IsInf(metric.Value, 0) || metric.Time == nil {
					t.Fatalf("incorrect NTP metric: %v", metric)
				}
				return
			}
		case <-deadline.C:
			t.Fatal("no node NTP sample")
		}
	}
}

func TestNodeSystemPublishesIntakeIndependentlyOfNTP(t *testing.T) {
	t.Setenv("ISPWATCH_NTP_SERVERS", "127.0.0.1:9")
	now := time.Now()
	clock.ObserveIntakeDate(now.Add(5*time.Second).UTC().Format(http.TimeFormat), now)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := make(chan []*collectorv1.Metric, 4)
	StartNodeSystem(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), out, "node-test", "/proc", time.Hour)
	for {
		select {
		case metrics := <-out:
			for _, metric := range metrics {
				if metric.MetricName == "ntp.intake_offset" {
					if metric.HostId != "node-test" || metric.Source != "ntp" || metric.Value < 4 || metric.Value > 5 || metric.Time.AsTime().Before(now.Add(4*time.Second)) {
						t.Fatalf("invalid intake metric: %v", metric)
					}
					return
				}
			}
		case <-ctx.Done():
			t.Fatal("no intake metric while NTP unavailable")
		}
	}
}
