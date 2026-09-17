package ebpf

import (
	"testing"
	"time"

	"github.com/ispwatch/collector/internal/apm/concentrator"
	"github.com/ispwatch/collector/internal/ebpf/l7"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"inet.af/netaddr"
)

type fakeInboundServerResolver struct {
	endpoint netaddr.IPPort
	calls    int
}

func (r *fakeInboundServerResolver) ResolveInboundServer(_ uint32, _ uint64) (netaddr.IPPort, bool) {
	r.calls++
	return r.endpoint, !r.endpoint.IsZero()
}

func TestBuildSpan_TagsOnlyInboundPostgresWorkloadForConfiguredMonitor(t *testing.T) {
	registry := NewDatabaseMonitorRegistry()
	registry.ApplyPostgresServerDelta([]*collectorv1.CheckConfig{
		postgresMonitorConfig("check-a", "monitor-a", "192.0.2.15", "5432"),
	}, nil)
	resolver := &fakeInboundServerResolver{endpoint: mustIPPort(t, "192.0.2.15", 5432)}
	cfg := BridgeConfig{DatabaseMonitors: registry, InboundServerResolver: resolver}

	span := buildSpan(postgresEvent(77, 11, true), newParsersByConn(), newConnTracker(), cfg)
	if span == nil {
		t.Fatal("expected PostgreSQL span")
	}
	if got := span.Attributes[concentrator.DatabaseMonitorIDAttr]; got != "monitor-a" {
		t.Fatalf("database monitor id = %q, want monitor-a", got)
	}
	if span.Kind != 2 { // SERVER
		t.Fatalf("inbound PostgreSQL span kind = %d, want SERVER (2)", span.Kind)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}
}

func TestBuildSpan_DoesNotTagOutboundPostgresProbe(t *testing.T) {
	registry := NewDatabaseMonitorRegistry()
	registry.ApplyPostgresServerDelta([]*collectorv1.CheckConfig{
		postgresMonitorConfig("check-a", "monitor-a", "192.0.2.15", "5432"),
	}, nil)
	event := postgresEvent(77, 11, false)
	event.DstAddr = mustIPPort(t, "192.0.2.15", 5432)

	span := buildSpan(event, newParsersByConn(), newConnTracker(), BridgeConfig{DatabaseMonitors: registry})
	if span == nil {
		t.Fatal("expected PostgreSQL span")
	}
	if got := span.Attributes[concentrator.DatabaseMonitorIDAttr]; got != "" {
		t.Fatalf("outbound monitor probe must not be attributed, got %q", got)
	}
	if span.Kind != 3 { // CLIENT
		t.Fatalf("outbound PostgreSQL span kind = %d, want CLIENT (3)", span.Kind)
	}
}

func TestBuildSpan_DoesNotTagInboundPostgresWithoutEndpointMatch(t *testing.T) {
	registry := NewDatabaseMonitorRegistry()
	registry.ApplyPostgresServerDelta([]*collectorv1.CheckConfig{
		postgresMonitorConfig("check-a", "monitor-a", "192.0.2.15", "5432"),
	}, nil)
	resolver := &fakeInboundServerResolver{endpoint: mustIPPort(t, "192.0.2.16", 5432)}

	span := buildSpan(postgresEvent(77, 11, true), newParsersByConn(), newConnTracker(), BridgeConfig{
		DatabaseMonitors:     registry,
		InboundServerResolver: resolver,
	})
	if span == nil {
		t.Fatal("expected PostgreSQL span")
	}
	if got := span.Attributes[concentrator.DatabaseMonitorIDAttr]; got != "" {
		t.Fatalf("unmatched endpoint must not be attributed, got %q", got)
	}
}

func TestBuildSpan_CachesInboundEndpointForConnection(t *testing.T) {
	registry := NewDatabaseMonitorRegistry()
	registry.ApplyPostgresServerDelta([]*collectorv1.CheckConfig{
		postgresMonitorConfig("check-a", "monitor-a", "192.0.2.15", "5432"),
	}, nil)
	resolver := &fakeInboundServerResolver{endpoint: mustIPPort(t, "192.0.2.15", 5432)}
	conns := newConnTracker()
	cfg := BridgeConfig{DatabaseMonitors: registry, InboundServerResolver: resolver}

	first := buildSpan(postgresEvent(77, 11, true), newParsersByConn(), conns, cfg)
	second := buildSpan(postgresEvent(77, 11, true), newParsersByConn(), conns, cfg)
	if first == nil || second == nil {
		t.Fatal("expected PostgreSQL spans")
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want cached single lookup", resolver.calls)
	}
}

func postgresEvent(pid uint32, fd uint64, inbound bool) Event {
	payload := append([]byte{'Q', 0, 0, 0, 0}, []byte("SELECT 1\x00")...)
	return Event{
		Type: EventTypeL7Request,
		Pid:  pid,
		Fd:   fd,
		L7Request: &l7.RequestData{
			Protocol:  l7.ProtocolPostgres,
			Duration:  time.Millisecond,
			Payload:   payload,
			IsInbound: inbound,
		},
	}
}

func mustIPPort(t *testing.T, raw string, port uint16) netaddr.IPPort {
	t.Helper()
	ip, err := netaddr.ParseIP(raw)
	if err != nil {
		t.Fatalf("parse IP %q: %v", raw, err)
	}
	return netaddr.IPPortFrom(ip, port)
}
