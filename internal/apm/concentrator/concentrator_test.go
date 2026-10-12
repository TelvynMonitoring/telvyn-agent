package concentrator

import (
	"testing"

	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/DataDog/sketches-go/ddsketch/store"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const ms = int64(1_000_000) // 1ms em nanos

func TestExactMaximumIncludesErrorsAndZeroDuration(t *testing.T) {
	c := New(nil)
	base := int64(1700000000000000000)
	for _, duration := range []int64{0, ms, 1234567} {
		c.Add(span("api", base, base+duration, 2, nil))
	}
	g := c.Flush()[0]
	if g.MaxDurationNano != 1234567 || g.Hits != 3 {
		t.Fatalf("maximum/count = %+v", g)
	}
}

func TestVersionsAreSeparatedBeforeSamplingAndResourceNameWins(t *testing.T) {
	c := New(nil)
	base := int64(1700000000000000000)
	for _, version := range []string{"v1", "v2", ""} {
		c.Add(span("api", base, base+ms, 1, map[string]string{"service.version": version, "resource.name": "GET /orders/{id}", "http.method": "GET", "http.route": "/wrong"}))
	}
	groups := c.Flush()
	if len(groups) != 3 {
		t.Fatalf("versions merged: %+v", groups)
	}
	versions := map[string]bool{}
	for _, group := range groups {
		versions[group.ServiceVersion] = true
		if group.Resource != "GET /orders/{id}" || group.Hits != 1 {
			t.Fatalf("resource/count incorrect: %+v", group)
		}
	}
	if !versions["v1"] || !versions["v2"] || !versions[""] {
		t.Fatal("unknown version was guessed")
	}
}

func TestPeerBucketsKeepDatabaseInstancesSeparate(t *testing.T) {
	c := New(nil)
	for _, host := range []string{"db-a", "db-b"} {
		s := span("api", 1700000000000000000, 1700000000000000000+ms, 1, map[string]string{"db.system": "postgresql", "server.address": host, "server.port": "5432"})
		s.Kind = 3
		c.Add(s)
	}
	groups := c.Flush()
	if len(groups) != 2 || groups[0].Peer == groups[1].Peer {
		t.Fatalf("peers collapsed: %+v", groups)
	}
}

func span(service string, start, end int64, status int32, attrs map[string]string) *collectorv1.Span {
	return &collectorv1.Span{
		ServiceName:   service,
		Name:          "GET /x",
		Kind:          2, // SERVER
		StartUnixNano: start,
		EndUnixNano:   end,
		StatusCode:    status,
		Attributes:    attrs,
	}
}

func TestConcentrator_HitsErrorsEQuantis(t *testing.T) {
	c := New(nil)
	base := int64(1_700_000_000_000_000_000) // alinhado a 10s
	// 4 OK (10,20,30,40ms) + 1 erro (100ms) no mesmo bucket/grupo
	c.Add(span("svc", base, base+10*ms, 1, nil))
	c.Add(span("svc", base, base+20*ms, 1, nil))
	c.Add(span("svc", base, base+30*ms, 1, nil))
	c.Add(span("svc", base, base+40*ms, 1, nil))
	c.Add(span("svc", base, base+100*ms, 2, nil)) // erro

	out := c.Flush()
	if len(out) != 1 {
		t.Fatalf("esperava 1 grupo, veio %d", len(out))
	}
	g := out[0]
	if g.Hits != 5 || g.Errors != 1 {
		t.Fatalf("hits/errors errados: hits=%d errors=%d", g.Hits, g.Errors)
	}
	if g.Service != "svc" || !g.TopLevel {
		t.Fatalf("service/topLevel errados: %q topLevel=%v", g.Service, g.TopLevel)
	}
	if g.DurationSumNano != uint64((10+20+30+40+100)*ms) {
		t.Fatalf("durationSum errado: %d", g.DurationSumNano)
	}
	// p95 das OK deve cair na cauda alta (entre ~30 e 40ms; o DDSketch tem 1%
	// de erro relativo, então o piso é folgado).
	okP95 := quantile(t, g.OkSummary, 0.95)
	if okP95 < 25*float64(ms) || okP95 > 41*float64(ms) {
		t.Fatalf("p95 OK fora da faixa: %.0f ns", okP95)
	}
	// o sketch de erro tem só 1 valor (100ms)
	errP50 := quantile(t, g.ErrorSummary, 0.5)
	if errP50 < 99*float64(ms) || errP50 > 101*float64(ms) {
		t.Fatalf("p50 erro fora da faixa: %.0f ns", errP50)
	}
	// flush zerou o estado
	if got := len(c.Flush()); got != 0 {
		t.Fatalf("flush não zerou: %d", got)
	}
}

func TestConcentrator_BucketsSeparados(t *testing.T) {
	c := New(nil)
	b1 := int64(1_700_000_000_000_000_000) // alinhado
	b2 := b1 + int64(BucketDuration) + 1   // próximo bucket de 10s
	c.Add(span("svc", b1, b1+ms, 1, nil))
	c.Add(span("svc", b2, b2+ms, 1, nil))
	if got := len(c.Flush()); got != 2 {
		t.Fatalf("esperava 2 buckets, veio %d", got)
	}
}

func TestConcentrator_AgrupaPorHTTPStatusEResource(t *testing.T) {
	c := New(nil)
	base := int64(1_700_000_000_000_000_000)
	c.Add(span("svc", base, base+ms, 1, map[string]string{"http.request.method": "GET", "http.route": "/a", "http.response.status_code": "200"}))
	c.Add(span("svc", base, base+ms, 1, map[string]string{"http.request.method": "GET", "http.route": "/a", "http.response.status_code": "500"}))
	out := c.Flush()
	if len(out) != 2 { // mesmo resource, status diferente → 2 grupos
		t.Fatalf("esperava 2 grupos por status, veio %d", len(out))
	}
	for _, g := range out {
		if g.Resource != "GET /a" {
			t.Fatalf("resource errado: %q", g.Resource)
		}
	}
}

func TestConcentrator_SeparatesDatabaseMonitorIdentity(t *testing.T) {
	c := New(nil)
	base := int64(1_700_000_000_000_000_000)
	c.Add(span("postgres", base, base+ms, 1, map[string]string{
		"db.system":           "postgresql",
		DatabaseMonitorIDAttr: "monitor-a",
	}))
	c.Add(span("postgres", base, base+ms, 1, map[string]string{
		"db.system":           "postgresql",
		DatabaseMonitorIDAttr: "monitor-b",
	}))

	out := c.Flush()
	if len(out) != 2 {
		t.Fatalf("expected separate groups for monitors, got %d", len(out))
	}
	seen := map[string]bool{}
	for _, group := range out {
		seen[group.DatabaseMonitorID] = true
		if group.Hits != 1 || group.DbSystem != "postgresql" {
			t.Fatalf("unexpected group: %+v", group)
		}
	}
	if !seen["monitor-a"] || !seen["monitor-b"] {
		t.Fatalf("monitor identities missing from groups: %#v", seen)
	}
}

func quantile(t *testing.T, encoded []byte, q float64) float64 {
	t.Helper()
	if len(encoded) == 0 {
		t.Fatalf("sketch vazio")
	}
	s, err := ddsketch.DecodeDDSketch(encoded, store.DefaultProvider, nil)
	if err != nil {
		t.Fatalf("decode falhou: %v", err)
	}
	v, err := s.GetValueAtQuantile(q)
	if err != nil {
		t.Fatalf("quantile falhou: %v", err)
	}
	return v
}

func TestOutboundEbpfStatsUseClientIdentity(t *testing.T) {
	c := New(nil)
	base := int64(1_700_000_000_000_000_000)
	s := span("redis-pod", base, base+ms, 1, map[string]string{
		SourceAttr: "ebpf", "client.pod": "api-pod", "server.pod": "redis-pod", "db.system": "redis",
	})
	s.Kind = 3
	c.Add(s)
	out := c.Flush()
	if len(out) != 1 || out[0].Service != "api-pod" || out[0].Peer != "redis-pod" || out[0].TopLevel {
		t.Fatalf("outbound client/destination lost: %+v", out)
	}
	if s.ServiceName != "redis-pod" {
		t.Fatal("query owner must remain unchanged")
	}
}

func TestPeerDoesNotInventUnspecifiedEndpoints(t *testing.T) {
	for _, host := range []string{"::", "0.0.0.0"} {
		s := &collectorv1.Span{Kind: 3, Attributes: map[string]string{"net.peer.ip": host, "net.peer.port": "0"}}
		if peer := peerOf(s); peer != "" {
			t.Fatalf("unspecified address became dependency: %q", peer)
		}
	}
}
