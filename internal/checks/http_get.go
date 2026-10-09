// http_get.go — Check "http.get" para link_probe.
//
// Faz GET HTTP/HTTPS contra um endpoint conhecido (captive-portal canary
// ou asset estatico publico) e captura o pipeline de timings via
// httptrace, distinguindo onde o link engasga: DNS, TCP, TLS, ou
// recebimento do response.
//
// Metricas:
//   http.status        - status code (-1 quando o request nem completou)
//   http.success       - 0/1 (1 = 2xx/3xx; 0 = >=400 ou erro de rede)
//   http.dns_ms        - tempo de resolucao DNS
//   http.connect_ms    - tempo de TCP handshake
//   http.tls_ms        - tempo de TLS handshake (0 se http://)
//   http.ttfb_ms       - first byte recebido (dns + connect + tls + server)
//   http.total_ms      - tempo ate fechar o body
//   http.size_bytes    - bytes recebidos no body
//
// Params:
//   target           - URL completa (http:// ou https://)
//   method           - default GET
//   source_iface/ip  - source binding
//   timeout_ms       - default 5000

package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type httpGetCheck struct {
	id             string
	interval       time.Duration
	hostID         string
	target         string
	method         string
	timeout        time.Duration
	sourceIface    string
	sourceIP       string
	staticTags     map[string]string
	expectedStatus int
	bodyContains   string
	headerName     string
	headerValue    string
	maxResponseMs  int
}

func newHTTPGetCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	target := strings.TrimSpace(params["target"])
	if target == "" {
		return nil, fmt.Errorf("http.get: missing param 'target'")
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return nil, fmt.Errorf("http.get: target must begin with http:// or https://")
	}

	method := strings.ToUpper(strings.TrimSpace(params["method"]))
	if method == "" {
		method = "GET"
	}
	expectedStatus, err := optionalHTTPInt(params["expected_status"], 100, 599)
	if err != nil {
		return nil, err
	}
	maxResponseMs, err := optionalHTTPInt(params["max_response_ms"], 1, 300000)
	if err != nil {
		return nil, err
	}
	if len(params["body_contains"]) > 4096 || len(params["expected_header_value"]) > 4096 {
		return nil, fmt.Errorf("http.get: assertion exceeds 4096 bytes")
	}
	headerName := strings.TrimSpace(params["expected_header_name"])
	if strings.ContainsAny(headerName, "\r\n:") || len(headerName) > 256 || (headerName == "" && params["expected_header_value"] != "") {
		return nil, fmt.Errorf("http.get: invalid assertion header")
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 60 * time.Second
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "http.get-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &httpGetCheck{
		id:             id,
		interval:       interval,
		hostID:         cfg.GetHostId(),
		target:         target,
		method:         method,
		timeout:        parseTimeoutMs(params, 5000),
		sourceIface:    params["source_iface"],
		sourceIP:       params["source_ip"],
		staticTags:     tags,
		expectedStatus: expectedStatus,
		bodyContains:   params["body_contains"],
		headerName:     headerName,
		headerValue:    params["expected_header_value"],
		maxResponseMs:  maxResponseMs,
	}, nil
}

func (c *httpGetCheck) ID() string              { return c.id }
func (c *httpGetCheck) Interval() time.Duration { return c.interval }
func (c *httpGetCheck) Tags() map[string]string { return c.staticTags }

func (c *httpGetCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	dialer := newBindingDialer(c.sourceIface, c.sourceIP, c.timeout)

	// Transport dedicado por run pra que o source binding nao vaze entre
	// probes (cada link tem o seu) e pra evitar reuso de conexao entre
	// ciclos — queremos medir DNS+TCP+TLS frescos a cada coleta.
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
		IdleConnTimeout:       1 * time.Second,
		ResponseHeaderTimeout: c.timeout,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		},
		TLSHandshakeTimeout: c.timeout,
	}
	client := &http.Client{
		Timeout:   c.timeout,
		Transport: transport,
	}
	defer transport.CloseIdleConnections()

	var (
		dnsStart, connectStart, tlsStart, gotFirstByte time.Time
		dnsMs, connectMs, tlsMs, ttfbMs                float64
	)
	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:           func(httptrace.DNSDoneInfo) { dnsMs = sinceMs(dnsStart) },
		ConnectStart:      func(string, string) { connectStart = time.Now() },
		ConnectDone:       func(string, string, error) { connectMs = sinceMs(connectStart) },
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { tlsMs = sinceMs(tlsStart) },
		GotFirstResponseByte: func() {
			gotFirstByte = time.Now()
		},
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	reqCtx = httptrace.WithClientTrace(reqCtx, trace)

	req, err := http.NewRequestWithContext(reqCtx, c.method, c.target, nil)
	if err != nil {
		now := timestamppb.Now()
		return []*collectorv1.Metric{
			c.metric(now, "http.status", -1),
			c.metric(now, "http.success", 0),
		}, nil
	}
	req.Header.Set("User-Agent", "ispwatch-collector/link-probe")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		now := timestamppb.Now()
		return []*collectorv1.Metric{
			c.metric(now, "http.status", -1),
			c.metric(now, "http.success", 0),
			c.metric(now, "http.dns_ms", dnsMs),
			c.metric(now, "http.connect_ms", connectMs),
			c.metric(now, "http.tls_ms", tlsMs),
		}, nil
	}
	defer resp.Body.Close()

	if !gotFirstByte.IsZero() {
		ttfbMs = float64(gotFirstByte.Sub(start)) / float64(time.Millisecond)
	}

	// Le body inteiro pra contabilizar size + total. Limita a 1MB pra nao
	// queimar memoria com endpoints inesperadamente grandes.
	const maxBody = 1 << 20
	var n int64
	var body []byte
	var bodyErr error
	if c.bodyContains != "" {
		body, bodyErr = io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		n = int64(len(body))
	} else {
		n, bodyErr = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody+1))
	}
	totalMs := float64(time.Since(start)) / float64(time.Millisecond)

	status := resp.StatusCode
	successFlag := 0.0
	if status >= 200 && status < 400 {
		successFlag = 1.0
	}
	if c.expectedStatus != 0 {
		successFlag = 0
		if status == c.expectedStatus {
			successFlag = 1
		}
	}
	if bodyErr != nil || (c.bodyContains != "" && (n > maxBody || !strings.Contains(string(body), c.bodyContains))) ||
		(c.headerName != "" && (len(resp.Header.Values(c.headerName)) == 0 || resp.Header.Get(c.headerName) != c.headerValue)) ||
		(c.maxResponseMs != 0 && totalMs > float64(c.maxResponseMs)) {
		successFlag = 0
	}

	now := timestamppb.Now()
	return []*collectorv1.Metric{
		c.metric(now, "http.status", float64(status)),
		c.metric(now, "http.success", successFlag),
		c.metric(now, "http.dns_ms", dnsMs),
		c.metric(now, "http.connect_ms", connectMs),
		c.metric(now, "http.tls_ms", tlsMs),
		c.metric(now, "http.ttfb_ms", ttfbMs),
		c.metric(now, "http.total_ms", totalMs),
		c.metric(now, "http.size_bytes", float64(n)),
	}, nil
}

func optionalHTTPInt(value string, min, max int) (int, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("http.get: invalid numeric assertion")
	}
	return n, nil
}

func (c *httpGetCheck) metric(t *timestamppb.Timestamp, name string, value float64) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags)+2)
	for k, v := range c.staticTags {
		tags[k] = v
	}
	tags["target"] = c.target
	tags["method"] = c.method
	return &collectorv1.Metric{
		Time:       t,
		HostId:     c.hostID,
		MetricName: name,
		Value:      value,
		Tags:       tags,
		Source:     "http",
	}
}

func sinceMs(start time.Time) float64 {
	if start.IsZero() {
		return 0
	}
	return float64(time.Since(start)) / float64(time.Millisecond)
}

// Ensure net imported (used indirectly via Dialer).
var _ = net.IPv4zero

func init() {
	Default.Register("http.get", newHTTPGetCheck)
}
