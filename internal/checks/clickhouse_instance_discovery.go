package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type clickhouseClient struct {
	url, user, password string
	http                *http.Client
}

func openClickHouseClient(cfg *collectorv1.CheckConfig) (*clickhouseClient, error) {
	raw := cfg.GetParams()["dsn"]
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("clickhouse: DSN HTTP(S) inválido")
	}
	user, password := "", ""
	if parsed.User != nil {
		user = parsed.User.Username()
		password, _ = parsed.User.Password()
	}
	parsed.User = nil
	query := parsed.Query()
	insecure := query.Get("tls_insecure") == "true"
	query.Del("tls_insecure")
	query.Set("max_execution_time", "5")
	query.Set("max_result_rows", "10001")
	parsed.RawQuery = query.Encode()
	if insecure && parsed.Scheme != "https" {
		return nil, fmt.Errorf("clickhouse: tls_insecure exige HTTPS")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	} // Explicit operator choice: encrypt without identity verification.
	client := &clickhouseClient{parsed.String(), user, password, &http.Client{Transport: transport, Timeout: 10 * time.Second}}
	var probe []map[string]any
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.query(ctx, "SELECT 1 AS value", &probe); err != nil {
		return nil, fmt.Errorf("clickhouse: unreachable: %w", err)
	}
	return client, nil
}

func (c *clickhouseClient) query(ctx context.Context, statement string, dest *[]map[string]any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url,
		bytes.NewBufferString(statement+" FORMAT JSONEachRow"))
	if err != nil {
		return err
	}
	if c.user != "" {
		request.SetBasicAuth(c.user, c.password)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 16<<20))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		var item map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			return err
		}
		*dest = append(*dest, item)
		if len(*dest) > 10001 {
			return fmt.Errorf("clickhouse: limite de 10001 linhas excedido")
		}
	}
	return scanner.Err()
}

type clickhouseInstanceDiscovery struct {
	id, installationID, server string
	port                       int
	interval                   time.Duration
	tags                       map[string]string
	client                     *clickhouseClient
}

func newClickHouseInstanceDiscoveryCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	installationID, _ := databaseIdentity(cfg.GetParams(), cfg.GetStaticTags())
	server := strings.TrimSpace(cfg.GetStaticTags()["db_server"])
	port := postgresInstancePort(cfg.GetStaticTags()["db_port"])
	if installationID == "" || server == "" || port == 0 {
		return nil, fmt.Errorf("clickhouse.instance_discovery: identidade incompleta")
	}
	client, err := openClickHouseClient(cfg)
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	return &clickhouseInstanceDiscovery{cfg.GetCheckId(), installationID, server, port, interval, tags, client}, nil
}

func (c *clickhouseInstanceDiscovery) ID() string              { return c.id }
func (c *clickhouseInstanceDiscovery) Interval() time.Duration { return c.interval }
func (c *clickhouseInstanceDiscovery) Tags() map[string]string { return c.tags }
func (c *clickhouseInstanceDiscovery) Close() error            { c.client.http.CloseIdleConnections(); return nil }
func (c *clickhouseInstanceDiscovery) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunInstanceDiscovery(ctx)
	return nil, err
}

func (c *clickhouseInstanceDiscovery) RunInstanceDiscovery(ctx context.Context) (*DatabaseInstanceDiscovery, error) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var versions []map[string]any
	if err := c.client.query(qctx, "SELECT version() AS version", &versions); err != nil {
		return nil, err
	}
	if len(versions) != 1 {
		return nil, fmt.Errorf("clickhouse: versão indisponível")
	}
	version, _ := versions[0]["version"].(string)
	var databases []map[string]any
	if err := c.client.query(qctx, `SELECT name FROM system.databases
		WHERE name NOT IN ('system','INFORMATION_SCHEMA','information_schema') ORDER BY name`, &databases); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(databases))
	for _, item := range databases {
		if name, ok := item["name"].(string); ok {
			names = append(names, name)
		}
	}
	return &DatabaseInstanceDiscovery{InstallationID: c.installationID, Engine: "clickhouse", Server: c.server,
		Port: c.port, ServerVersion: version, Databases: names}, nil
}

func init() { Default.Register("clickhouse.instance_discovery", newClickHouseInstanceDiscoveryCheck) }
