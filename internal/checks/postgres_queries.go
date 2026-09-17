// postgres_queries.go — coleta agregada de pg_stat_statements.
//
// O check não cria uma série por consulta no VictoriaMetrics. Ele guarda a
// leitura anterior dos contadores cumulativos do Postgres, calcula o delta da
// janela e entrega um lote ao endpoint próprio de query stats.
package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	postgresQueryStatsLimit = 200
	postgresQueryTextLimit  = 4096
)

// DatabaseQueryStat é uma linha de uma janela de coleta. Calls, TotalMS e
// Rows já são deltas; nunca são os contadores cumulativos crus do Postgres.
type DatabaseQueryStat struct {
	QueryID string
	Text    string
	Calls   int64
	TotalMS float64
	MeanMS  float64
	Rows    int64
}

type DatabaseQueryStats struct {
	DBServer      string
	DBName        string
	WindowSeconds int
	Queries       []DatabaseQueryStat
}

// QueryStatsCheck é implementado por checks que têm um canal agregado além de
// métricas nativas. O scheduler o detecta para não executar Run duas vezes.
type QueryStatsCheck interface {
	Check
	RunQueryStats(context.Context) (*DatabaseQueryStats, error)
}

type postgresQueryStatRow struct {
	QueryID string  `json:"query_id"`
	Text    string  `json:"text"`
	Calls   int64   `json:"calls"`
	TotalMS float64 `json:"total_ms"`
	Rows    int64   `json:"rows"`
}

type postgresQueryCounter struct {
	calls   int64
	totalMS float64
	rows    int64
}

type postgresQueries struct {
	id         string
	interval   time.Duration
	hostID     string
	dbServer   string
	dbName     string
	staticTags map[string]string
	pool       pgxPool

	mu       sync.Mutex
	previous map[string]postgresQueryCounter
}

const sqlPostgresQueryStats = `SELECT COALESCE(json_agg(q ORDER BY q.total_ms DESC), '[]'::json)::text
  FROM (
    SELECT s.queryid::text AS query_id,
           s.query AS text,
           s.calls::bigint AS calls,
           s.total_exec_time::float8 AS total_ms,
           s.rows::bigint AS rows
      FROM pg_stat_statements s
      JOIN pg_database d ON d.oid = s.dbid
     WHERE d.datname = current_database()
       AND s.calls > 0
     ORDER BY s.total_exec_time DESC
     LIMIT 200
  ) q`

func newPostgresQueriesCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	return newPostgresQueriesCheckWithFactory(cfg, defaultPgxPoolFactory)
}

func newPostgresQueriesCheckWithFactory(cfg *collectorv1.CheckConfig, factory pgxPoolFactory) (Check, error) {
	pool, err := openPostgresPool(cfg, factory, "postgres.queries")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 60 * time.Second
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}
	server := strings.TrimSpace(tags["db_server"])
	if server == "" {
		pool.Close()
		return nil, fmt.Errorf("postgres.queries: static_tags.db_server obrigatório")
	}
	database := strings.TrimSpace(tags["db_name"])
	id := cfg.GetCheckId()
	if id == "" {
		id = "postgres.queries-" + cfg.GetHostId()
	}
	return &postgresQueries{
		id: id, interval: interval, hostID: cfg.GetHostId(), dbServer: server, dbName: database,
		staticTags: tags, pool: pool, previous: make(map[string]postgresQueryCounter),
	}, nil
}

func (c *postgresQueries) ID() string              { return c.id }
func (c *postgresQueries) Interval() time.Duration { return c.interval }
func (c *postgresQueries) Tags() map[string]string { return c.staticTags }

func (c *postgresQueries) Close() error {
	if c.pool != nil {
		c.pool.Close()
	}
	return nil
}

// Run mantém a interface Check para consumidores legados. O scheduler usa
// RunQueryStats diretamente e publica o lote no sinal db/query-stats.
func (c *postgresQueries) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	_, err := c.RunQueryStats(ctx)
	return nil, err
}

func (c *postgresQueries) RunQueryStats(ctx context.Context) (*DatabaseQueryStats, error) {
	qctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()
	var body string
	if err := c.pool.QueryRow(qctx, sqlPostgresQueryStats).Scan(&body); err != nil {
		log.Printf("postgres.queries[%s]: query failed: %v", c.id, err)
		return nil, err
	}
	var rows []postgresQueryStatRow
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		return nil, fmt.Errorf("postgres.queries: resposta inválida: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	out := &DatabaseQueryStats{
		DBServer: c.dbServer, DBName: c.dbName, WindowSeconds: max(1, int(c.interval/time.Second)),
		Queries: make([]DatabaseQueryStat, 0, len(rows)),
	}
	for _, row := range rows {
		if row.QueryID == "" || row.Calls <= 0 {
			continue
		}
		current := postgresQueryCounter{calls: row.Calls, totalMS: row.TotalMS, rows: row.Rows}
		previous, hadPrevious := c.previous[row.QueryID]
		c.previous[row.QueryID] = current
		if !hadPrevious {
			// A primeira leitura só firma a baseline; não inventa uma janela
			// histórica desde o último restart do Postgres.
			continue
		}
		calls := counterDelta(current.calls, previous.calls)
		totalMS := floatDelta(current.totalMS, previous.totalMS)
		readRows := counterDelta(current.rows, previous.rows)
		if calls <= 0 {
			continue
		}
		text := sanitizeQueryText(row.Text)
		if text == "" {
			text = "(consulta sem texto)"
		}
		out.Queries = append(out.Queries, DatabaseQueryStat{
			QueryID: row.QueryID, Text: text, Calls: calls, TotalMS: totalMS,
			MeanMS: totalMS / float64(calls), Rows: readRows,
		})
	}
	return out, nil
}

func counterDelta(current, previous int64) int64 {
	if current < previous {
		return current // contador reiniciou/foi resetado
	}
	return current - previous
}

func floatDelta(current, previous float64) float64 {
	if current < previous {
		return current
	}
	return current - previous
}

var (
	queryComments = regexp.MustCompile(`(?s)/\*.*?\*/|--[^\r\n]*`)
	queryStrings  = regexp.MustCompile(`'(?:''|[^'])*'`)
	queryNumbers  = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	querySpaces   = regexp.MustCompile(`\s+`)
)

// sanitizeQueryText conserva o formato útil para agrupar/ler a consulta sem
// enviar valores literais e comentários que podem conter dados do cliente.
func sanitizeQueryText(query string) string {
	query = maskDollarQuotedStrings(query)
	query = queryComments.ReplaceAllString(query, " ")
	query = queryStrings.ReplaceAllString(query, "?")
	query = queryNumbers.ReplaceAllString(query, "?")
	query = querySpaces.ReplaceAllString(strings.TrimSpace(query), " ")
	if len(query) > postgresQueryTextLimit {
		query = query[:postgresQueryTextLimit]
	}
	return query
}

// maskDollarQuotedStrings cobre literais PostgreSQL como $$segredo$$ e
// $tag$segredo$tag$. RE2 não oferece backreferences para casar o delimitador de
// abertura/fechamento, então fazemos a leitura curta aqui antes das regexes.
// Delimitador sem fechamento é mascarado até o fim por segurança.
func maskDollarQuotedStrings(query string) string {
	var out strings.Builder
	out.Grow(len(query))
	for index := 0; index < len(query); {
		if query[index] != '$' {
			out.WriteByte(query[index])
			index++
			continue
		}
		end := index + 1
		if end < len(query) && query[end] != '$' {
			if !isDollarTagStart(query[end]) {
				out.WriteByte(query[index])
				index++
				continue
			}
			end++
			for end < len(query) && query[end] != '$' && isDollarTagPart(query[end]) {
				end++
			}
		}
		if end >= len(query) || query[end] != '$' {
			out.WriteByte(query[index])
			index++
			continue
		}
		delimiter := query[index : end+1]
		closing := strings.Index(query[end+1:], delimiter)
		out.WriteByte('?')
		if closing < 0 {
			return out.String()
		}
		index = end + 1 + closing + len(delimiter)
	}
	return out.String()
}

func isDollarTagStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isDollarTagPart(value byte) bool {
	return isDollarTagStart(value) || value >= '0' && value <= '9'
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func init() {
	Default.Register("postgres.queries", newPostgresQueriesCheck)
}
