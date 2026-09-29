package checks

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type oracleServer struct {
	id, hostID string
	interval   time.Duration
	tags       map[string]string
	pool       sqlDatabasePool
}

func newOracleServerCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	if strings.TrimSpace(cfg.GetStaticTags()["db_name"]) == "" {
		return nil, fmt.Errorf("oracle.server: db_name obrigatório")
	}
	pool, err := openSQLDatabasePool(cfg, defaultOraclePoolFactory, "oracle.server")
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = time.Minute
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	return &oracleServer{cfg.GetCheckId(), cfg.GetHostId(), interval, tags, pool}, nil
}

func (c *oracleServer) ID() string              { return c.id }
func (c *oracleServer) Interval() time.Duration { return c.interval }
func (c *oracleServer) Tags() map[string]string { return c.tags }
func (c *oracleServer) Close() error            { return c.pool.Close() }

func (c *oracleServer) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	now := timestamppb.Now()
	metrics := make([]*collectorv1.Metric, 0, 10)
	read := func(name, query string) (float64, bool) {
		var value sql.NullFloat64
		if err := c.pool.QueryRow(qctx, query).Scan(&value); err != nil || !value.Valid {
			return 0, false
		}
		metrics = append(metrics, &collectorv1.Metric{
			Time: now, HostId: c.hostID, MetricName: "oracle." + name,
			Value: value.Float64, Tags: c.tags, Source: "oracle.server",
		})
		return value.Float64, true
	}
	read("active_connections", "SELECT COUNT(*) FROM V$SESSION WHERE TYPE='USER' AND STATUS='ACTIVE'")
	read("total_connections", "SELECT COUNT(*) FROM V$SESSION WHERE TYPE='USER'")
	read("max_connections", "SELECT TO_NUMBER(VALUE) FROM V$PARAMETER WHERE NAME='sessions'")
	read("locks_waiting", "SELECT COUNT(*) FROM V$SESSION WHERE BLOCKING_SESSION IS NOT NULL")
	read("database_size_bytes", "SELECT COALESCE(SUM(BYTES),0) FROM DBA_SEGMENTS")
	read("commits", "SELECT VALUE FROM V$SYSSTAT WHERE NAME='user commits'")
	read("rollbacks", "SELECT VALUE FROM V$SYSSTAT WHERE NAME='user rollbacks'")
	physical, physicalOK := read("physical_reads", "SELECT VALUE FROM V$SYSSTAT WHERE NAME='physical reads'")
	gets, getsOK := read("db_block_gets", "SELECT VALUE FROM V$SYSSTAT WHERE NAME='db block gets'")
	consistent, consistentOK := read("consistent_gets", "SELECT VALUE FROM V$SYSSTAT WHERE NAME='consistent gets'")
	if physicalOK && getsOK && consistentOK && gets+consistent > 0 {
		ratio := 1 - physical/(gets+consistent)
		if ratio < 0 {
			ratio = 0
		}
		metrics = append(metrics, &collectorv1.Metric{
			Time: now, HostId: c.hostID, MetricName: "oracle.cache_hit_ratio",
			Value: ratio, Tags: c.tags, Source: "oracle.server",
		})
	}
	if len(metrics) == 0 {
		return nil, fmt.Errorf("oracle.server: nenhuma métrica disponível")
	}
	return metrics, nil
}

func init() { Default.Register("oracle.server", newOracleServerCheck) }
