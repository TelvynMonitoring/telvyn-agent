package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const sqlPostgresObjectStats = `SELECT json_build_object(
'table', COALESCE((SELECT json_agg(json_build_object('schema',s.schemaname,'name',s.relname,'metrics',json_build_object(
'seq_scan',s.seq_scan,'seq_rows_read',s.seq_tup_read,'index_scan',s.idx_scan,'index_rows_fetched',s.idx_tup_fetch,
'rows_inserted',s.n_tup_ins,'rows_updated',s.n_tup_upd,'rows_deleted',s.n_tup_del,
'live_rows',s.n_live_tup,'dead_rows',s.n_dead_tup,'heap_blocks_read',i.heap_blks_read,'heap_blocks_hit',i.heap_blks_hit,
'last_autovacuum_age_seconds',extract(epoch from(now()-s.last_autovacuum)),
'last_autoanalyze_age_seconds',extract(epoch from(now()-s.last_autoanalyze)))))
FROM pg_stat_user_tables s JOIN pg_statio_user_tables i ON i.relid=s.relid),'[]'::json),
'index', COALESCE((SELECT json_agg(json_build_object('schema',s.schemaname,'name',s.indexrelname,'parent',s.relname,'metrics',json_build_object(
'scan',s.idx_scan,'rows_read',s.idx_tup_read,'rows_fetched',s.idx_tup_fetch,'blocks_read',i.idx_blks_read,'blocks_hit',i.idx_blks_hit,
'size_bytes',pg_relation_size(s.indexrelid))))
FROM pg_stat_user_indexes s JOIN pg_statio_user_indexes i ON i.indexrelid=s.indexrelid),'[]'::json),
'function', COALESCE((SELECT json_agg(json_build_object('schema',s.schemaname,'name',s.funcname,'identity',s.funcid::text,'metrics',json_build_object(
'calls',s.calls,'self_time_ms',s.self_time,'total_time_ms',s.total_time))) FROM pg_stat_user_functions s),'[]'::json),
'lock', COALESCE((SELECT json_agg(json_build_object('schema',x.schema,'name',x.name,'identity',x.mode||':'||x.granted::text,'metrics',json_build_object('count',x.count))) FROM (
SELECT COALESCE(n.nspname,'') AS schema,COALESCE(c.relname,l.locktype) AS name,l.mode,l.granted,count(*) AS count FROM pg_locks l LEFT JOIN pg_class c ON c.oid=l.relation LEFT JOIN pg_namespace n ON n.oid=c.relnamespace WHERE l.database IS NULL OR l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) GROUP BY n.nspname,c.relname,l.locktype,l.mode,l.granted) x),'[]'::json),
'wait', COALESCE((SELECT json_agg(json_build_object('schema','','name',x.event_type,'identity',x.event,'metrics',json_build_object('active_connections',x.count))) FROM (
SELECT COALESCE(wait_event_type,'CPU') AS event_type,COALESCE(wait_event,'CPU') AS event,count(*) AS count FROM pg_stat_activity WHERE datname=current_database() AND state='active' GROUP BY wait_event_type,wait_event) x),'[]'::json)
)::text`

type postgresObjectStat struct {
	Schema   string              `json:"schema"`
	Name     string              `json:"name"`
	Parent   string              `json:"parent"`
	Identity string              `json:"identity"`
	Metrics  map[string]*float64 `json:"metrics"`
}

func (c *postgresServer) objectMetrics(ctx context.Context, now *timestamppb.Timestamp) []*collectorv1.Metric {
	qctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()
	var raw string
	if err := c.pool.QueryRow(qctx, sqlPostgresObjectStats).Scan(&raw); err != nil {
		log.Printf("postgres.server[%s]: object statistics unavailable: %v", c.id, err)
		return nil
	}
	var objects map[string][]postgresObjectStat
	if err := json.Unmarshal([]byte(raw), &objects); err != nil {
		log.Printf("postgres.server[%s]: invalid object statistics: %v", c.id, err)
		return nil
	}
	// Extension discovery preserves non-public schemas and leaves other families
	// available when pg_stat_statements is absent or inaccessible.
	capabilities, err := discoverPostgresExtensionRelationCapabilities(ctx, c.pool, "pg_stat_statements", "pg_stat_statements")
	if err == nil && capabilities.available() {
		query := buildPostgresObjectQuerySQL(capabilities)
		if query != "" {
			var queryRaw string
			if c.pool.QueryRow(qctx, query).Scan(&queryRaw) == nil {
				var rows []postgresObjectStat
				if json.Unmarshal([]byte(queryRaw), &rows) == nil {
					objects["query"] = rows
				}
			}
		}
	}
	var out []*collectorv1.Metric
	for kind, rows := range objects {
		for _, row := range rows {
			for name, value := range row.Metrics {
				if value == nil || math.IsNaN(*value) || math.IsInf(*value, 0) {
					continue
				}
				metric := c.metric(now, "postgres.object."+kind+"."+name, *value)
				metric.Tags["schema_name"] = row.Schema
				metric.Tags[kind+"_name"] = row.Name
				if row.Parent != "" {
					metric.Tags["table_name"] = row.Parent
				}
				if row.Identity != "" {
					metric.Tags["object_identity"] = row.Identity
					if kind == "function" {
						metric.Tags["function_oid"] = row.Identity
					}
				}
				out = append(out, metric)
			}
		}
	}
	return out
}

func buildPostgresObjectQuerySQL(capabilities postgresRelationCapabilities) string {
	for _, required := range []string{"dbid", "queryid", "calls", "shared_blks_hit", "shared_blks_read", "shared_blks_dirtied"} {
		if !capabilities.hasColumn(required) {
			return ""
		}
	}
	return fmt.Sprintf(`SELECT COALESCE(json_agg(json_build_object('schema','','name',s.queryid::text,'identity',s.queryid::text,'metrics',json_build_object(
'calls',s.calls,'shared_blocks_hit',s.shared_blks_hit,'shared_blocks_read',s.shared_blks_read,'shared_blocks_dirtied',s.shared_blks_dirtied))), '[]'::json)::text FROM (SELECT * FROM %s WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND calls>0 ORDER BY calls DESC LIMIT 200) s`, capabilities.qualifiedName)
}
