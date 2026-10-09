package checks

import (
	"context"
	"encoding/json"
	"log"
	"math"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Native counters are emitted unchanged; rates belong to the backend.
// JSON field lookup keeps fields removed in PostgreSQL 17 absent, not zero.
const sqlPostgresExtendedStats = `WITH db AS (
 SELECT to_jsonb(s) AS s FROM pg_stat_database s WHERE datname=current_database()
), writer AS (SELECT to_jsonb(s) AS s FROM pg_stat_bgwriter s),
 tables AS (SELECT sum(seq_scan) seq_scans, sum(idx_scan) index_scans,
 sum(n_live_tup) live_rows, sum(n_dead_tup) dead_rows FROM pg_stat_user_tables),
 indexes AS (SELECT sum(idx_blks_hit) hits, sum(idx_blks_read) reads FROM pg_statio_user_indexes),
 functions AS (SELECT sum(calls) calls, sum(self_time) self_ms, sum(total_time) total_ms FROM pg_stat_user_functions)
SELECT json_build_object(
 'rows_returned',db.s->'tup_returned','rows_fetched',db.s->'tup_fetched',
 'rows_inserted',db.s->'tup_inserted','rows_updated',db.s->'tup_updated','rows_deleted',db.s->'tup_deleted',
 'blocks_hit',db.s->'blks_hit','blocks_read',db.s->'blks_read',
 'block_read_time_ms',db.s->'blk_read_time','block_write_time_ms',db.s->'blk_write_time',
 'seq_scans',tables.seq_scans,'index_scans',tables.index_scans,
 'live_rows',tables.live_rows,'dead_rows',tables.dead_rows,
 'index_blocks_hit',indexes.hits,'index_blocks_read',indexes.reads,
 'function_calls',functions.calls,'function_self_time_ms',functions.self_ms,'function_total_time_ms',functions.total_ms,
 'checkpoints_scheduled',writer.s->'checkpoints_timed','checkpoints_requested',writer.s->'checkpoints_req',
 'checkpoint_write_time_ms',writer.s->'checkpoint_write_time','checkpoint_sync_time_ms',writer.s->'checkpoint_sync_time',
 'buffers_checkpoint',writer.s->'buffers_checkpoint','buffers_allocated',writer.s->'buffers_alloc',
 'buffers_bgwriter',writer.s->'buffers_clean','buffers_backend',writer.s->'buffers_backend'
)::text FROM db CROSS JOIN writer CROSS JOIN tables CROSS JOIN indexes CROSS JOIN functions`

func (c *postgresServer) extendedMetrics(ctx context.Context, now *timestamppb.Timestamp) []*collectorv1.Metric {
	qctx, cancel := context.WithTimeout(ctx, postgresQueryTimeout)
	defer cancel()
	var raw string
	if err := c.pool.QueryRow(qctx, sqlPostgresExtendedStats).Scan(&raw); err != nil {
		log.Printf("postgres.server[%s]: extended statistics unavailable: %v", c.id, err)
		return nil
	}
	var values map[string]*float64
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		log.Printf("postgres.server[%s]: invalid extended statistics: %v", c.id, err)
		return nil
	}
	out := make([]*collectorv1.Metric, 0, len(values))
	for name, value := range values {
		if value == nil || math.IsNaN(*value) || math.IsInf(*value, 0) {
			continue
		}
		out = append(out, c.metric(now, "postgres."+name, *value))
	}
	return out
}
