package sendbuf

import (
	"context"
	"fmt"
	"log/slog"

	bolt "go.etcd.io/bbolt"
)

// NewDurable requires disk retention; callers must not advance source cursors on failure.
func NewDurable(name string, maxBytes int, dir string, log *slog.Logger) (*Queue, error) {
	q := NewPersistent(name, maxBytes, dir, log)
	if q.db == nil {
		return nil, fmt.Errorf("durable queue %s unavailable", name)
	}
	return q, nil
}

// OfferDurable refuses a full queue instead of evicting unacknowledged records.
func (q *Queue) OfferDurable(body []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.db == nil {
		return fmt.Errorf("durable queue closed")
	}
	stats := q.snapshotPersistentLocked()
	if stats.Bytes+len(body) > q.maxBytes {
		return fmt.Errorf("durable queue full: %d bytes", stats.Bytes)
	}
	return q.offerPersistentLocked(body)
}

// FlushBatch retains every unacknowledged record, including rejected HTTP requests.
// The caller serializes offers and flushes; deletion commits only after a successful POST.
func (q *Queue) FlushBatch(ctx context.Context, limit int, post func(context.Context, [][]byte) error) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.db == nil {
		return fmt.Errorf("durable queue closed")
	}
	if limit < 1 {
		return fmt.Errorf("invalid batch size")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var bodies, keys [][]byte
		size := 0
		err := q.db.View(func(tx *bolt.Tx) error {
			cursor := tx.Bucket(payloadsBucket).Cursor()
			for key, value := cursor.First(); key != nil && len(bodies) < limit; key, value = cursor.Next() {
				keys = append(keys, append([]byte(nil), key...))
				bodies = append(bodies, append([]byte(nil), value...))
				size += len(value)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(bodies) == 0 {
			return nil
		}
		q.updateCounterLocked(metaRetries)
		if err := post(ctx, bodies); err != nil {
			return err
		}
		if err := q.db.Update(func(tx *bolt.Tx) error {
			bucket, meta := tx.Bucket(payloadsBucket), tx.Bucket(metaBucket)
			for _, key := range keys {
				if err := bucket.Delete(key); err != nil {
					return err
				}
			}
			if err := writeMeta(meta, metaCount, readMeta(meta, metaCount)-uint64(len(keys))); err != nil {
				return err
			}
			if err := writeMeta(meta, metaBytes, readMeta(meta, metaBytes)-uint64(size)); err != nil {
				return err
			}
			return writeMeta(meta, metaRetryOK, readMeta(meta, metaRetryOK)+1)
		}); err != nil {
			return err
		}
	}
}
