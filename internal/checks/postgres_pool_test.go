package checks

import (
	"context"
	"testing"
)

func TestSharedPgxPoolOnePoolPerDSN(t *testing.T) {
	ctx := context.Background()
	dsn := "postgres://telvyn@127.0.0.1:1/marketplace?sslmode=disable"
	other := "postgres://telvyn@127.0.0.1:1/postgres?sslmode=disable"

	a, err := sharedPgxPool(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b, err := sharedPgxPool(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	c, err := sharedPgxPool(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if a.(*pgxPoolShare).shared != b.(*pgxPoolShare).shared {
		t.Fatal("checks of the same database must share one pool")
	}
	if a.(*pgxPoolShare).shared == c.(*pgxPoolShare).shared {
		t.Fatal("each database keeps its own pool")
	}

	a.Close()
	a.Close() // idempotent: must not release b's share
	pgxPools.Lock()
	_, open := pgxPools.byDSN[dsn]
	pgxPools.Unlock()
	if !open {
		t.Fatal("pool closed while another check still uses it")
	}
	b.Close()
	c.Close()
	pgxPools.Lock()
	left := len(pgxPools.byDSN)
	pgxPools.Unlock()
	if left != 0 {
		t.Fatalf("pools left open after the last check closed: %d", left)
	}
}
