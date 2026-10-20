package checks

import (
	"context"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Um pool por database monitorado (mesma DSN): cada database descoberto ganha suas checagens (server, queries,
// catálogo, diagnóstico, explain, custom, descoberta) e, com um pool por checagem, dois databases já abriam mais de
// dez conexões, acima do CONNECTION LIMIT comum para o usuário de monitoramento. No PostgreSQL a conexão pertence a
// um database, então o compartilhamento é por DSN e cada database usa no máximo postgresMaxConns conexões.
type pgxSharedPool struct {
	pool *pgxpool.Pool
	refs int
}

var pgxPools = struct {
	sync.Mutex
	byDSN map[string]*pgxSharedPool
}{byDSN: map[string]*pgxSharedPool{}}

func sharedPgxPool(ctx context.Context, dsn string) (pgxPool, error) {
	pgxPools.Lock()
	defer pgxPools.Unlock()
	shared := pgxPools.byDSN[dsn]
	if shared == nil {
		pool, err := newPgxPool(ctx, dsn)
		if err != nil {
			return nil, err
		}
		shared = &pgxSharedPool{pool: pool}
		pgxPools.byDSN[dsn] = shared
	}
	shared.refs++
	return &pgxPoolShare{shared: shared, dsn: dsn}, nil
}

// pgxPoolShare é a parte de uma checagem no pool do database; Close só fecha o pool na última parte.
type pgxPoolShare struct {
	shared *pgxSharedPool
	dsn    string
	once   sync.Once
}

func (s *pgxPoolShare) Ping(ctx context.Context) error { return s.shared.pool.Ping(ctx) }

func (s *pgxPoolShare) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return s.shared.pool.QueryRow(ctx, sql, args...)
}

func (s *pgxPoolShare) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	return s.shared.pool.BeginTx(ctx, options)
}

func (s *pgxPoolShare) Close() {
	s.once.Do(func() {
		pgxPools.Lock()
		defer pgxPools.Unlock()
		s.shared.refs--
		if s.shared.refs == 0 {
			delete(pgxPools.byDSN, s.dsn)
			s.shared.pool.Close()
		}
	})
}
