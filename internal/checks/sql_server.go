package checks

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	sqlDatabaseQueryTimeout = 5 * time.Second
	sqlDatabasePingTimeout  = 3 * time.Second
)

// sqlDatabaseRow e sqlDatabasePool mantêm os checks SQL testáveis sem abrir
// conexão TCP. Cada engine continua responsável pelas suas queries e métricas.
type sqlDatabaseRow interface {
	Scan(...any) error
}

type sqlDatabasePool interface {
	Ping(context.Context) error
	QueryRow(context.Context, string, ...any) sqlDatabaseRow
	Close() error
}

type sqlDatabasePoolFactory func(context.Context, string) (sqlDatabasePool, error)

type realSQLDatabasePool struct {
	db *sql.DB
}

func (p *realSQLDatabasePool) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

func (p *realSQLDatabasePool) QueryRow(ctx context.Context, query string, args ...any) sqlDatabaseRow {
	return p.db.QueryRowContext(ctx, query, args...)
}

func (p *realSQLDatabasePool) Close() error {
	return p.db.Close()
}

func defaultSQLDatabasePoolFactory(driver string) sqlDatabasePoolFactory {
	return func(_ context.Context, dsn string) (sqlDatabasePool, error) {
		db, err := sql.Open(driver, dsn)
		if err != nil {
			return nil, fmt.Errorf("DSN inválido: %w", err)
		}
		// Cada check tem o seu pool. Duas conexões bastam para as consultas
		// sequenciais e evitam pressionar o banco de produção.
		db.SetMaxOpenConns(2)
		db.SetMaxIdleConns(1)
		db.SetConnMaxIdleTime(time.Minute)
		return &realSQLDatabasePool{db: db}, nil
	}
}

func openSQLDatabasePool(cfg *collectorv1.CheckConfig, factory sqlDatabasePoolFactory, kind string) (sqlDatabasePool, error) {
	dsn := cfg.GetParams()["dsn"]
	if dsn == "" {
		return nil, fmt.Errorf("%s: param 'dsn' obrigatório", kind)
	}
	pool, err := factory(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), sqlDatabasePingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("%s: unreachable: %w", kind, err)
	}
	return pool, nil
}
