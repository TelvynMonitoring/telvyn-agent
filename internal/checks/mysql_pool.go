package checks

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Um pool por servidor MySQL/MariaDB, como o Datadog: o usuário de monitoramento costuma ser criado com
// MAX_USER_CONNECTIONS 5, e cada database descoberto ganha suas próprias checagens (server, queries, catálogo,
// diagnóstico). Com um pool por checagem, dois databases já abriam até 18 conexões. Todas as checagens do mesmo
// servidor (host, porta, usuário e parâmetros) dividem mysqlServerMaxConns conexões; cada uma continua vendo o
// seu database porque a conexão emprestada recebe USE antes da consulta. Nenhuma checagem segura duas conexões
// ao mesmo tempo, então elas só esperam umas pelas outras.
const mysqlServerMaxConns = 2

type mysqlSharedServer struct {
	db   *sql.DB
	refs int
}

var mysqlServers = struct {
	sync.Mutex
	byKey map[string]*mysqlSharedServer
}{byKey: map[string]*mysqlSharedServer{}}

var defaultMySQLPoolFactory sqlDatabasePoolFactory = func(_ context.Context, dsn string) (sqlDatabasePool, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("DSN inválido: %w", err)
	}
	database := cfg.DBName
	cfg.DBName = ""
	key := cfg.FormatDSN()
	mysqlServers.Lock()
	defer mysqlServers.Unlock()
	server := mysqlServers.byKey[key]
	if server == nil {
		db, err := sql.Open("mysql", key)
		if err != nil {
			return nil, fmt.Errorf("DSN inválido: %w", err)
		}
		db.SetMaxOpenConns(mysqlServerMaxConns)
		db.SetMaxIdleConns(mysqlServerMaxConns)
		db.SetConnMaxIdleTime(time.Minute)
		server = &mysqlSharedServer{db: db}
		mysqlServers.byKey[key] = server
	}
	server.refs++
	return &mysqlDatabasePool{server: server, key: key, database: database}, nil
}

// mysqlDatabasePool é a visão de uma checagem sobre o pool do servidor: as consultas rodam no database dela.
type mysqlDatabasePool struct {
	server   *mysqlSharedServer
	key      string
	database string
	once     sync.Once
}

// conn empresta uma conexão do servidor já apontada para o database da checagem. A descoberta de databases não
// tem database e não depende do atual.
func (p *mysqlDatabasePool) conn(ctx context.Context) (*sql.Conn, error) {
	conn, err := p.server.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if p.database != "" {
		if _, err := conn.ExecContext(ctx, "USE `"+strings.ReplaceAll(p.database, "`", "``")+"`"); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func (p *mysqlDatabasePool) Ping(ctx context.Context) error {
	conn, err := p.conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.PingContext(ctx)
}

func (p *mysqlDatabasePool) QueryRow(ctx context.Context, query string, args ...any) sqlDatabaseRow {
	conn, err := p.conn(ctx)
	if err != nil {
		return mysqlConnRow{err: err}
	}
	return mysqlConnRow{row: conn.QueryRowContext(ctx, query, args...), conn: conn}
}

func (p *mysqlDatabasePool) Query(ctx context.Context, query string, args ...any) (sqlDatabaseRows, error) {
	conn, err := p.conn(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := conn.QueryContext(ctx, query, args...)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &mysqlConnRows{Rows: rows, conn: conn}, nil
}

// Close devolve a parte da checagem; o pool do servidor fecha quando a última checagem dele sai.
func (p *mysqlDatabasePool) Close() error {
	var err error
	p.once.Do(func() {
		mysqlServers.Lock()
		defer mysqlServers.Unlock()
		p.server.refs--
		if p.server.refs == 0 {
			delete(mysqlServers.byKey, p.key)
			err = p.server.db.Close()
		}
	})
	return err
}

// mysqlConnRow devolve a conexão ao pool depois do Scan (todo QueryRow dos checks termina em Scan).
type mysqlConnRow struct {
	row  *sql.Row
	conn *sql.Conn
	err  error
}

func (r mysqlConnRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	defer r.conn.Close()
	return r.row.Scan(dest...)
}

// mysqlConnRows devolve a conexão ao pool quando as linhas fecham; Columns vem de *sql.Rows.
type mysqlConnRows struct {
	*sql.Rows
	conn *sql.Conn
}

func (r *mysqlConnRows) Close() error {
	err := r.Rows.Close()
	_ = r.conn.Close()
	return err
}
