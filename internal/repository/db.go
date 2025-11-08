package repository

import (
	"context"
	"database/sql"
)

// DBTX est une interface qui peut représenter soit un *sql.DB, soit un *sql.Tx.
// Elle permet aux méthodes du repository de fonctionner de manière transparente
// à l'intérieur ou à l'extérieur d'une transaction.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}
