package ports

import (
	"context"
	"database/sql"
)

// DBTX abstracts database operations for both DB and Tx / Abstrait les opérations de BD pour DB et Tx
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}
