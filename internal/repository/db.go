package repository

import (
	"context"
	"database/sql"
)

// DBTX is an interface that abstracts the common database operations shared by
// both `*sql.DB` (a database connection pool) and `*sql.Tx` (a database transaction).
// This design allows repository methods to operate seamlessly, whether they are
// part of a larger transaction or executing directly against the database pool.
// It promotes flexibility and simplifies transaction management within the data layer.
type DBTX interface {
	// ExecContext executes a query without returning any rows.
	// The args are for any placeholder parameters in the query.
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	// PrepareContext creates a prepared statement for later queries or executions.
	// The caller must close the statement when no longer needed.
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	// QueryContext executes a query that returns rows, typically a SELECT statement.
	// The args are for any placeholder parameters in the query.
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	// QueryRowContext executes a query that is expected to return at most one row.
	// QueryRowContext always returns a non-nil value. Errors are deferred until
	// Row's Scan method is called.
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}
