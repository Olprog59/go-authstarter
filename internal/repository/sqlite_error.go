package repository

import (
	"database/sql"
	"errors"
	"log"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	// ErrDup indicates that a record with a duplicate unique key already exists.
	ErrDup = errors.New("record already exists")
	// ErrNoRecord indicates that no record was found for the given query.
	ErrNoRecord = errors.New("record not found")
	// ErrBusy indicates that the database is busy and cannot complete the operation.
	ErrBusy = errors.New("database is busy")
	// ErrLocked indicates that the database is locked and cannot complete the operation.
	ErrLocked = errors.New("database is locked")
)

// wrapDBError translates low-level database errors into more semantic, application-specific errors.
// This function inspects the provided error and, if it's a known database error (e.g., `sql.ErrNoRows`
// or a specific SQLite error code), it returns a more descriptive error from this package.
//
// This abstraction helps to decouple the application's business logic from the specifics
// of the underlying database implementation, making error handling more consistent.
func wrapDBError(err error) error {
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoRecord
		}
		if liteErr, ok := err.(*sqlite.Error); ok {
			code := liteErr.Code()
			switch code {
			case sqlite3.SQLITE_CONSTRAINT_UNIQUE:
				return ErrDup
			case sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
				return ErrDup
			case sqlite3.SQLITE_BUSY:
				// Handling of busy database (e.g. locking)
				log.Printf("Database is busy: %s", liteErr.Error())
				return ErrBusy
			case sqlite3.SQLITE_LOCKED:
				// Handling of locked database
				log.Printf("Database is locked: %s", liteErr.Error())
				return ErrLocked
				// Add other specific cases if necessary
			}
			// For other errors, we can log the code for debugging
			log.Printf("SQLite error code: %d, message: %s", code, liteErr.Error())
		}
	}
	return err
}
