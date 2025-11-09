package repository

import (
	"database/sql"
	"errors"
	"log"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	ErrDup      = errors.New("record already exists")
	ErrNoRecord = errors.New("record not found")
	ErrBusy     = errors.New("database is busy")
	ErrLocked   = errors.New("database is locked")
)

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

				log.Printf("Database is busy: %s", liteErr.Error())
				return ErrBusy
			case sqlite3.SQLITE_LOCKED:

				log.Printf("Database is locked: %s", liteErr.Error())
				return ErrLocked

			}

			log.Printf("SQLite error code: %d, message: %s", code, liteErr.Error())
		}
	}
	return err
}
