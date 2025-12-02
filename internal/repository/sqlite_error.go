package repository

import (
	"database/sql"
	"errors"
	"log"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	ErrDup      = errors.New("record already exists") // Duplicate unique key / Clé unique dupliquée
	ErrNoRecord = errors.New("record not found")      // No record found / Enregistrement non trouvé
	ErrBusy     = errors.New("database is busy")      // Database busy / Base de données occupée
	ErrLocked   = errors.New("database is locked")    // Database locked / Base de données verrouillée
)

// wrapDBError translates DB errors to typed errors / Traduit les erreurs DB en erreurs typées
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
