package sqlite

import (
	"database/sql"
	"errors"
	"log"

	"github.com/Olprog59/go-authstarter/internal/repository/db"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	ErrDup      = errors.New("record already exists") // Duplicate unique key / Clé unique dupliquée
	ErrNoRecord = db.ErrNoRecord                      // Re-export from db package
	ErrBusy     = errors.New("database is busy")      // Database busy / Base de données occupée
	ErrLocked   = errors.New("database is locked")    // Database locked / Base de données verrouillée
)

// handleError translates DB errors to typed errors / Traduit les erreurs DB en erreurs typées
func handleError(err error) error {
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

// wrapDBError is deprecated, use handleError / Déprécié, utiliser handleError
func wrapDBError(err error) error {
	return handleError(err)
}
