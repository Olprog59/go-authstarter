package postgres

import (
	"database/sql"
	"errors"

	"github.com/Olprog59/go-authstarter/internal/repository/db"
	"github.com/lib/pq"
)

var (
	ErrDup      = errors.New("record already exists") // Duplicate unique key / Clé unique dupliquée
	ErrNoRecord = db.ErrNoRecord                      // Re-export from db package
)

// handleError translates PostgreSQL errors to typed errors / Traduit les erreurs PostgreSQL en erreurs typées
func handleError(err error) error {
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoRecord
		}
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505": // unique_violation
				return ErrDup
			}
		}
	}
	return err
}
