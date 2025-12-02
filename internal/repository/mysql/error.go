package mysql

import (
	"database/sql"
	"errors"

	"github.com/Olprog59/go-authstarter/internal/repository/db"
	"github.com/go-sql-driver/mysql"
)

var (
	ErrDup      = errors.New("record already exists") // Duplicate unique key / Clé unique dupliquée
	ErrNoRecord = db.ErrNoRecord                      // Re-export from db package
)

// handleError translates MySQL errors to typed errors / Traduit les erreurs MySQL en erreurs typées
func handleError(err error) error {
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoRecord
		}
		if mysqlErr, ok := err.(*mysql.MySQLError); ok {
			switch mysqlErr.Number {
			case 1062: // ER_DUP_ENTRY
				return ErrDup
			}
		}
	}
	return err
}
