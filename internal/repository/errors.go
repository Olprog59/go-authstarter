package repository

import (
	"github.com/Olprog59/go-authstarter/internal/repository/db"
	"github.com/Olprog59/go-authstarter/internal/repository/sqlite"
)

// Re-export common errors for backward compatibility and convenience
var (
	// Common database errors from db package
	ErrNoRecord            = db.ErrNoRecord
	ErrDuplicateEmail      = db.ErrDuplicateEmail
	ErrForeignKeyViolation = db.ErrForeignKeyViolation

	// SQLite-specific errors from sqlite package
	ErrDup    = sqlite.ErrDup
	ErrBusy   = sqlite.ErrBusy
	ErrLocked = sqlite.ErrLocked
)
