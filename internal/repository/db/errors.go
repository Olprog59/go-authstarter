package db

import "errors"

// Common database errors
var (
	ErrNoRecord             = errors.New("no matching record found")
	ErrDuplicateEmail       = errors.New("email already exists")
	ErrForeignKeyViolation  = errors.New("foreign key constraint violation")
)
