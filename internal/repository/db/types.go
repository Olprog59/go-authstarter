package db

// DatabaseType represents supported database types
type DatabaseType string

const (
	SQLite     DatabaseType = "sqlite"
	MySQL      DatabaseType = "mysql"
	PostgreSQL DatabaseType = "postgres"
)

// String returns string representation
func (dt DatabaseType) String() string {
	return string(dt)
}

// IsValid checks if database type is valid
func (dt DatabaseType) IsValid() bool {
	switch dt {
	case SQLite, MySQL, PostgreSQL:
		return true
	default:
		return false
	}
}
