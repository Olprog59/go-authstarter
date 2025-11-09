package ports

import (
	"time"

	"github.com/Olprog59/go-fun/internal/domain"
)

// UserRepository defines the contract for user persistence operations.
// This is a "port" in the Hexagonal Architecture, abstracting the underlying
// data storage mechanism for user data. Any concrete implementation (e.g.,
// SQLite, PostgreSQL) must satisfy this interface.
type UserRepository interface {
	// Create inserts a new user record into the persistence layer.
	// It takes the user's email and hashed password, and returns the newly created
	// `domain.User` object with its assigned ID, or an error if the creation fails.
	Create(email, password string) (*domain.User, error)
	// GetByID retrieves a single user record by their unique identifier.
	// It returns the `domain.User` object if found, or an error (e.g., `ErrNotFound`) if not.
	GetByID(id int64) (*domain.User, error)
	// GetByEmail retrieves a single user record by their email address.
	// It returns the `domain.User` object if found, or an error (e.g., `ErrNotFound`) if not.
	GetByEmail(email string) (*domain.User, error)
	// UpdateDBSendEmail updates a user's verification token and its expiration time in the database.
	// This is typically called when a verification email is sent or re-sent.
	UpdateDBSendEmail(token string, expiresAt time.Time, id int64) error
	// UpdateDBVerify marks a user's email as verified and clears their verification token details.
	// This is called after a user successfully verifies their email address.
	UpdateDBVerify(token string) error
	// List retrieves all user records from the persistence layer.
	// It returns a slice of `domain.User` objects, or an error if the retrieval fails.
	List() ([]*domain.User, error)
	// Delete removes a user record from the persistence layer by their unique identifier.
	// It returns an error if the deletion fails.
	Delete(id int64) error
}
