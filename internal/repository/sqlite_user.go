package repository

import (
	"database/sql"
	"time"

	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
)

// Verifies that sqliteUserRepo implements the interface well
var _ ports.UserRepository = (*sqliteUserRepo)(nil)

// sqliteUserRepo is a concrete implementation of the `ports.UserRepository` interface
// for SQLite databases. It handles all database interactions related to user management.
type sqliteUserRepo struct {
	db *sql.DB // The database connection pool.
}

// NewSQLiteUser creates and returns a new instance of `sqliteUserRepo`.
// It takes a standard `*sql.DB` connection pool and wraps it, providing the
// `ports.UserRepository` interface for the application's services.
func NewSQLiteUser(db *sql.DB) ports.UserRepository {
	return &sqliteUserRepo{db: db}
}

// Create inserts a new user record into the `users` table.
// It takes the user's email and a hashed password.
//
// Parameters:
//   - email: The email address of the new user.
//   - password: The hashed password of the new user.
//
// Returns:
//   - A pointer to the newly created `domain.User` object, including its generated ID.
//   - An error if the insertion fails (e.g., duplicate email, database constraint violation).
func (r *sqliteUserRepo) Create(email, password string) (*domain.User, error) {
	query := `INSERT INTO users (email, password) VALUES (?, ?)`
	result, err := r.db.Exec(query, email, password)
	if err != nil {
		// SQLite-specific error checking
		return nil, wrapDBError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, wrapDBError(err)
	}

	return r.GetByID(id)
}

// GetByID retrieves a single user record from the `users` table by their unique ID.
//
// Parameters:
//   - id: The unique identifier of the user to retrieve.
//
// Returns:
//   - A pointer to the `domain.User` object if found.
//   - An error, typically `ErrNoRecord` if no user with the given ID exists, or a database error.
func (r *sqliteUserRepo) GetByID(id int64) (*domain.User, error) {
	query := `SELECT id, email, password, email_verified, created_at FROM users WHERE id = ?`
	user := &domain.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.EmailVerified,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, wrapDBError(err)
	}
	return user, nil
}

// GetByEmail retrieves a single user record from the `users` table by their email address.
//
// Parameters:
//   - email: The email address of the user to retrieve.
//
// Returns:
//   - A pointer to the `domain.User` object if found.
//   - An error, typically `ErrNoRecord` if no user with the given email exists, or a database error.
func (r *sqliteUserRepo) GetByEmail(email string) (*domain.User, error) {
	query := `SELECT id, email, password, email_verified, created_at FROM users WHERE email = ?`
	user := &domain.User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.EmailVerified,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, wrapDBError(err)
	}
	return user, nil
}

// List retrieves all user records from the `users` table, ordered by creation date in descending order.
//
// Returns:
//   - A slice of pointers to `domain.User` objects.
//   - An error if the database query or scanning of rows fails.
func (r *sqliteUserRepo) List() ([]*domain.User, error) {
	query := `SELECT id, email, password, created_at FROM users ORDER BY created_at DESC`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, wrapDBError(err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		user := &domain.User{}
		if err := rows.Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt); err != nil {
			return nil, wrapDBError(err)
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

// Delete removes a user record from the `users` table by their unique ID.
//
// Parameters:
//   - id: The unique identifier of the user to delete.
//
// Returns:
//   - An error if the deletion fails.
func (r *sqliteUserRepo) Delete(id int64) error {
	query := `DELETE FROM users WHERE id = ?`
	_, err := r.db.Exec(query, id)
	return wrapDBError(err)
}

// UpdateDBSendEmail updates a user's verification token and its expiration time in the database.
// This is typically called when a verification email is sent or re-sent.
//
// Parameters:
//   - token: The new verification token string.
//   - expiresAt: The expiration time for the new token.
//   - id: The ID of the user to update.
//
// Returns:
//   - An error if the database update operation fails.
func (r *sqliteUserRepo) UpdateDBSendEmail(token string, expiresAt time.Time, id int64) error {
	query := `UPDATE users
		SET verification_token = ?, verification_expires_at = ?
		WHERE id = ?`

	_, err := r.db.Exec(query, token, expiresAt, id)
	if err != nil {
		return err
	}
	return nil
}

// UpdateDBVerify marks a user's email as verified and clears their verification token details.
// This is called after a user successfully verifies their email address.
// The update only occurs if the provided token matches and is not expired.
//
// Parameters:
//   - token: The verification token provided by the user.
//
// Returns:
//   - An error if the database update operation fails or if no rows were affected
//     (e.g., token not found or expired).
func (r *sqliteUserRepo) UpdateDBVerify(token string) error {
	query := `
		UPDATE users
		SET email_verified = 1, verification_token = NULL, verification_expires_at = NULL
		WHERE verification_token = ? AND verification_expires_at > ?
	`

	rows, err := r.db.Exec(query, token, time.Now())
	rowsAffected, _ := rows.RowsAffected()
	if err != nil || rowsAffected == 0 {
		return err
	}
	return nil
}
