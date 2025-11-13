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
	query := `SELECT id, email, password, role, email_verified, created_at, failed_login_attempts, locked_until
	          FROM users WHERE id = ?`
	user := &domain.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
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
	query := `SELECT id, email, password, role, email_verified, created_at, failed_login_attempts, locked_until
	          FROM users WHERE email = ?`
	user := &domain.User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
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
	query := `SELECT id, email, password, role, created_at FROM users ORDER BY created_at DESC`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, wrapDBError(err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		user := &domain.User{}
		if err := rows.Scan(&user.ID, &user.Email, &user.Password, &user.Role, &user.CreatedAt); err != nil {
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

// IncrementFailedAttempts increments the failed login attempts counter for a user.
// This is called after each failed login attempt to track potential brute force attacks.
//
// Parameters:
//   - userID: The ID of the user whose failed attempt count should be incremented.
//
// Returns:
//   - An error if the database update operation fails.
func (r *sqliteUserRepo) IncrementFailedAttempts(userID int64) error {
	query := `UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?`
	_, err := r.db.Exec(query, userID)
	return wrapDBError(err)
}

// ResetFailedAttempts resets the failed login attempts counter to zero for a user.
// This is typically called after a successful login or when unlocking an account.
//
// Parameters:
//   - userID: The ID of the user whose failed attempt count should be reset.
//
// Returns:
//   - An error if the database update operation fails.
func (r *sqliteUserRepo) ResetFailedAttempts(userID int64) error {
	query := `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`
	_, err := r.db.Exec(query, userID)
	return wrapDBError(err)
}

// LockAccount locks a user account until a specific timestamp.
// This prevents the user from logging in until the lock expires.
//
// Parameters:
//   - userID: The ID of the user whose account should be locked.
//   - until: The timestamp until which the account should remain locked.
//
// Returns:
//   - An error if the database update operation fails.
func (r *sqliteUserRepo) LockAccount(userID int64, until time.Time) error {
	query := `UPDATE users SET locked_until = ? WHERE id = ?`
	_, err := r.db.Exec(query, until, userID)
	return wrapDBError(err)
}

// UpdateRole changes the role of a user in the database.
// This is an administrative function used for managing user permissions.
//
// Parameters:
//   - userID: The ID of the user whose role should be updated.
//   - role: The new role to assign (must be one of: "user", "moderator", "admin").
//
// Returns:
//   - An error if the database update operation fails or if the role is invalid.
//
// Note: The role validation is enforced by database triggers, which will raise
// an error if an invalid role is provided.
func (r *sqliteUserRepo) UpdateRole(userID int64, role string) error {
	query := `UPDATE users SET role = ? WHERE id = ?`
	_, err := r.db.Exec(query, role, userID)
	return wrapDBError(err)
}

// CountUsers returns the total number of users in the system.
// This is primarily used for admin bootstrapping: the first user to register
// is automatically granted admin privileges.
//
// Returns:
//   - The total count of users in the database.
//   - An error if the database query fails.
func (r *sqliteUserRepo) CountUsers() (int, error) {
	query := `SELECT COUNT(*) FROM users`
	var count int
	err := r.db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, wrapDBError(err)
	}
	return count, nil
}
