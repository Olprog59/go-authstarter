package repository

import (
	"context"
	"time"

	"github.com/Olprog59/go-fun/internal/common"
	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
)

var _ ports.UserRepository = (*sqliteUserRepo)(nil) // Interface compliance check / Vérification d'interface

// sqliteUserRepo implements UserRepository for SQLite / Implémente UserRepository pour SQLite
type sqliteUserRepo struct {
	dbtx common.DBTX // Database connection or transaction / Connexion BD ou transaction
}

// NewSQLiteUser creates SQLite user repository / Crée le repository utilisateur SQLite
func NewSQLiteUser(dbtx common.DBTX) ports.UserRepository {
	return &sqliteUserRepo{dbtx: dbtx}
}

// WithTx returns repository with transaction support / Retourne le repository avec support transactionnel
func (r *sqliteUserRepo) WithTx(dbtx common.DBTX) ports.AccountSecurityRepository {
	return &sqliteUserRepo{dbtx: dbtx}
}

// Create inserts new user in database / Insère un nouvel utilisateur dans la BD
// First user automatically becomes admin / Premier utilisateur devient automatiquement admin
func (r *sqliteUserRepo) Create(ctx context.Context, email, password string) (*domain.User, error) {
	// Check if this is the first user / Vérifie si c'est le premier utilisateur
	var count int
	countQuery := `SELECT COUNT(*) FROM users WHERE deleted_at IS NULL`
	if err := r.dbtx.QueryRowContext(ctx, countQuery).Scan(&count); err != nil {
		return nil, wrapDBError(err)
	}

	// First user gets admin role, others get default user role / Premier utilisateur = admin, autres = user
	role := "user"
	if count == 0 {
		role = "admin"
	}

	query := `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`
	result, err := r.dbtx.ExecContext(ctx, query, email, password, role)
	if err != nil {
		return nil, wrapDBError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, wrapDBError(err)
	}

	return r.GetByID(ctx, id)
}

// GetByID retrieves user by ID / Récupère l'utilisateur par ID
func (r *sqliteUserRepo) GetByID(ctx context.Context, id int64) (*domain.User, error) {
	query := `SELECT id, email, password, role, email_verified, created_at, failed_login_attempts, locked_until
	          FROM users WHERE id = ?`
	user := &domain.User{}
	err := r.dbtx.QueryRowContext(ctx, query, id).Scan(
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

// GetByEmail retrieves user by email / Récupère l'utilisateur par email
func (r *sqliteUserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `SELECT id, email, password, role, email_verified, created_at, failed_login_attempts, locked_until
	          FROM users WHERE email = ?`
	user := &domain.User{}
	err := r.dbtx.QueryRowContext(ctx, query, email).Scan(
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
// List retrieves paginated user records from the database.
//
// Parameters:
//   - offset: Number of records to skip (for pagination)
//   - limit: Maximum number of records to return (page size)
//
// Returns:
//   - []*domain.User: Slice of users for the current page
//   - int: Total count of all users (not just the current page)
//   - error: Any error that occurred during retrieval
//
// Performance note: Uses LIMIT and OFFSET for efficient pagination.
// The total count query only counts non-deleted users.
func (r *sqliteUserRepo) List(ctx context.Context, offset, limit int) ([]*domain.User, int, error) {
	// First, get total count of users
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM users WHERE deleted_at IS NULL`
	if err := r.dbtx.QueryRowContext(ctx, countQuery).Scan(&totalCount); err != nil {
		return nil, 0, wrapDBError(err)
	}

	// Then get paginated results
	query := `
		SELECT id, email, password, role, created_at, email_verified
		FROM users
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`
	rows, err := r.dbtx.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, wrapDBError(err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		user := &domain.User{}
		if err := rows.Scan(&user.ID, &user.Email, &user.Password, &user.Role, &user.CreatedAt, &user.EmailVerified); err != nil {
			return nil, 0, wrapDBError(err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, wrapDBError(err)
	}

	return users, totalCount, nil
}

// Delete removes a user record from the `users` table by their unique ID.
//
// Parameters:
//   - id: The unique identifier of the user to delete.
//
// Returns:
//   - An error if the deletion fails.
func (r *sqliteUserRepo) Delete(ctx context.Context, id int64) error {
	query := `DELETE FROM users WHERE id = ?`
	_, err := r.dbtx.ExecContext(ctx, query, id)
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
func (r *sqliteUserRepo) UpdateDBSendEmail(ctx context.Context, token string, expiresAt time.Time, id int64) error {
	query := `UPDATE users
		SET verification_token = ?, verification_expires_at = ?
		WHERE id = ?`

	_, err := r.dbtx.ExecContext(ctx, query, token, expiresAt, id)
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
func (r *sqliteUserRepo) UpdateDBVerify(ctx context.Context, token string) error {
	query := `
		UPDATE users
		SET email_verified = 1, verification_token = NULL, verification_expires_at = NULL
		WHERE verification_token = ? AND verification_expires_at > ?
	`

	rows, err := r.dbtx.ExecContext(ctx, query, token, time.Now())
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
func (r *sqliteUserRepo) IncrementFailedAttempts(ctx context.Context, userID int64) error {
	query := `UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?`
	_, err := r.dbtx.ExecContext(ctx, query, userID)
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
func (r *sqliteUserRepo) ResetFailedAttempts(ctx context.Context, userID int64) error {
	query := `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`
	_, err := r.dbtx.ExecContext(ctx, query, userID)
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
func (r *sqliteUserRepo) LockAccount(ctx context.Context, userID int64, until time.Time) error {
	query := `UPDATE users SET locked_until = ? WHERE id = ?`
	_, err := r.dbtx.ExecContext(ctx, query, until, userID)
	return wrapDBError(err)
}

// IncrementFailedAttemptsWithDBTX increments the failed login attempts counter for a user, using a provided DBTX.
func (r *sqliteUserRepo) IncrementFailedAttemptsWithDBTX(dbtx common.DBTX, ctx context.Context, userID int64) error {
	query := `UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?`
	_, err := dbtx.ExecContext(ctx, query, userID)
	return wrapDBError(err)
}

// ResetFailedAttemptsWithDBTX resets the failed login attempts counter to zero for a user, using a provided DBTX.
func (r *sqliteUserRepo) ResetFailedAttemptsWithDBTX(dbtx common.DBTX, ctx context.Context, userID int64) error {
	query := `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`
	_, err := dbtx.ExecContext(ctx, query, userID)
	return wrapDBError(err)
}

// LockAccountWithDBTX locks a user account until a specific timestamp, using a provided DBTX.
func (r *sqliteUserRepo) LockAccountWithDBTX(dbtx common.DBTX, ctx context.Context, userID int64, until time.Time) error {
	query := `UPDATE users SET locked_until = ? WHERE id = ?`
	_, err := dbtx.ExecContext(ctx, query, until, userID)
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
func (r *sqliteUserRepo) UpdateRole(ctx context.Context, userID int64, role string) error {
	query := `UPDATE users SET role = ? WHERE id = ?`
	_, err := r.dbtx.ExecContext(ctx, query, role, userID)
	return wrapDBError(err)
}

// CountUsers returns the total number of users in the system.
// This is primarily used for admin bootstrapping: the first user to register
// is automatically granted admin privileges.
//
// Returns:
//   - The total count of users in the database.
//   - An error if the database query fails.
func (r *sqliteUserRepo) CountUsers(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM users`
	var count int
	err := r.dbtx.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, wrapDBError(err)
	}
	return count, nil
}

// GetPermissionsForRole retrieves all permissions assigned to a specific role.
// This queries the role_permissions junction table to get all permissions
// associated with the given role.
//
// Parameters:
//   - role: The role name (e.g., "user", "moderator", "admin")
//
// Returns:
//   - A slice of Permission objects assigned to the role
//   - An error if the database query fails
func (r *sqliteUserRepo) GetPermissionsForRole(ctx context.Context, role string) ([]domain.Permission, error) {
	query := `
		SELECT permission
		FROM role_permissions
		WHERE role = ?
	`
	rows, err := r.dbtx.QueryContext(ctx, query, role)
	if err != nil {
		return nil, wrapDBError(err)
	}
	defer rows.Close()

	var permissions []domain.Permission
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, wrapDBError(err)
		}
		permissions = append(permissions, domain.Permission(perm))
	}

	if err := rows.Err(); err != nil {
		return nil, wrapDBError(err)
	}

	return permissions, nil
}

// UserHasPermission checks if a user has a specific permission based on their role.
// This is the primary method used by authorization middleware to verify permissions.
//
// Parameters:
//   - userID: The ID of the user to check
//   - permission: The permission to verify (e.g., "users:read")
//
// Returns:
//   - true if the user has the permission, false otherwise
//   - An error if the database query fails
func (r *sqliteUserRepo) UserHasPermission(ctx context.Context, userID int64, permission domain.Permission) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM users u
			JOIN role_permissions rp ON u.role = rp.role
			WHERE u.id = ? AND rp.permission = ?
		)
	`
	var exists bool
	err := r.dbtx.QueryRowContext(ctx, query, userID, permission.String()).Scan(&exists)
	if err != nil {
		return false, wrapDBError(err)
	}
	return exists, nil
}

// AddPermissionToRole assigns a permission to a role.
// This is used for dynamic permission management by administrators.
//
// Parameters:
//   - role: The role name to assign the permission to
//   - permission: The permission to assign
//
// Returns:
//   - An error if the database operation fails or if the permission is already assigned
func (r *sqliteUserRepo) AddPermissionToRole(ctx context.Context, role string, permission domain.Permission) error {
	query := `
		INSERT INTO role_permissions (role, permission)
		VALUES (?, ?)
	`
	_, err := r.dbtx.ExecContext(ctx, query, role, permission.String())
	return wrapDBError(err)
}

// RemovePermissionFromRole removes a permission from a role.
// This is used for dynamic permission management by administrators.
//
// Parameters:
//   - role: The role name to remove the permission from
//   - permission: The permission to remove
//
// Returns:
//   - An error if the database operation fails
func (r *sqliteUserRepo) RemovePermissionFromRole(ctx context.Context, role string, permission domain.Permission) error {
	query := `
		DELETE FROM role_permissions
		WHERE role = ? AND permission = ?
	`
	_, err := r.dbtx.ExecContext(ctx, query, role, permission.String())
	return wrapDBError(err)
}

// SetPasswordResetToken stores a password reset token and its expiration for a user.
// This is called when a user requests a password reset via email.
//
// Parameters:
//   - email: The user's email address
//   - token: The randomly generated password reset token (UUID)
//   - expiresAt: The expiration timestamp for the token (typically 1 hour from now)
//
// Returns:
//   - An error if the user is not found or the database operation fails
func (r *sqliteUserRepo) SetPasswordResetToken(ctx context.Context, email string, token string, expiresAt time.Time) error {
	query := `
		UPDATE users
		SET password_reset_token = ?, password_reset_expires_at = ?
		WHERE email = ? AND deleted_at IS NULL
	`
	result, err := r.dbtx.ExecContext(ctx, query, token, expiresAt, email)
	if err != nil {
		return wrapDBError(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return wrapDBError(err)
	}

	if rowsAffected == 0 {
		return ErrNoRecord
	}

	return nil
}

// GetByPasswordResetToken retrieves a user by their password reset token.
// It checks that the token exists and hasn't expired.
//
// Parameters:
//   - token: The password reset token from the URL/email
//
// Returns:
//   - The user if the token is valid and not expired
//   - ErrNoRecord if the token doesn't exist or has expired
func (r *sqliteUserRepo) GetByPasswordResetToken(ctx context.Context, token string) (*domain.User, error) {
	query := `
		SELECT id, email, password, email_verified, role,
			   failed_login_attempts, locked_until,
			   created_at, updated_at
		FROM users
		WHERE password_reset_token = ?
		  AND password_reset_expires_at > datetime('now')
		  AND deleted_at IS NULL
	`

	var user domain.User
	err := r.dbtx.QueryRowContext(ctx, query, token).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.EmailVerified,
		&user.Role,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, wrapDBError(err)
	}

	return &user, nil
}

// UpdatePassword updates a user's password hash in the database.
// This is called after successful password reset or password change.
//
// Parameters:
//   - userID: The user's unique identifier
//   - hashedPassword: The new bcrypt-hashed password
//
// Returns:
//   - An error if the database operation fails
func (r *sqliteUserRepo) UpdatePassword(ctx context.Context, userID int64, hashedPassword string) error {
	query := `
		UPDATE users
		SET password = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND deleted_at IS NULL
	`
	_, err := r.dbtx.ExecContext(ctx, query, hashedPassword, userID)
	return wrapDBError(err)
}

// ClearPasswordResetToken clears the password reset token and expiration for a user.
// This is called after a successful password reset to invalidate the token
// and prevent it from being reused.
//
// Parameters:
//   - userID: The user's unique identifier
//
// Returns:
//   - An error if the database operation fails
func (r *sqliteUserRepo) ClearPasswordResetToken(ctx context.Context, userID int64) error {
	query := `
		UPDATE users
		SET password_reset_token = NULL,
		    password_reset_expires_at = NULL,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND deleted_at IS NULL
	`
	_, err := r.dbtx.ExecContext(ctx, query, userID)
	return wrapDBError(err)
}
