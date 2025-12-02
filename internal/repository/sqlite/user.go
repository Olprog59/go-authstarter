package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/Olprog59/go-authstarter/internal/ports"
	"github.com/Olprog59/go-authstarter/internal/domain"
)

var _ ports.UserRepository = (*userRepository)(nil)

// userRepository implements UserRepository for SQLite / Implémente UserRepository pour SQLite
type userRepository struct {
	db ports.DBTX
}

// NewUserRepository creates user repository / Crée le repository utilisateur
func NewUserRepository(db *sql.DB) ports.UserRepository {
	return &userRepository{db: db}
}

// WithTx returns repository with transaction / Retourne le repository avec transaction
func (r *userRepository) WithTx(dbtx ports.DBTX) ports.AccountSecurityRepository {
	return &userRepository{db: dbtx}
}

// Create inserts new user in database / Insère un nouvel utilisateur dans la BD
func (r *userRepository) Create(ctx context.Context, email, password string) (*domain.User, error) {
	var count int
	countQuery := `SELECT COUNT(*) FROM users WHERE deleted_at IS NULL`
	if err := r.db.QueryRowContext(ctx, countQuery).Scan(&count); err != nil {
		return nil, handleError(err)
	}

	role := "user"
	if count == 0 {
		role = "admin"
	}

	query := `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`
	result, err := r.db.ExecContext(ctx, query, email, password, role)
	if err != nil {
		return nil, handleError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, handleError(err)
	}

	return r.GetByID(ctx, id)
}

// GetByID retrieves user by ID / Récupère l'utilisateur par ID
func (r *userRepository) GetByID(ctx context.Context, id int64) (*domain.User, error) {
	query := `SELECT id, email, password, role, email_verified, created_at, failed_login_attempts, locked_until
	          FROM users WHERE id = ?`
	user := &domain.User{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
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
		return nil, handleError(err)
	}
	return user, nil
}

// GetByEmail retrieves user by email / Récupère l'utilisateur par email
func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `SELECT id, email, password, role, email_verified, created_at, failed_login_attempts, locked_until
	          FROM users WHERE email = ?`
	user := &domain.User{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
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
		return nil, handleError(err)
	}
	return user, nil
}

// List retrieves paginated users / Récupère les utilisateurs paginés
func (r *userRepository) List(ctx context.Context, offset, limit int) ([]*domain.User, int, error) {
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM users WHERE deleted_at IS NULL`
	if err := r.db.QueryRowContext(ctx, countQuery).Scan(&totalCount); err != nil {
		return nil, 0, handleError(err)
	}

	query := `
		SELECT id, email, password, role, created_at, email_verified
		FROM users
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`
	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, handleError(err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		user := &domain.User{}
		if err := rows.Scan(&user.ID, &user.Email, &user.Password, &user.Role, &user.CreatedAt, &user.EmailVerified); err != nil {
			return nil, 0, handleError(err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, handleError(err)
	}

	return users, totalCount, nil
}

// Delete removes user by ID / Supprime l'utilisateur par ID
func (r *userRepository) Delete(ctx context.Context, id int64) error {
	query := `DELETE FROM users WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	return handleError(err)
}

// UpdateDBSendEmail updates verification token / Met à jour le token de vérification
func (r *userRepository) UpdateDBSendEmail(ctx context.Context, token string, expiresAt time.Time, id int64) error {
	query := `UPDATE users
		SET verification_token = ?, verification_expires_at = ?
		WHERE id = ?`

	_, err := r.db.ExecContext(ctx, query, token, expiresAt, id)
	return err
}

// UpdateDBVerify marks email as verified / Marque l'email comme vérifié
func (r *userRepository) UpdateDBVerify(ctx context.Context, token string) error {
	query := `
		UPDATE users
		SET email_verified = 1, verification_token = NULL, verification_expires_at = NULL
		WHERE verification_token = ? AND verification_expires_at > ?
	`

	rows, err := r.db.ExecContext(ctx, query, token, time.Now())
	rowsAffected, _ := rows.RowsAffected()
	if err != nil || rowsAffected == 0 {
		return err
	}
	return nil
}

// IncrementFailedAttempts increments failed login attempts / Incrémente les tentatives échouées
func (r *userRepository) IncrementFailedAttempts(ctx context.Context, userID int64) error {
	query := `UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, userID)
	return handleError(err)
}

// ResetFailedAttempts resets failed login attempts / Réinitialise les tentatives échouées
func (r *userRepository) ResetFailedAttempts(ctx context.Context, userID int64) error {
	query := `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, userID)
	return handleError(err)
}

// LockAccount locks user account / Verrouille le compte utilisateur
func (r *userRepository) LockAccount(ctx context.Context, userID int64, until time.Time) error {
	query := `UPDATE users SET locked_until = ? WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, until, userID)
	return handleError(err)
}

// IncrementFailedAttemptsWithDBTX increments failed attempts with transaction / Incrémente les tentatives avec transaction
func (r *userRepository) IncrementFailedAttemptsWithDBTX(dbtx ports.DBTX, ctx context.Context, userID int64) error {
	query := `UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?`
	_, err := dbtx.ExecContext(ctx, query, userID)
	return handleError(err)
}

// ResetFailedAttemptsWithDBTX resets failed attempts with transaction / Réinitialise les tentatives avec transaction
func (r *userRepository) ResetFailedAttemptsWithDBTX(dbtx ports.DBTX, ctx context.Context, userID int64) error {
	query := `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`
	_, err := dbtx.ExecContext(ctx, query, userID)
	return handleError(err)
}

// LockAccountWithDBTX locks account with transaction / Verrouille le compte avec transaction
func (r *userRepository) LockAccountWithDBTX(dbtx ports.DBTX, ctx context.Context, userID int64, until time.Time) error {
	query := `UPDATE users SET locked_until = ? WHERE id = ?`
	_, err := dbtx.ExecContext(ctx, query, until, userID)
	return handleError(err)
}

// UpdateRole changes user role / Change le rôle utilisateur
func (r *userRepository) UpdateRole(ctx context.Context, userID int64, role string) error {
	query := `UPDATE users SET role = ? WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, role, userID)
	return handleError(err)
}

// CountUsers returns total user count / Retourne le nombre total d'utilisateurs
func (r *userRepository) CountUsers(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM users`
	var count int
	err := r.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, handleError(err)
	}
	return count, nil
}

// GetPermissionsForRole retrieves permissions for role / Récupère les permissions du rôle
func (r *userRepository) GetPermissionsForRole(ctx context.Context, role string) ([]domain.Permission, error) {
	query := `
		SELECT permission
		FROM role_permissions
		WHERE role = ?
	`
	rows, err := r.db.QueryContext(ctx, query, role)
	if err != nil {
		return nil, handleError(err)
	}
	defer rows.Close()

	var permissions []domain.Permission
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, handleError(err)
		}
		permissions = append(permissions, domain.Permission(perm))
	}

	if err := rows.Err(); err != nil {
		return nil, handleError(err)
	}

	return permissions, nil
}

// UserHasPermission checks if user has permission / Vérifie si l'utilisateur a la permission
func (r *userRepository) UserHasPermission(ctx context.Context, userID int64, permission domain.Permission) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM users u
			JOIN role_permissions rp ON u.role = rp.role
			WHERE u.id = ? AND rp.permission = ?
		)
	`
	var exists bool
	err := r.db.QueryRowContext(ctx, query, userID, permission.String()).Scan(&exists)
	if err != nil {
		return false, handleError(err)
	}
	return exists, nil
}

// AddPermissionToRole assigns permission to role / Assigne la permission au rôle
func (r *userRepository) AddPermissionToRole(ctx context.Context, role string, permission domain.Permission) error {
	query := `
		INSERT INTO role_permissions (role, permission)
		VALUES (?, ?)
	`
	_, err := r.db.ExecContext(ctx, query, role, permission.String())
	return handleError(err)
}

// RemovePermissionFromRole removes permission from role / Retire la permission du rôle
func (r *userRepository) RemovePermissionFromRole(ctx context.Context, role string, permission domain.Permission) error {
	query := `
		DELETE FROM role_permissions
		WHERE role = ? AND permission = ?
	`
	_, err := r.db.ExecContext(ctx, query, role, permission.String())
	return handleError(err)
}

// SetPasswordResetToken stores password reset token / Stocke le token de réinitialisation
func (r *userRepository) SetPasswordResetToken(ctx context.Context, email string, token string, expiresAt time.Time) error {
	query := `
		UPDATE users
		SET password_reset_token = ?, password_reset_expires_at = ?
		WHERE email = ? AND deleted_at IS NULL
	`
	result, err := r.db.ExecContext(ctx, query, token, expiresAt, email)
	if err != nil {
		return handleError(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return handleError(err)
	}

	if rowsAffected == 0 {
		return ErrNoRecord
	}

	return nil
}

// GetByPasswordResetToken retrieves user by reset token / Récupère l'utilisateur par token
func (r *userRepository) GetByPasswordResetToken(ctx context.Context, token string) (*domain.User, error) {
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
	err := r.db.QueryRowContext(ctx, query, token).Scan(
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
		return nil, handleError(err)
	}

	return &user, nil
}

// UpdatePassword updates user password / Met à jour le mot de passe
func (r *userRepository) UpdatePassword(ctx context.Context, userID int64, hashedPassword string) error {
	query := `
		UPDATE users
		SET password = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND deleted_at IS NULL
	`
	_, err := r.db.ExecContext(ctx, query, hashedPassword, userID)
	return handleError(err)
}

// ClearPasswordResetToken clears password reset token / Efface le token de réinitialisation
func (r *userRepository) ClearPasswordResetToken(ctx context.Context, userID int64) error {
	query := `
		UPDATE users
		SET password_reset_token = NULL,
		    password_reset_expires_at = NULL,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND deleted_at IS NULL
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	return handleError(err)
}
