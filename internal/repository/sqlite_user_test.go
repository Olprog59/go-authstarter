package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/Olprog59/go-authstarter/internal/ports"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}

	// Create schema
	schema := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		email_verified BOOLEAN NOT NULL DEFAULT 0,
		verification_token TEXT,
		verification_expires_at TIMESTAMP,
		failed_login_attempts INTEGER NOT NULL DEFAULT 0,
		locked_until TIMESTAMP,
		password_reset_token TEXT,
		password_reset_expires_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP
	);
	`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	return db
}

func TestSQLiteUserRepo_Create(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// First user should be admin / Premier utilisateur doit être admin
	user, err := repo.Create(context.Background(), "test@example.com", "hashedpassword123")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	if user.ID == 0 {
		t.Error("Expected user ID to be set")
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", user.Email)
	}

	if user.Role != "admin" {
		t.Errorf("Expected first user to have role 'admin', got '%s'", user.Role)
	}

	// Second user should have default 'user' role / Deuxième utilisateur doit avoir le rôle 'user'
	user2, err := repo.Create(context.Background(), "user2@example.com", "password2")
	if err != nil {
		t.Fatalf("Failed to create second user: %v", err)
	}

	if user2.Role != "user" {
		t.Errorf("Expected second user to have role 'user', got '%s'", user2.Role)
	}

	// Test duplicate email
	_, err = repo.Create(context.Background(), "test@example.com", "password3")
	if err == nil {
		t.Error("Expected error for duplicate email")
	}
}

func TestSQLiteUserRepo_GetByID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create a user first
	created, _ := repo.Create(context.Background(), "test@example.com", "password")

	// Get by ID
	user, err := repo.GetByID(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Failed to get user by ID: %v", err)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", user.Email)
	}

	// Test non-existent ID
	_, err = repo.GetByID(context.Background(), 999)
	if err == nil {
		t.Error("Expected error for non-existent user ID")
	}
}

func TestSQLiteUserRepo_GetByEmail(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create a user
	_, _ = repo.Create(context.Background(), "test@example.com", "password")

	// Get by email
	user, err := repo.GetByEmail(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("Failed to get user by email: %v", err)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", user.Email)
	}

	// Test non-existent email
	_, err = repo.GetByEmail(context.Background(), "notfound@example.com")
	if err == nil {
		t.Error("Expected error for non-existent email")
	}
}

func TestSQLiteUserRepo_List(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create multiple users
	repo.Create(context.Background(), "user1@example.com", "password")
	repo.Create(context.Background(), "user2@example.com", "password")
	repo.Create(context.Background(), "user3@example.com", "password")

	// Test pagination: get first 10 users
	users, totalCount, err := repo.List(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("Failed to list users: %v", err)
	}

	if len(users) != 3 {
		t.Errorf("Expected 3 users, got %d", len(users))
	}

	if totalCount != 3 {
		t.Errorf("Expected total count 3, got %d", totalCount)
	}

	// Test pagination with offset
	users2, totalCount2, err := repo.List(context.Background(), 1, 2)
	if err != nil {
		t.Fatalf("Failed to list users with offset: %v", err)
	}

	if len(users2) != 2 {
		t.Errorf("Expected 2 users with offset, got %d", len(users2))
	}

	if totalCount2 != 3 {
		t.Errorf("Expected total count 3, got %d", totalCount2)
	}
}

func TestSQLiteUserRepo_Delete(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create a user
	user, _ := repo.Create(context.Background(), "test@example.com", "password")

	// Delete the user
	err := repo.Delete(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}

	// Verify user is deleted
	_, err = repo.GetByID(context.Background(), user.ID)
	if err == nil {
		t.Error("Expected error when getting deleted user")
	}

	// Deleting non-existent user should not error (idempotent)
	err = repo.Delete(context.Background(), 999)
	if err != nil {
		t.Logf("Delete non-existent user returned: %v", err)
	}
}

func TestSQLiteUserRepo_UpdateRole(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create a user
	user, _ := repo.Create(context.Background(), "test@example.com", "password")

	// Update role
	err := repo.UpdateRole(context.Background(), user.ID, "admin")
	if err != nil {
		t.Fatalf("Failed to update role: %v", err)
	}

	// Verify role was updated
	updatedUser, _ := repo.GetByID(context.Background(), user.ID)
	if updatedUser.Role != "admin" {
		t.Errorf("Expected role 'admin', got '%s'", updatedUser.Role)
	}

	// Updating non-existent user should not error (idempotent)
	err = repo.UpdateRole(context.Background(), 999, "admin")
	if err != nil {
		t.Logf("UpdateRole non-existent user returned: %v", err)
	}
}

func TestSQLiteUserRepo_IncrementFailedAttempts(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	user, _ := repo.Create(context.Background(), "test@example.com", "password")

	// Increment failed attempts
	err := repo.IncrementFailedAttempts(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Failed to increment failed attempts: %v", err)
	}

	// Verify counter was incremented
	updatedUser, _ := repo.GetByID(context.Background(), user.ID)
	if updatedUser.FailedLoginAttempts != 1 {
		t.Errorf("Expected 1 failed attempt, got %d", updatedUser.FailedLoginAttempts)
	}

	// Increment again
	repo.IncrementFailedAttempts(context.Background(), user.ID)
	updatedUser, _ = repo.GetByID(context.Background(), user.ID)
	if updatedUser.FailedLoginAttempts != 2 {
		t.Errorf("Expected 2 failed attempts, got %d", updatedUser.FailedLoginAttempts)
	}
}

func TestSQLiteUserRepo_ResetFailedAttempts(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	user, _ := repo.Create(context.Background(), "test@example.com", "password")

	// Set failed attempts
	repo.IncrementFailedAttempts(context.Background(), user.ID)
	repo.IncrementFailedAttempts(context.Background(), user.ID)

	// Reset
	err := repo.ResetFailedAttempts(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Failed to reset failed attempts: %v", err)
	}

	// Verify counter was reset
	updatedUser, _ := repo.GetByID(context.Background(), user.ID)
	if updatedUser.FailedLoginAttempts != 0 {
		t.Errorf("Expected 0 failed attempts, got %d", updatedUser.FailedLoginAttempts)
	}
}

func TestSQLiteUserRepo_LockAccount(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	user, _ := repo.Create(context.Background(), "test@example.com", "password")

	lockUntil := time.Now().Add(15 * time.Minute)
	err := repo.LockAccount(context.Background(), user.ID, lockUntil)
	if err != nil {
		t.Fatalf("Failed to lock account: %v", err)
	}

	// Verify account is locked
	updatedUser, _ := repo.GetByID(context.Background(), user.ID)
	if updatedUser.LockedUntil == nil {
		t.Error("Expected LockedUntil to be set")
	} else if !updatedUser.IsLocked() {
		t.Error("Expected account to be locked")
	}
}

func TestSQLiteUserRepo_UpdatePassword(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	user, _ := repo.Create(context.Background(), "test@example.com", "oldpassword")

	// Update password
	err := repo.UpdatePassword(context.Background(), user.ID, "newhashedpassword")
	if err != nil {
		t.Fatalf("Failed to update password: %v", err)
	}

	// Verify password was updated
	updatedUser, _ := repo.GetByID(context.Background(), user.ID)
	if updatedUser.Password != "newhashedpassword" {
		t.Errorf("Expected password 'newhashedpassword', got '%s'", updatedUser.Password)
	}
}

func TestSQLiteUserRepo_PasswordResetToken(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	user, _ := repo.Create(context.Background(), "test@example.com", "password")

	// Set password reset token
	expiresAt := time.Now().Add(1 * time.Hour)
	err := repo.SetPasswordResetToken(context.Background(), "test@example.com", "reset-token-123", expiresAt)
	if err != nil {
		t.Fatalf("Failed to set password reset token: %v", err)
	}

	// Get user by reset token
	foundUser, err := repo.GetByPasswordResetToken(context.Background(), "reset-token-123")
	if err != nil {
		t.Fatalf("Failed to get user by reset token: %v", err)
	}

	if foundUser.ID != user.ID {
		t.Errorf("Expected user ID %d, got %d", user.ID, foundUser.ID)
	}

	// Clear password reset token
	err = repo.ClearPasswordResetToken(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Failed to clear reset token: %v", err)
	}

	// Verify token was cleared
	_, err = repo.GetByPasswordResetToken(context.Background(), "reset-token-123")
	if err == nil {
		t.Error("Expected error when getting user by cleared token")
	}
}

func TestSQLiteUserRepo_CountUsers(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Initially no users
	count, err := repo.CountUsers(context.Background())
	if err != nil {
		t.Fatalf("Failed to count users: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 users, got %d", count)
	}

	// Add users
	repo.Create(context.Background(), "user1@example.com", "password")
	repo.Create(context.Background(), "user2@example.com", "password")

	count, err = repo.CountUsers(context.Background())
	if err != nil {
		t.Fatalf("Failed to count users: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 users, got %d", count)
	}
}

func TestSQLiteUserRepo_UpdateDBSendEmail(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create a user
	user, _ := repo.Create(context.Background(), "test@example.com", "password")

	// Update DB after sending email
	token := "verification-token-123"
	expiresAt := time.Now().Add(24 * time.Hour)
	err := repo.UpdateDBSendEmail(context.Background(), token, expiresAt, user.ID)
	if err != nil {
		t.Fatalf("Failed to update DB after sending email: %v", err)
	}

	// Verify token was set
	var storedToken string
	err = db.QueryRow("SELECT verification_token FROM users WHERE id = ?", user.ID).Scan(&storedToken)
	if err != nil {
		t.Fatalf("Failed to query verification token: %v", err)
	}
	if storedToken != token {
		t.Errorf("Expected verification token %s, got %s", token, storedToken)
	}
}

func TestSQLiteUserRepo_UpdateDBVerify(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create a user with verification token
	user, _ := repo.Create(context.Background(), "test@example.com", "password")
	token := "verification-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	repo.UpdateDBSendEmail(context.Background(), token, expiresAt, user.ID)

	// Verify email
	err := repo.UpdateDBVerify(context.Background(), token)
	if err != nil {
		t.Fatalf("Failed to verify email: %v", err)
	}

	// Check user is verified
	var emailVerified bool
	var storedToken sql.NullString
	err = db.QueryRow("SELECT email_verified, verification_token FROM users WHERE id = ?", user.ID).Scan(&emailVerified, &storedToken)
	if err != nil {
		t.Fatalf("Failed to query user: %v", err)
	}
	if !emailVerified {
		t.Error("Expected email to be verified")
	}
	if storedToken.Valid && storedToken.String != "" {
		t.Error("Expected verification token to be cleared")
	}
}

func TestSQLiteUserRepo_GetPermissionsForRole(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Add permissions and role_permissions tables
	_, _ = db.Exec(`
		CREATE TABLE permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE role_permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			role TEXT NOT NULL,
			permission TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(role, permission)
		);

		INSERT INTO permissions (name, description) VALUES
			('users:read', 'Read users'),
			('users:write', 'Write users'),
			('users:delete', 'Delete users');

		INSERT INTO role_permissions (role, permission) VALUES
			('admin', 'users:read'),
			('admin', 'users:write'),
			('admin', 'users:delete'),
			('moderator', 'users:read');
	`)

	repo := NewSQLiteUser(db)

	// Get permissions for admin
	perms, err := repo.GetPermissionsForRole(context.Background(), "admin")
	if err != nil {
		t.Fatalf("Failed to get permissions for admin: %v", err)
	}

	if len(perms) != 3 {
		t.Errorf("Expected 3 permissions for admin, got %d", len(perms))
	}

	// Get permissions for moderator
	perms, err = repo.GetPermissionsForRole(context.Background(), "moderator")
	if err != nil {
		t.Fatalf("Failed to get permissions for moderator: %v", err)
	}

	if len(perms) != 1 {
		t.Errorf("Expected 1 permission for moderator, got %d", len(perms))
	}
}

func TestSQLiteUserRepo_UserHasPermission(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Setup permissions
	_, _ = db.Exec(`
		CREATE TABLE permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL
		);

		CREATE TABLE role_permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			role TEXT NOT NULL,
			permission TEXT NOT NULL,
			UNIQUE(role, permission)
		);

		INSERT INTO permissions (name, description) VALUES ('users:read', 'Read users');
		INSERT INTO role_permissions (role, permission) VALUES ('admin', 'users:read');
	`)

	repo := NewSQLiteUser(db)

	// Create admin user
	user, _ := repo.Create(context.Background(), "admin@example.com", "password")
	repo.UpdateRole(context.Background(), user.ID, "admin")

	// Check permission
	hasPermission, err := repo.UserHasPermission(context.Background(), user.ID, "users:read")
	if err != nil {
		t.Fatalf("Failed to check permission: %v", err)
	}

	if !hasPermission {
		t.Error("Expected user to have users:read permission")
	}

	// Check non-existent permission
	hasPermission, err = repo.UserHasPermission(context.Background(), user.ID, "users:delete")
	if err != nil {
		t.Fatalf("Failed to check permission: %v", err)
	}

	if hasPermission {
		t.Error("Expected user to NOT have users:delete permission")
	}
}

func TestSQLiteUserRepo_AddPermissionToRole(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Setup permissions table
	_, _ = db.Exec(`
		CREATE TABLE permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL
		);

		CREATE TABLE role_permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			role TEXT NOT NULL,
			permission TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(role, permission)
		);

		INSERT INTO permissions (name, description) VALUES ('users:write', 'Write users');
	`)

	repo := NewSQLiteUser(db)

	// Add permission to moderator role
	err := repo.AddPermissionToRole(context.Background(), "moderator", "users:write")
	if err != nil {
		t.Fatalf("Failed to add permission to role: %v", err)
	}

	// Verify permission was added
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM role_permissions WHERE role = ? AND permission = ?",
		"moderator", "users:write").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query role_permissions: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 role_permission record, got %d", count)
	}
}

func TestSQLiteUserRepo_RemovePermissionFromRole(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Setup permissions
	_, _ = db.Exec(`
		CREATE TABLE permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL
		);

		CREATE TABLE role_permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			role TEXT NOT NULL,
			permission TEXT NOT NULL,
			UNIQUE(role, permission)
		);

		INSERT INTO permissions (name, description) VALUES ('users:read', 'Read users');
		INSERT INTO role_permissions (role, permission) VALUES ('moderator', 'users:read');
	`)

	repo := NewSQLiteUser(db)

	// Remove permission from role
	err := repo.RemovePermissionFromRole(context.Background(), "moderator", "users:read")
	if err != nil {
		t.Fatalf("Failed to remove permission from role: %v", err)
	}

	// Verify permission was removed
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM role_permissions WHERE role = ? AND permission = ?",
		"moderator", "users:read").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query role_permissions: %v", err)
	}

	if count != 0 {
		t.Errorf("Expected 0 role_permission records, got %d", count)
	}
}

func TestSQLiteUserRepo_WithTx(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	// Get repo with transaction
	txRepo := repo.WithTx(tx).(ports.UserRepository)

	// Create user using transaction
	_, err = txRepo.Create(context.Background(), "tx@example.com", "password")
	if err != nil {
		t.Fatalf("Failed to create user in transaction: %v", err)
	}

	// Rollback transaction
	tx.Rollback()

	// Verify user was not created
	_, err = repo.GetByEmail(context.Background(), "tx@example.com")
	if err == nil {
		t.Error("Expected error when getting rolled back user")
	}
}
