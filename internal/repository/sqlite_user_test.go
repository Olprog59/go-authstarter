package repository

import (
	"database/sql"
	"testing"
	"time"

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

	user, err := repo.Create("test@example.com", "hashedpassword123")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	if user.ID == 0 {
		t.Error("Expected user ID to be set")
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", user.Email)
	}

	if user.Role != "user" {
		t.Errorf("Expected role 'user', got '%s'", user.Role)
	}

	// Test duplicate email
	_, err = repo.Create("test@example.com", "password2")
	if err == nil {
		t.Error("Expected error for duplicate email")
	}
}

func TestSQLiteUserRepo_GetByID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create a user first
	created, _ := repo.Create("test@example.com", "password")

	// Get by ID
	user, err := repo.GetByID(created.ID)
	if err != nil {
		t.Fatalf("Failed to get user by ID: %v", err)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", user.Email)
	}

	// Test non-existent ID
	_, err = repo.GetByID(999)
	if err == nil {
		t.Error("Expected error for non-existent user ID")
	}
}

func TestSQLiteUserRepo_GetByEmail(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create a user
	_, _ = repo.Create("test@example.com", "password")

	// Get by email
	user, err := repo.GetByEmail("test@example.com")
	if err != nil {
		t.Fatalf("Failed to get user by email: %v", err)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", user.Email)
	}

	// Test non-existent email
	_, err = repo.GetByEmail("notfound@example.com")
	if err == nil {
		t.Error("Expected error for non-existent email")
	}
}

func TestSQLiteUserRepo_List(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create multiple users
	repo.Create("user1@example.com", "password")
	repo.Create("user2@example.com", "password")
	repo.Create("user3@example.com", "password")

	users, err := repo.List()
	if err != nil {
		t.Fatalf("Failed to list users: %v", err)
	}

	if len(users) != 3 {
		t.Errorf("Expected 3 users, got %d", len(users))
	}
}

func TestSQLiteUserRepo_Delete(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create a user
	user, _ := repo.Create("test@example.com", "password")

	// Delete the user
	err := repo.Delete(user.ID)
	if err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}

	// Verify user is deleted
	_, err = repo.GetByID(user.ID)
	if err == nil {
		t.Error("Expected error when getting deleted user")
	}

	// Deleting non-existent user should not error (idempotent)
	err = repo.Delete(999)
	if err != nil {
		t.Logf("Delete non-existent user returned: %v", err)
	}
}

func TestSQLiteUserRepo_UpdateRole(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Create a user
	user, _ := repo.Create("test@example.com", "password")

	// Update role
	err := repo.UpdateRole(user.ID, "admin")
	if err != nil {
		t.Fatalf("Failed to update role: %v", err)
	}

	// Verify role was updated
	updatedUser, _ := repo.GetByID(user.ID)
	if updatedUser.Role != "admin" {
		t.Errorf("Expected role 'admin', got '%s'", updatedUser.Role)
	}

	// Updating non-existent user should not error (idempotent)
	err = repo.UpdateRole(999, "admin")
	if err != nil {
		t.Logf("UpdateRole non-existent user returned: %v", err)
	}
}

func TestSQLiteUserRepo_IncrementFailedAttempts(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	user, _ := repo.Create("test@example.com", "password")

	// Increment failed attempts
	err := repo.IncrementFailedAttempts(user.ID)
	if err != nil {
		t.Fatalf("Failed to increment failed attempts: %v", err)
	}

	// Verify counter was incremented
	updatedUser, _ := repo.GetByID(user.ID)
	if updatedUser.FailedLoginAttempts != 1 {
		t.Errorf("Expected 1 failed attempt, got %d", updatedUser.FailedLoginAttempts)
	}

	// Increment again
	repo.IncrementFailedAttempts(user.ID)
	updatedUser, _ = repo.GetByID(user.ID)
	if updatedUser.FailedLoginAttempts != 2 {
		t.Errorf("Expected 2 failed attempts, got %d", updatedUser.FailedLoginAttempts)
	}
}

func TestSQLiteUserRepo_ResetFailedAttempts(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	user, _ := repo.Create("test@example.com", "password")

	// Set failed attempts
	repo.IncrementFailedAttempts(user.ID)
	repo.IncrementFailedAttempts(user.ID)

	// Reset
	err := repo.ResetFailedAttempts(user.ID)
	if err != nil {
		t.Fatalf("Failed to reset failed attempts: %v", err)
	}

	// Verify counter was reset
	updatedUser, _ := repo.GetByID(user.ID)
	if updatedUser.FailedLoginAttempts != 0 {
		t.Errorf("Expected 0 failed attempts, got %d", updatedUser.FailedLoginAttempts)
	}
}

func TestSQLiteUserRepo_LockAccount(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	user, _ := repo.Create("test@example.com", "password")

	lockUntil := time.Now().Add(15 * time.Minute)
	err := repo.LockAccount(user.ID, lockUntil)
	if err != nil {
		t.Fatalf("Failed to lock account: %v", err)
	}

	// Verify account is locked
	updatedUser, _ := repo.GetByID(user.ID)
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

	user, _ := repo.Create("test@example.com", "oldpassword")

	// Update password
	err := repo.UpdatePassword(user.ID, "newhashedpassword")
	if err != nil {
		t.Fatalf("Failed to update password: %v", err)
	}

	// Verify password was updated
	updatedUser, _ := repo.GetByID(user.ID)
	if updatedUser.Password != "newhashedpassword" {
		t.Errorf("Expected password 'newhashedpassword', got '%s'", updatedUser.Password)
	}
}

func TestSQLiteUserRepo_PasswordResetToken(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	user, _ := repo.Create("test@example.com", "password")

	// Set password reset token
	expiresAt := time.Now().Add(1 * time.Hour)
	err := repo.SetPasswordResetToken("test@example.com", "reset-token-123", expiresAt)
	if err != nil {
		t.Fatalf("Failed to set password reset token: %v", err)
	}

	// Get user by reset token
	foundUser, err := repo.GetByPasswordResetToken("reset-token-123")
	if err != nil {
		t.Fatalf("Failed to get user by reset token: %v", err)
	}

	if foundUser.ID != user.ID {
		t.Errorf("Expected user ID %d, got %d", user.ID, foundUser.ID)
	}

	// Clear password reset token
	err = repo.ClearPasswordResetToken(user.ID)
	if err != nil {
		t.Fatalf("Failed to clear reset token: %v", err)
	}

	// Verify token was cleared
	_, err = repo.GetByPasswordResetToken("reset-token-123")
	if err == nil {
		t.Error("Expected error when getting user by cleared token")
	}
}

func TestSQLiteUserRepo_CountUsers(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSQLiteUser(db)

	// Initially no users
	count, err := repo.CountUsers()
	if err != nil {
		t.Fatalf("Failed to count users: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 users, got %d", count)
	}

	// Add users
	repo.Create("user1@example.com", "password")
	repo.Create("user2@example.com", "password")

	count, err = repo.CountUsers()
	if err != nil {
		t.Fatalf("Failed to count users: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 users, got %d", count)
	}
}
