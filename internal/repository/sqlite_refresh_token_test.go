package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/Olprog59/go-authstarter/internal/domain"
	_ "modernc.org/sqlite"
)

func setupRefreshTokenTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}

	// Create schema
	schema := `
	CREATE TABLE refresh_tokens (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		issue_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP NOT NULL,
		is_revoked BOOLEAN NOT NULL DEFAULT 0,
		ip_hash TEXT NOT NULL DEFAULT '',
		ua_hash TEXT NOT NULL DEFAULT ''
	);
	`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	return db
}

func TestRefreshTokenStore_Save(t *testing.T) {
	db := setupRefreshTokenTestDB(t)
	defer db.Close()

	store := NewSQLiteRefreshTokenStore(db)

	token := &domain.RefreshToken{
		Token:     "test-token-12345",
		UserID:    1,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked: false,
		IPHash:    "ip-hash",
		UAHash:    "ua-hash",
	}

	err := store.Save(context.Background(), token)
	if err != nil {
		t.Fatalf("Failed to save refresh token: %v", err)
	}

	// Verify token was saved (note: token is hashed in database)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM refresh_tokens").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count tokens: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 token in database, got %d", count)
	}

	// Test saving nil token
	err = store.Save(context.Background(), nil)
	if err == nil {
		t.Error("Expected error when saving nil token")
	}
}

func TestRefreshTokenStore_Get(t *testing.T) {
	db := setupRefreshTokenTestDB(t)
	defer db.Close()

	store := NewSQLiteRefreshTokenStore(db)

	// Create and save a token
	originalToken := "test-token-12345"
	token := &domain.RefreshToken{
		Token:     originalToken,
		UserID:    1,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked: false,
		IPHash:    "ip-hash",
		UAHash:    "ua-hash",
	}

	err := store.Save(context.Background(), token)
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Retrieve token
	retrieved, err := store.Get(context.Background(), originalToken)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	if retrieved.UserID != token.UserID {
		t.Errorf("Expected user ID %d, got %d", token.UserID, retrieved.UserID)
	}

	if retrieved.IPHash != token.IPHash {
		t.Errorf("Expected IP hash %s, got %s", token.IPHash, retrieved.IPHash)
	}

	if retrieved.UAHash != token.UAHash {
		t.Errorf("Expected UA hash %s, got %s", token.UAHash, retrieved.UAHash)
	}

	// Test getting non-existent token
	_, err = store.Get(context.Background(), "non-existent-token")
	if err == nil {
		t.Error("Expected error when getting non-existent token")
	}
}

func TestRefreshTokenStore_Revoke(t *testing.T) {
	db := setupRefreshTokenTestDB(t)
	defer db.Close()

	store := NewSQLiteRefreshTokenStore(db)

	// Create and save a token
	originalToken := "test-token-revoke"
	token := &domain.RefreshToken{
		Token:     originalToken,
		UserID:    1,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked: false,
		IPHash:    "ip-hash",
		UAHash:    "ua-hash",
	}

	err := store.Save(context.Background(), token)
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Revoke token
	err = store.Revoke(context.Background(), originalToken)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Verify token is revoked
	retrieved, err := store.Get(context.Background(), originalToken)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	if !retrieved.IsRevoked {
		t.Error("Expected token to be revoked")
	}

	// Test revoking non-existent token (should not error)
	err = store.Revoke(context.Background(), "non-existent-token")
	if err != nil {
		t.Logf("Revoke non-existent token returned: %v", err)
	}
}

func TestRefreshTokenStore_RevokeAllForUser(t *testing.T) {
	db := setupRefreshTokenTestDB(t)
	defer db.Close()

	store := NewSQLiteRefreshTokenStore(db)

	// Create multiple tokens for same user
	userID := int64(1)
	for i := 0; i < 3; i++ {
		token := &domain.RefreshToken{
			Token:     string(rune('a' + i)) + "-token",
			UserID:    userID,
			IssueAt:   time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			IsRevoked: false,
			IPHash:    "ip-hash",
			UAHash:    "ua-hash",
		}
		err := store.Save(context.Background(), token)
		if err != nil {
			t.Fatalf("Failed to save token %d: %v", i, err)
		}
	}

	// Create token for different user
	otherToken := &domain.RefreshToken{
		Token:     "other-user-token",
		UserID:    2,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked: false,
		IPHash:    "ip-hash",
		UAHash:    "ua-hash",
	}
	err := store.Save(context.Background(), otherToken)
	if err != nil {
		t.Fatalf("Failed to save other user token: %v", err)
	}

	// Revoke all tokens for user 1
	err = store.RevokeAllForUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("Failed to revoke all tokens for user: %v", err)
	}

	// Verify user 1 tokens are revoked
	var revokedCount int
	err = db.QueryRow("SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ? AND is_revoked = 1", userID).Scan(&revokedCount)
	if err != nil {
		t.Fatalf("Failed to count revoked tokens: %v", err)
	}

	if revokedCount != 3 {
		t.Errorf("Expected 3 revoked tokens for user 1, got %d", revokedCount)
	}

	// Verify user 2 token is NOT revoked
	retrieved, err := store.Get(context.Background(), "other-user-token")
	if err != nil {
		t.Fatalf("Failed to get other user token: %v", err)
	}

	if retrieved.IsRevoked {
		t.Error("Expected other user token to NOT be revoked")
	}
}

func TestRefreshTokenStore_PurgeExpired(t *testing.T) {
	db := setupRefreshTokenTestDB(t)
	defer db.Close()

	store := NewSQLiteRefreshTokenStore(db)

	// Create expired token
	expiredToken := &domain.RefreshToken{
		Token:     "expired-token",
		UserID:    1,
		IssueAt:   time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired yesterday
		IsRevoked: false,
		IPHash:    "ip-hash",
		UAHash:    "ua-hash",
	}
	err := store.Save(context.Background(), expiredToken)
	if err != nil {
		t.Fatalf("Failed to save expired token: %v", err)
	}

	// Create valid token
	validToken := &domain.RefreshToken{
		Token:     "valid-token",
		UserID:    1,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Expires tomorrow
		IsRevoked: false,
		IPHash:    "ip-hash",
		UAHash:    "ua-hash",
	}
	err = store.Save(context.Background(), validToken)
	if err != nil {
		t.Fatalf("Failed to save valid token: %v", err)
	}

	// Purge expired tokens
	err = store.PurgeExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("Failed to purge expired tokens: %v", err)
	}

	// Verify only valid token remains
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM refresh_tokens").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count tokens: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 token remaining, got %d", count)
	}

	// Verify the remaining token is the valid one
	_, err = store.Get(context.Background(), "valid-token")
	if err != nil {
		t.Error("Expected valid token to still exist")
	}

	// Verify expired token was deleted
	_, err = store.Get(context.Background(), "expired-token")
	if err == nil {
		t.Error("Expected expired token to be deleted")
	}
}

func TestRefreshTokenStore_WithTx(t *testing.T) {
	db := setupRefreshTokenTestDB(t)
	defer db.Close()

	store := NewSQLiteRefreshTokenStore(db)

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	// Get store with transaction
	txStore := store.WithTx(tx)

	// Save token using transaction
	token := &domain.RefreshToken{
		Token:     "tx-token",
		UserID:    1,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked: false,
		IPHash:    "ip-hash",
		UAHash:    "ua-hash",
	}

	err = txStore.Save(context.Background(), token)
	if err != nil {
		t.Fatalf("Failed to save token in transaction: %v", err)
	}

	// Rollback transaction
	tx.Rollback()

	// Verify token was not saved
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM refresh_tokens").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count tokens: %v", err)
	}

	if count != 0 {
		t.Errorf("Expected 0 tokens after rollback, got %d", count)
	}

	// Test with commit
	tx2, err := db.Begin()
	if err != nil {
		t.Fatalf("Failed to begin second transaction: %v", err)
	}

	txStore2 := store.WithTx(tx2)
	err = txStore2.Save(context.Background(), token)
	if err != nil {
		t.Fatalf("Failed to save token in second transaction: %v", err)
	}

	tx2.Commit()

	// Verify token was saved
	err = db.QueryRow("SELECT COUNT(*) FROM refresh_tokens").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count tokens after commit: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 token after commit, got %d", count)
	}
}
