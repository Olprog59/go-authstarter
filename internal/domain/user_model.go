package domain

import "time"

// User represents the core business entity for a user.
// This struct is "pure" as it belongs to the domain layer and has no dependencies
// on external packages like databases or serializers. It defines the essential
// properties of a user within the system.
type User struct {
	BaseModel             // Embeds common fields like CreatedAt, UpdatedAt, DeletedAt.
	ID                    int64
	Email                 string    // The user's unique email address.
	Password              string    // The hashed password.
	CreatedAt             time.Time // Timestamp of when the user was created.
	Token                 *RefreshToken
	EmailVerified         bool      // Flag indicating if the user has verified their email address.
	VerificationToken     string    // The token sent to the user for email verification.
	VerificationExpiresAt time.Time // The expiration time of the verification token.
}

// RefreshToken represents a stored refresh token.
// This entity is used to manage user sessions and allows for the issuance of new
// access tokens without requiring the user to re-authenticate.
type RefreshToken struct {
	Token     string    // The refresh token value itself (often stored as a hash).
	UserID    int64     // The ID of the user who owns the token.
	IssueAt   time.Time // The timestamp when the token was issued.
	ExpiresAt time.Time // The timestamp when the token will expire.
	IsRevoked bool      // A flag to indicate if the token has been revoked.
	IPHash    string    // A SHA-256 hash of the client's IP address, used for security binding.
	UAHash    string    // A SHA-256 hash of the client's User-Agent, for security binding.
}

// IsTokenExpired checks if the refresh token has passed its expiration time.
// It compares the current time with the token's `ExpiresAt` timestamp.
func (rt *RefreshToken) IsTokenExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsTokenValid checks if the refresh token is currently valid.
// A token is considered valid if it has not been revoked AND it has not expired.
// This provides a single, convenient method for checking the overall validity of a token.
func (rt *RefreshToken) IsTokenValid() bool {
	return !rt.IsRevoked && !rt.IsTokenExpired()
}

// IsDeleted checks if the entity has been "soft-deleted".
// Soft deletion is a pattern where a record is marked as deleted (e.g., by setting a
// `DeletedAt` timestamp) instead of being permanently removed from the database.
// This allows for data recovery and maintains historical integrity.
func (bm *BaseModel) IsDeleted() bool {
	return bm.DeletedAt != nil
}
