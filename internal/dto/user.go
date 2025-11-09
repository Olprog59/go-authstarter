package dto

import "github.com/Olprog59/go-fun/internal/domain"

// UserLoginDTOResponse represents the data transfer object for a user's login response.
// It contains fields that are safe to expose to the client after a successful login.
type UserLoginDTOResponse struct {
	ID    int64  `json:"id,omitempty"`    // The unique identifier of the user.
	Email string `json:"email,omitempty"` // The email address of the user.
}

// UserDTOReq represents the data transfer object for user login or registration requests.
// It contains the credentials provided by the client.
type UserDTOReq struct {
	Username string `json:"email,omitempty"`    // The user's email address, used as a username.
	Password string `json:"password,omitempty"` // The user's password.
}

// UserLoginToDTO converts a `domain.User` model into a `UserLoginDTOResponse` DTO.
// This function is used to transform internal domain objects into a format suitable
// for API responses, ensuring that only necessary and safe information is exposed.
func UserLoginToDTO(user *domain.User) *UserLoginDTOResponse {
	return &UserLoginDTOResponse{
		ID:    user.ID,
		Email: user.Email,
	}
}
