package dto

import "github.com/Olprog59/go-fun/internal/domain"

type UserLoginDTOResponse struct {
	ID    int64  `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
}

type UserDTOReq struct {
	Username string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

func UserLoginToDTO(user *domain.User) *UserLoginDTOResponse {
	return &UserLoginDTOResponse{
		ID:    user.ID,
		Email: user.Email,
	}
}
