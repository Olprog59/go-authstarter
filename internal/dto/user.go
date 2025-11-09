package dto

import "github.com/Olprog59/go-fun/internal/domain"

type UserLoginDTOResponse struct {
	Email string `json:"email,omitempty"`
}

type UserDTOReq struct {
	Username string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

func UserLoginToDTO(user *domain.User) *UserLoginDTOResponse {
	return &UserLoginDTOResponse{
		Email: user.Email,
	}
}
