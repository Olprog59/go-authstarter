package dto

import "github.com/Olprog59/go-fun/internal/domain"

type UserLoginDTOResponse struct {
	ID       int64  `json:"id,omitempty"`
	UserName string `json:"user_name,omitempty"`
}

type UserDTOReq struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func UserLoginToDTO(user *domain.User) *UserLoginDTOResponse {
	return &UserLoginDTOResponse{
		ID:       user.ID,
		UserName: user.Username,
	}
}
