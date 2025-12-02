package dto_test

import (
	"testing"

	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/dto"
)

func TestUserLoginToDTO(t *testing.T) {
	// Create a sample domain.User
	user := &domain.User{
		ID:    123,
		Email: "test@example.com",
		Role:  domain.RoleUser,
	}

	// Convert to DTO
	userDTO := dto.UserLoginToDTO(user)

	// Assert the values
	if userDTO.ID != user.ID {
		t.Errorf("Expected ID %d, got %d", user.ID, userDTO.ID)
	}
	if userDTO.Email != user.Email {
		t.Errorf("Expected Email %s, got %s", user.Email, userDTO.Email)
	}
	if userDTO.Role != string(user.Role) {
		t.Errorf("Expected Role %s, got %s", string(user.Role), userDTO.Role)
	}
}
