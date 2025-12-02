package dto

import "github.com/Olprog59/go-authstarter/internal/domain"

// UserLoginDTOResponse is DTO for user login response / Est le DTO pour la réponse de connexion utilisateur
type UserLoginDTOResponse struct {
	ID    int64  `json:"id,omitempty"`    // User unique identifier / Identifiant unique de l'utilisateur
	Email string `json:"email,omitempty"` // User email address / Adresse email de l'utilisateur
	Role  string `json:"role,omitempty"`  // User role / Rôle de l'utilisateur
}

// UserDTOReq is DTO for login/registration requests / Est le DTO pour les demandes de connexion/inscription
type UserDTOReq struct {
	Username string `json:"email,omitempty"`    // User email / Email de l'utilisateur
	Password string `json:"password,omitempty"` // User password / Mot de passe de l'utilisateur
}

// UserLoginToDTO converts domain.User to UserLoginDTOResponse / Convertit domain.User en UserLoginDTOResponse
func UserLoginToDTO(user *domain.User) *UserLoginDTOResponse {
	return &UserLoginDTOResponse{
		ID:    user.ID,
		Email: user.Email,
		Role:  string(user.Role),
	}
}

// PasswordResetRequestDTO is DTO for password reset request / Est le DTO pour la demande de réinitialisation
type PasswordResetRequestDTO struct {
	Email string `json:"email"` // Account email address / Adresse email du compte
}

// PasswordResetDTO is DTO for password reset completion / Est le DTO pour terminer la réinitialisation
type PasswordResetDTO struct {
	Token       string `json:"token"`        // Password reset token / Token de réinitialisation
	NewPassword string `json:"new_password"` // New password / Nouveau mot de passe
}
