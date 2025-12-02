package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/dto"
)

// ListUsers returns paginated list of users / Retourne la liste paginée des utilisateurs
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	// Parse pagination parameters from query string
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	// Default values
	page := 1
	limit := 20

	// Parse page
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	// Parse limit (max 100 to prevent abuse)
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = min(l, 100)
		}
	}

	// Calculate offset
	offset := (page - 1) * limit

	// Get paginated users
	users, totalCount, err := h.container.UserSvc.ListUsers(r.Context(), offset, limit)
	if err != nil {
		ErrorResponse(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}

	// Convert domain users to DTOs (removes sensitive data)
	userDTOs := make([]dto.UserLoginDTOResponse, len(users))
	for i, user := range users {
		userDTOs[i] = *dto.UserLoginToDTO(user)
	}

	// Calculate total pages
	totalPages := (totalCount + limit - 1) / limit // Ceiling division

	// Return response with pagination metadata
	response := map[string]any{
		"users": userDTOs,
		"pagination": map[string]int{
			"total":      totalCount,
			"page":       page,
			"limit":      limit,
			"totalPages": totalPages,
		},
	}

	jsonResponse(w, response)
}

// DeleteUser deletes a user by ID / Supprime un utilisateur par ID
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL path
	idStr := r.PathValue("id")
	if idStr == "" {
		ErrorResponse(w, "User ID is required", http.StatusBadRequest)
		return
	}

	userID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		ErrorResponse(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Delete the user
	if err := h.container.UserSvc.DeleteUser(r.Context(), userID); err != nil {
		ErrorResponse(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User deleted successfully",
	})
}

// UpdateUserRole is an admin-only endpoint that allows changing a user's role.
// This endpoint should be protected with RequireRole(domain.RoleAdmin) middleware.
//
// It expects a JSON body with the new role:
//
//	{
//	  "role": "moderator"
//	}
// UpdateUserRole updates user role / Met à jour le rôle d'un utilisateur
func (h *Handler) UpdateUserRole(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL path
	idStr := r.PathValue("id")
	if idStr == "" {
		ErrorResponse(w, "User ID is required", http.StatusBadRequest)
		return
	}

	userID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		ErrorResponse(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Limit request body size to 1MB to prevent DoS attacks
	limitRequestBody(w, r, 1*1024*1024)

	// Parse request body
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			ErrorResponse(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		ErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate role
	newRole := domain.UserRole(req.Role)
	if !newRole.IsValid() {
		ErrorResponse(w, "Invalid role. Must be one of: user, moderator, admin", http.StatusBadRequest)
		return
	}

	// Update user role
	if err := h.container.UserSvc.UpdateUserRole(r.Context(), userID, newRole); err != nil {
		ErrorResponse(w, "Failed to update user role", http.StatusInternalServerError)
		return
	}

	// Rotate CSRF token after role change for security
	// (role changes affect permissions and are sensitive operations)
	if err := h.rotateCSRFToken(w); err != nil {
		// Log error but don't fail the request - role was already updated successfully
		slog.Error("failed to rotate CSRF token after role update", "err", err)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User role updated successfully",
	})
}

// GetUserStats is a moderator-accessible endpoint that returns statistics about users.
// Both moderators and admins can access this endpoint.
// GetUserStats returns user statistics / Retourne les statistiques utilisateurs
func (h *Handler) GetUserStats(w http.ResponseWriter, r *http.Request) {
	// For stats, we want all users. Use a large limit to get all in one call.
	// Note: In very large systems (>100k users), consider using aggregation queries in the DB
	users, totalCount, err := h.container.UserSvc.ListUsers(r.Context(), 0, 100000)
	if err != nil {
		ErrorResponse(w, "Failed to retrieve stats", http.StatusInternalServerError)
		return
	}

	// Calculate simple statistics
	stats := map[string]interface{}{
		"total_users": totalCount, // Use totalCount from DB instead of len(users)
		"verified_users": func() int {
			count := 0
			for _, u := range users {
				if u.EmailVerified {
					count++
				}
			}
			return count
		}(),
		"roles": func() map[string]int {
			roleCounts := map[string]int{
				"user":      0,
				"moderator": 0,
				"admin":     0,
			}
			for _, u := range users {
				roleCounts[string(u.Role)]++
			}
			return roleCounts
		}(),
	}

	jsonResponse(w, stats)
}
