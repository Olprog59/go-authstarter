package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/dto"
)

// ListUsers is an admin-only endpoint that returns a list of all users in the system.
// This endpoint should be protected with RequireRole(domain.RoleAdmin) middleware.
//
// It retrieves all user records from the database and returns them as a JSON array,
// excluding sensitive information like passwords (handled by the DTO conversion).
//
// Example usage in mux.go:
//
//	mux.Handle("GET /api/admin/users", chain(h.ListUsers, mw, mw.Auth, mw.RequireRole("admin")))
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.container.UserSvc.ListUsers()
	if err != nil {
		ErrorResponse(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}

	// Convert domain users to DTOs (removes sensitive data)
	userDTOs := make([]dto.UserLoginDTOResponse, len(users))
	for i, user := range users {
		userDTOs[i] = *dto.UserLoginToDTO(user)
	}

	jsonResponse(w, userDTOs)
}

// DeleteUser is an admin-only endpoint that permanently deletes a user from the system.
// This endpoint should be protected with RequireRole(domain.RoleAdmin) middleware.
//
// It expects a user ID in the URL path (e.g., DELETE /api/admin/users/123)
// and removes the user from the database.
//
// Example usage in mux.go:
//
//	mux.Handle("DELETE /api/admin/users/{id}", chain(h.DeleteUser, mw, mw.Auth, mw.RequireRole("admin")))
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
	if err := h.container.UserSvc.DeleteUser(userID); err != nil {
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
//
// Valid roles are: "user", "moderator", "admin"
//
// Example usage in mux.go:
//
//	mux.Handle("PATCH /api/admin/users/{id}/role", chain(h.UpdateUserRole, mw, mw.Auth, mw.RequireRole("admin")))
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

	// Parse request body
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	if err := h.container.UserSvc.UpdateUserRole(userID, newRole); err != nil {
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
//
// Example usage in mux.go:
//
//	mux.Handle("GET /api/moderator/stats", chain(h.GetUserStats, mw, mw.Auth, mw.RequireRole("moderator")))
func (h *Handler) GetUserStats(w http.ResponseWriter, r *http.Request) {
	users, err := h.container.UserSvc.ListUsers()
	if err != nil {
		ErrorResponse(w, "Failed to retrieve stats", http.StatusInternalServerError)
		return
	}

	// Calculate simple statistics
	stats := map[string]interface{}{
		"total_users": len(users),
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
