package ports

import "github.com/Olprog59/go-fun/internal/domain"

// UserRepository définit le contrat pour la persistance des utilisateurs
// Pattern: Repository Interface (Port)
type UserRepository interface {
	Create(username, password string) (*domain.User, error)
	GetByID(id int64) (*domain.User, error)
	GetByUsername(username string) (*domain.User, error)
	List() ([]*domain.User, error)
	Delete(id int64) error
}
