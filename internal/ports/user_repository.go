package ports

import (
	"time"

	"github.com/Olprog59/go-fun/internal/domain"
)

// UserRepository définit le contrat pour la persistance des utilisateurs
// Pattern: Repository Interface (Port)
type UserRepository interface {
	Create(email, password string) (*domain.User, error)
	GetByID(id int64) (*domain.User, error)
	GetByEmail(email string) (*domain.User, error)
	UpdateDBSendEmail(token string, expiresAt time.Time, id int64) error
	UpdateDBVerify(token string) error
	List() ([]*domain.User, error)
	Delete(id int64) error
}
