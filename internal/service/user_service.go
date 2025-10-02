package service

import (
	"errors"

	"github.com/Olprog59/go-plugins/internal/domain"
	"github.com/Olprog59/go-plugins/internal/ports"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type UserService struct {
	repo ports.UserRepository
}

func NewUserService(r ports.UserRepository) *UserService {
	return &UserService{repo: r}
}

// Auth vérifie le mot de passe.
func (s *UserService) Auth(username, password string) (*domain.User, error) {
	u, err := s.repo.GetByUsername(username)
	if err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) != nil {
		return nil, errors.New("invalid credentials")
	}
	return u, nil
}

func (s *UserService) Encode(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), 10)
}

func (s *UserService) Register(username, password string) (*domain.User, error) {
	bpass, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return nil, err
	}
	return s.repo.Create(username, string(bpass))
}

func (s *UserService) Login(username, password string) (*domain.User, error) {
	user, err := s.repo.GetByUsername(username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))

	if user.Password != password || err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

func (s *UserService) GetUser(id int64) (*domain.User, error) {
	user, err := s.repo.GetByID(id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (s *UserService) ListUsers() ([]*domain.User, error) {
	return s.repo.List()
}
