package service

import (
	"errors"
	"log"

	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
	"github.com/Olprog59/go-fun/internal/service/auth"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type UserService struct {
	repo ports.UserRepository
	conf *config.Config
}

func NewUserService(r ports.UserRepository, c *config.Config) *UserService {
	return &UserService{repo: r, conf: c}
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

func (s *UserService) encode(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), 10)
}

func (s *UserService) Register(username, password string) (*domain.User, error) {
	bpass, err := s.encode(password)
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
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	token, err := auth.GenerateJWT(user.Username, s.conf.JWTToken)
	if err != nil {
		log.Println("Error generating JWT:", err)
		return nil, err
	}
	user.Token = token

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
