package service

import (
	"errors"
	"fmt"
	"time"

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
	repo         ports.UserRepository
	refreshStore ports.RefreshTokenStore
	conf         *config.Config
}

func NewUserService(repo ports.UserRepository, conf *config.Config, refreshStore ports.RefreshTokenStore) *UserService {
	return &UserService{repo: repo, conf: conf, refreshStore: refreshStore}
}

// Auth vérifie le mot de passe.
func (s *UserService) Auth(username, password string) (*domain.User, error) {
	u, err := s.repo.GetByEmail(username)
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

func (s *UserService) Login(username, password string) (*domain.User, *auth.TokenPair, error) {
	user, err := s.repo.GetByEmail(username)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}
	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	// Générer access + refresh tokens
	tokenPair, err := auth.GenerateTokenPair(user.ID, s.conf.JWTKey)
	if err != nil {
		return nil, nil, fmt.Errorf("génération tokens: %w", err)
	}

	// Construire l'entité de domaine pour le refresh token
	rt := &domain.RefreshToken{
		Token:     tokenPair.RefreshToken,
		UserID:    user.ID,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		IsRevoked: false,
	}

	// Sauvegarder via le repo
	if err := s.refreshStore.Save(rt); err != nil {
		return nil, nil, fmt.Errorf("stockage refresh token: %w", err)
	}

	// Attacher l’entité au user (optionnel)
	user.Token = rt

	return user, tokenPair, nil
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

func (s *UserService) RefreshToken(refreshToken string) (*auth.TokenPair, error) {
	// Récupérer le token stocké
	storedToken, err := s.refreshStore.Get(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token invalide ou introuvable")
	}

	// Vérifier si le token est révoqué ou expiré
	if storedToken.IsRevoked || time.Now().After(storedToken.ExpiresAt) {
		return nil, fmt.Errorf("refresh token expiré ou révoqué")
	}

	userID := storedToken.UserID

	// Rotation du refresh token : révoquer l'ancien
	if err := s.refreshStore.Revoke(refreshToken); err != nil {
		return nil, fmt.Errorf("échec révocation refresh token")
	}

	// Générer une nouvelle paire de tokens
	tokenPair, err := auth.GenerateTokenPair(userID, s.conf.JWTKey)
	if err != nil {
		return nil, fmt.Errorf("génération token impossible")
	}

	// Sauvegarder le nouveau refresh token
	newRefreshToken := &domain.RefreshToken{
		Token:     tokenPair.RefreshToken,
		UserID:    userID,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		IsRevoked: false,
	}

	if err := s.refreshStore.Save(newRefreshToken); err != nil {
		return nil, fmt.Errorf("sauvegarde nouveau refresh token impossible")
	}

	return tokenPair, nil
}
