package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
	"github.com/Olprog59/go-fun/internal/repository"
	"github.com/Olprog59/go-fun/internal/service/auth"
	"github.com/google/uuid"
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
	emailSvc     *EmailService
	userLocks    map[int64]*sync.Mutex
	mapMutex     sync.Mutex
	db           *sql.DB
}

func NewUserService(repo ports.UserRepository, conf *config.Config, refreshStore ports.RefreshTokenStore, db *sql.DB) *UserService {
	return &UserService{
		repo:         repo,
		conf:         conf,
		refreshStore: refreshStore,
		emailSvc:     NewEmailService(conf),
		userLocks:    make(map[int64]*sync.Mutex),
		db:           db,
	}
}

func (s *UserService) getUserLock(userID int64) *sync.Mutex {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()

	if _, ok := s.userLocks[userID]; !ok {
		s.userLocks[userID] = &sync.Mutex{}
	}

	return s.userLocks[userID]
}

// Auth vérifie le mot de passe.
func (s *UserService) Auth(email, password string) (*domain.User, error) {
	u, err := s.repo.GetByEmail(email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// 🔐 Bloquer si email non vérifié
	if !u.EmailVerified {
		return nil, errors.New("email not verified")
	}

	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) != nil {
		return nil, ErrInvalidCredentials
	}

	return u, nil
}

func (s *UserService) encode(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), 10)
}

func (s *UserService) Register(email, password string) (*domain.User, error) {
	if !isValidEmail(email) {
		return nil, errors.New("invalid email format")
	}
	if !isStrongPassword(password) {
		return nil, errors.New("password must be ≥8 chars with upper, lower, digit, special")
	}

	// Vérifier si email déjà utilisé
	if _, err := s.repo.GetByEmail(email); err == nil {
		return nil, errors.New("email already registered")
	} else if !errors.Is(err, ports.ErrNotFound) && !errors.Is(err, repository.ErrNoRecord) {
		return nil, err
	}

	bpass, err := s.encode(password)
	if err != nil {
		return nil, err
	}
	user, err := s.repo.Create(email, string(bpass))
	if err != nil {
		return nil, err
	}

	err = s.SendVerificationEmail(user)
	if err != nil {
		return nil, err
	}

	log.Println(user.VerificationToken)

	// Envoi async de l’email de vérification
	go func() {
		link := fmt.Sprintf("%s/verify?token=%s",
			map[bool]string{true: "http://localhost:8080", false: "https://votre-domaine.com"}[s.conf.Environment == "development"],
			user.VerificationToken)

		body := fmt.Sprintf(`<p>Veuillez confirmer votre email : <a href="%s">Confirmer</a></p>`, link)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.emailSvc.Send(ctx, email, "Vérifiez votre compte", body); err != nil {
			slog.Error("Échec envoi email vérification", "email", email, "err", err)
			return
		}

		// Affichage dev uniquement
		if s.conf.Environment == "development" {
			slog.Info("📧 Lien vérification (dev)", "email", email, "link", link)
		}
	}()

	return user, nil
}

func (s *UserService) Login(email, password, ipHash, uaHash string) (*domain.User, *auth.TokenPair, error) {
	user, err := s.repo.GetByEmail(email)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	if !user.EmailVerified {
		return nil, nil, errors.New("email not verified")
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	mu := s.getUserLock(user.ID)
	mu.Lock()
	defer mu.Unlock()

	// --- Début de la transaction ---
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	// Rollback en cas de panique ou d'erreur non gérée
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p) // re-panic après rollback
		} else if err != nil {
			_ = tx.Rollback() // err est non-nil, donc rollback
		}
	}()

	// Utiliser le store transactionnel
	txStore := s.refreshStore.WithTx(tx)

	if err = txStore.RevokeAllForUser(user.ID); err != nil {
		return nil, nil, fmt.Errorf("failed to revoke old tokens: %w", err)
	}

	tokenPair, err := auth.GenerateTokenPair(user.ID, s.conf.Auth.JWTSecret, s.conf.Auth.AccessTokenDuration, s.conf.Auth.RefreshTokenDuration)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	now := time.Now()
	rt := &domain.RefreshToken{
		Token:     tokenPair.RefreshToken,
		UserID:    user.ID,
		IssueAt:   now,
		ExpiresAt: now.Add(s.conf.Auth.RefreshTokenDuration),
		IsRevoked: false,
		IPHash:    ipHash,
		UAHash:    uaHash,
	}

	if err = txStore.Save(rt); err != nil {
		return nil, nil, fmt.Errorf("failed to save new token: %w", err)
	}

	// Tout s'est bien passé, on commit la transaction
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	// --- Fin de la transaction ---

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

func (s *UserService) RefreshToken(refreshToken, ipHash, uaHash string) (*auth.TokenPair, error) {
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
	if err = s.refreshStore.Revoke(refreshToken); err != nil {
		return nil, fmt.Errorf("échec révocation refresh token")
	}

	// Générer une nouvelle paire de tokens
	tokenPair, err := auth.GenerateTokenPair(userID, s.conf.Auth.JWTSecret, s.conf.Auth.AccessTokenDuration, s.conf.Auth.RefreshTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("génération token impossible")
	}

	// Sauvegarder le nouveau refresh token
	now := time.Now()
	newRefreshToken := &domain.RefreshToken{
		Token:     tokenPair.RefreshToken,
		UserID:    userID,
		IssueAt:   now,
		ExpiresAt: now.Add(s.conf.Auth.RefreshTokenDuration),
		IsRevoked: false,
		IPHash:    ipHash,
		UAHash:    uaHash,
	}

	if err := s.refreshStore.Save(newRefreshToken); err != nil {
		return nil, fmt.Errorf("sauvegarde nouveau refresh token impossible")
	}

	return tokenPair, nil
}

func (s *UserService) SendVerificationEmail(user *domain.User) error {
	token := uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)

	err := s.repo.UpdateDBSendEmail(token, expiresAt, user.ID)
	if err != nil {
		return nil
	}

	user.VerificationToken = token
	user.VerificationExpiresAt = expiresAt

	return nil
}

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil && len(email) <= 254
}

func isStrongPassword(pw string) bool {
	if len(pw) < 8 {
		return false
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	special := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case strings.ContainsRune(special, r):
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasDigit && hasSpecial
}
