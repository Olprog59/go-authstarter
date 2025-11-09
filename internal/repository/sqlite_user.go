package repository

import (
	"database/sql"
	"time"

	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
)

// Vérifie que sqliteUserRepo implémente bien l'interface
var _ ports.UserRepository = (*sqliteUserRepo)(nil)

type sqliteUserRepo struct {
	db *sql.DB
}

// NewSQLiteUser crée une nouvelle instance du repository SQLite
func NewSQLiteUser(db *sql.DB) ports.UserRepository {
	return &sqliteUserRepo{db: db}
}

func (r *sqliteUserRepo) Create(email, password string) (*domain.User, error) {
	query := `INSERT INTO users (email, password) VALUES (?, ?)`
	result, err := r.db.Exec(query, email, password)
	if err != nil {

		return nil, wrapDBError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, wrapDBError(err)
	}

	return r.GetByID(id)
}

func (r *sqliteUserRepo) GetByID(id int64) (*domain.User, error) {
	query := `SELECT id, email, password, email_verified, created_at FROM users WHERE id = ?`
	user := &domain.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.EmailVerified,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, wrapDBError(err)
	}
	return user, nil
}

func (r *sqliteUserRepo) GetByEmail(email string) (*domain.User, error) {
	query := `SELECT id, email, password, email_verified, created_at FROM users WHERE email = ?`
	user := &domain.User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.EmailVerified,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, wrapDBError(err)
	}
	return user, nil
}

func (r *sqliteUserRepo) List() ([]*domain.User, error) {
	query := `SELECT id, email, password, created_at FROM users ORDER BY created_at DESC`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, wrapDBError(err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		user := &domain.User{}
		if err := rows.Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt); err != nil {
			return nil, wrapDBError(err)
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (r *sqliteUserRepo) Delete(id int64) error {
	query := `DELETE FROM users WHERE id = ?`
	_, err := r.db.Exec(query, id)
	return wrapDBError(err)
}

// UpdateDBSendEmail implements ports.UserRepository.
func (r *sqliteUserRepo) UpdateDBSendEmail(token string, expiresAt time.Time, id int64) error {
	query := `UPDATE users
		SET verification_token = ?, verification_expires_at = ?
		WHERE id = ?`

	_, err := r.db.Exec(query, token, expiresAt, id)
	if err != nil {
		return err
	}
	return nil
}

func (r *sqliteUserRepo) UpdateDBVerify(token string) error {
	query := `
		UPDATE users
		SET email_verified = 1, verification_token = NULL, verification_expires_at = NULL
		WHERE verification_token = ? AND verification_expires_at > ?
	`

	rows, err := r.db.Exec(query, token, time.Now())
	rowsAffected, _ := rows.RowsAffected()
	if err != nil || rowsAffected == 0 {
		return err
	}
	return nil
}
