package repository

import (
	"database/sql"

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

func (r *sqliteUserRepo) Create(username, password string) (*domain.User, error) {
	query := `INSERT INTO users (username, password) VALUES (?, ?)`
	result, err := r.db.Exec(query, username, password)
	if err != nil {
		// vérification d'erreur spécifique à SQLite
		return nil, wrapDBError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, wrapDBError(err)
	}

	return r.GetByID(id)
}

func (r *sqliteUserRepo) GetByID(id int64) (*domain.User, error) {
	query := `SELECT id, username, password, created_at FROM users WHERE id = ?`
	user := &domain.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Password,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, wrapDBError(err)
	}
	return user, nil
}

func (r *sqliteUserRepo) GetByUsername(username string) (*domain.User, error) {
	query := `SELECT id, username, password, created_at FROM users WHERE username = ?`
	user := &domain.User{}
	err := r.db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Password,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, wrapDBError(err)
	}
	return user, nil
}

func (r *sqliteUserRepo) List() ([]*domain.User, error) {
	query := `SELECT id, username, password, created_at FROM users ORDER BY created_at DESC`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, wrapDBError(err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		user := &domain.User{}
		if err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.CreatedAt); err != nil {
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
