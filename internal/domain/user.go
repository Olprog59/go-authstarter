package domain

import "time"

// User représente l'entité métier User (pure, sans dépendances)
type User struct {
	ID        int64
	Username  string
	Password  string
	CreatedAt time.Time
}
