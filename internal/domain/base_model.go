package domain

import "time"

// BaseModel contient les champs communs à toutes les entités
type BaseModel struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time // Pour le soft delete (optionnel)
}
