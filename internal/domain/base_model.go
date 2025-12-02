package domain

import "time"

// BaseModel provides common fields for domain models / Fournit les champs communs aux modèles
type BaseModel struct {
	CreatedAt time.Time  // Record creation time / Heure de création de l'enregistrement
	UpdatedAt time.Time  // Record last update time / Heure de dernière mise à jour
	DeletedAt *time.Time // Soft delete timestamp / Horodatage de suppression logique
}
