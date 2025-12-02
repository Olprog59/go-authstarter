package repository

import (
	"database/sql"

	"github.com/Olprog59/go-authstarter/internal/ports"
)

// DatabaseFactory must be implemented by each database package / Doit être implémenté par chaque package de BD
// This interface ensures compile-time safety: if you add a new repository,
// you MUST implement it in all database packages (sqlite, mysql, postgres)
// Cette interface garantit la sécurité à la compilation : si tu ajoutes un nouveau repository,
// tu DOIS l'implémenter dans tous les packages de BD (sqlite, mysql, postgres)
type DatabaseFactory interface {
	// NewUserRepository creates user repository / Crée le repository utilisateur
	NewUserRepository(db *sql.DB) ports.UserRepository

	// NewRefreshTokenStore creates refresh token store / Crée le store de refresh tokens
	NewRefreshTokenStore(db *sql.DB) ports.RefreshTokenStore

	// When adding a new table/repository, add the method here
	// The compiler will force you to implement it in all database packages
	// Quand tu ajoutes une nouvelle table/repository, ajoute la méthode ici
	// Le compilateur te forcera à l'implémenter dans tous les packages de BD
	//
	// Example / Exemple:
	// NewProductRepository(db *sql.DB) ports.ProductRepository
}
