package web

// ContextKey defines a type for context keys to avoid collisions.
type ContextKey string

// Defines the key for storing JWT claims in the context.
const ClaimsContextKey = ContextKey("claims")
