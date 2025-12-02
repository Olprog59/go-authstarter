package web

// ContextKey is a custom type used for creating context keys.
// Using a custom type for context keys helps prevent collisions between keys
// defined in different packages. It ensures that the keys used by this package
// are unique and will not clash with keys from other standard or third-party libraries.
type ContextKey string

// ClaimsContextKey is the specific key used to store and retrieve JWT claims
// from a request's context. The Auth middleware uses this key to pass the
// authenticated user's claims to downstream HTTP handlers.
const ClaimsContextKey = ContextKey("claims")
