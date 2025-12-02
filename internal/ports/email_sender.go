package ports

import "context"

// EmailSender sends emails / Envoie des emails
type EmailSender interface {
	// Send sends email with recipient, subject, body / Envoie un email avec destinataire, sujet, corps
	Send(ctx context.Context, to, subject, body string) error
}