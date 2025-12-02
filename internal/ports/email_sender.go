package ports

import "context"

// EmailSender defines the contract for sending emails.
// This interface allows for dependency inversion, making services that send
// emails testable and decoupled from concrete email implementations.
type EmailSender interface {
	// Send sends an email with the given recipient, subject, and body.
	// It returns an error if the email could not be sent.
	Send(ctx context.Context, to, subject, body string) error
}