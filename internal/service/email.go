package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/smtp"

	"github.com/Olprog59/go-authstarter/internal/config"
)

type EmailService struct {
	cfg *config.Config
}

// NewEmailService creates email service with config validation / Crée le service email avec validation de la config
func NewEmailService(cfg *config.Config) (*EmailService, error) {
	// Skip validation for test mode (localhost:1025) / Ignore la validation pour le mode test
	if cfg.SMTP.Host != "localhost" && cfg.SMTP.Port != 1025 {
		if err := validateSMTPConfig(cfg.SMTP); err != nil {
			return nil, fmt.Errorf("invalid SMTP configuration: %w", err)
		}
	}
	
	// Set default values for test environment / Valeurs par défaut pour l'environnement de test
	if cfg.SMTP.Host == "" {
		cfg.SMTP.Host = "localhost"
		cfg.SMTP.Port = 1025
		cfg.SMTP.From = "test@example.com"
	}
	
	return &EmailService{cfg: cfg}, nil
}

// validateSMTPConfig validates SMTP settings / Valide les paramètres SMTP
func validateSMTPConfig(smtp config.SMTPConfig) error {
	if smtp.Host == "" {
		return fmt.Errorf("SMTP host is required")
	}
	if smtp.Port <= 0 || smtp.Port > 65535 {
		return fmt.Errorf("SMTP port must be between 1 and 65535")
	}
	if smtp.From == "" {
		return fmt.Errorf("SMTP from address is required")
	}
	// Username/Password can be empty for some SMTP servers (e.g., unauthenticated relay)
	return nil
}

func (e *EmailService) Send(ctx context.Context, to, subject, body string) error {
	auth := smtp.PlainAuth("", e.cfg.SMTP.Username, e.cfg.SMTP.Password, e.cfg.SMTP.Host)

	headers := make(map[string]string)
	headers["From"] = e.cfg.SMTP.From
	headers["To"] = to
	headers["Subject"] = "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(subject)) + "?="
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=\"utf-8\""

	var msg string
	for k, v := range headers {
		msg += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	msg += "\r\n" + body

	addr := fmt.Sprintf("%s:%d", e.cfg.SMTP.Host, e.cfg.SMTP.Port)

	if e.cfg.SMTP.Host == "localhost" && e.cfg.SMTP.Port == 1025 {
		ch := make(chan error, 1)
		go func() {
			ch <- smtp.SendMail(addr, nil, e.cfg.SMTP.From, []string{to}, []byte(msg))
		}()
		select {
		case err := <-ch:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	tlsConfig := &tls.Config{
		ServerName: e.cfg.SMTP.Host,
		MinVersion: tls.VersionTLS12,
	}

	// Use context-aware dialer / Utilise un dialer respectant le contexte
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	conn := tls.Client(rawConn, tlsConfig)
	defer conn.Close()

	// Perform TLS handshake with context / Effectue le handshake TLS avec contexte
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return err
	}

	client, err := smtp.NewClient(conn, e.cfg.SMTP.Host)
	if err != nil {
		return err
	}
	defer client.Quit()

	if err = client.Auth(auth); err != nil {
		return err
	}
	if err = client.Mail(e.cfg.SMTP.From); err != nil {
		return err
	}
	if err = client.Rcpt(to); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = w.Write([]byte(msg))
	return err
}
