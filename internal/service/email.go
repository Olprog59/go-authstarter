package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/smtp"

	"github.com/Olprog59/go-fun/internal/config"
)

type EmailService struct {
	cfg *config.Config
}

func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{cfg: cfg}
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

	// En dev avec MailDev (auth & TLS désactivés)
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

	// En prod : TLS obligatoire
	tlsConfig := &tls.Config{
		ServerName: e.cfg.SMTP.Host,
		MinVersion: tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

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
