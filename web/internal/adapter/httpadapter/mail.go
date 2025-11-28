package httpadapter

import (
	"fmt"
	"net/smtp"
	"os"
)

func sendMail(to, subj, body string) error {
	host := os.Getenv("SES_SMTP_HOST")
	port := os.Getenv("SES_SMTP_PORT")
	user := os.Getenv("SES_SMTP_USER")
	pass := os.Getenv("SES_SMTP_PASS")
	from := os.Getenv("SES_FROM")

	if host == "" || port == "" || user == "" || pass == "" || from == "" {
		return fmt.Errorf("smtp env not set")
	}

	addr := host + ":" + port
	auth := smtp.PlainAuth("", user, pass, host)

	hdr := ""
	hdr += "From: " + from + "\r\n"
	hdr += "To: " + to + "\r\n"
	hdr += "Subject: " + subj + "\r\n"
	hdr += "MIME-Version: 1.0\r\n"
	hdr += "Content-Type: text/plain; charset=UTF-8\r\n"
	hdr += "\r\n"

	msg := hdr + body

	err := smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
	if err != nil {
		return fmt.Errorf("smtp send failed: %w", err)
	}

	return nil
}
