package smtp

import (
	"crypto/tls"
	"fmt"

	"github.com/basht0p/chickadee/models"
	"github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"
)

// SendSmtpAlert sends an email using the go-smtp library
func SendSmtpAlert(alertOptions models.AlertOptions) error {
	if !alertOptions.SmtpEnabled {
		return fmt.Errorf("SMTP is not enabled in the config")
	}

	smtpServer := fmt.Sprintf("%s:%s", alertOptions.SmtpHost, alertOptions.SmtpPort)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         alertOptions.SmtpHost,
		MinVersion:         tls.VersionTLS12,
	}

	var conn *smtp.Client
	var err error

	if alertOptions.SmtpTlsEnabled {
		switch alertOptions.SmtpTlsType {
		case 2: // STARTTLS (recommended for Microsoft 365)
			conn, err = smtp.DialStartTLS(smtpServer, tlsConfig)
			if err != nil {
				return fmt.Errorf("error during connection: %v", err)
			}

			// Authentication - ensure you're using the full email as the username
			authPlain := sasl.NewPlainClient("", alertOptions.SmtpAuthUser, alertOptions.SmtpAuthPass)
			if err = conn.Auth(authPlain); err != nil {
				fmt.Printf("error with auth_plain: %v\ntrying auth_login...\n", err)
				authLogin := sasl.NewLoginClient(alertOptions.SmtpAuthUser, alertOptions.SmtpAuthPass)
				if err = conn.Auth(authLogin); err != nil {
					return fmt.Errorf("error with auth_login: %v", err)
				}
			}
		default:
			return fmt.Errorf("invalid TLS type: %v", alertOptions.SmtpTlsType)
		}
	} else {
		// Non-TLS connection (not recommended for Microsoft 365)
		conn, err = smtp.Dial(smtpServer)
		if err != nil {
			return fmt.Errorf("error during connection: %v", err)
		}
	}

	mailOpts := smtp.MailOptions{}
	rcptOpts := smtp.RcptOptions{}

	if err = conn.Mail(alertOptions.SmtpFromField, &mailOpts); err != nil {
		return fmt.Errorf("error setting sender: %v", err)
	}
	if err = conn.Rcpt(alertOptions.SmtpToField, &rcptOpts); err != nil {
		return fmt.Errorf("error setting recipient: %v", err)
	}

	wc, err := conn.Data()
	if err != nil {
		return fmt.Errorf("error getting write closer: %v", err)
	}
	defer wc.Close()

	body := "This is the email body.\n"
	if _, err = wc.Write([]byte(body)); err != nil {
		return fmt.Errorf("error writing email body: %v", err)
	}

	if err = conn.Quit(); err != nil {
		if smtpErr, ok := err.(*smtp.SMTPError); ok && smtpErr.Code == 250 {
			fmt.Println("Connection closed successfully with response 250.")
		} else {
			return fmt.Errorf("error closing connection: %v", err)
		}
	} else {
		fmt.Println("Connection closed successfully.")
	}

	return nil
}
