package smtp

import (
	"crypto/tls"
	"fmt"

	"github.com/basht0p/chickadee/logger"
	"github.com/basht0p/chickadee/models"
	"github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"
)

// SendSmtpAlert sends an email using the go-smtp library
func SendSmtpAlert(alertOptions models.AlertOptions, alertMessage string, srcIp string) error {
	if !alertOptions.SmtpEnabled {
		logger.Log(true, 1, 503, "SMTP is not enabled, but the function was called. How'd you do that?")
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

	// Initiate connection w/ or w/o TLS / STARTTLS & handle auth

	if alertOptions.SmtpTlsEnabled {
		switch alertOptions.SmtpTlsType {
		case 1:
			conn, err = smtp.DialTLS(smtpServer, tlsConfig)
			if err != nil {
				logger.Log(true, 1, 503, fmt.Sprintf("Error during SSL/TLS connection: %v", err))
				return fmt.Errorf("error during connection: %v", err)
			}
		case 2:
			conn, err = smtp.DialStartTLS(smtpServer, tlsConfig)
			if err != nil {
				logger.Log(true, 1, 503, fmt.Sprintf("Error during STARTTLS connection: %v", err))
				return fmt.Errorf("error during connection: %v", err)
			}
		default:
			logger.Log(true, 2, 500, fmt.Sprintf("Invalid TLS type: %v", string(alertOptions.SmtpTlsType)))
			return err
		}

		authPlain := sasl.NewPlainClient("", alertOptions.SmtpAuthUser, alertOptions.SmtpAuthPass)
		if err = conn.Auth(authPlain); err != nil {

			logger.Log(true, 1, 503, fmt.Sprintf("Error encountered using AUTH PLAIN: %v", err))
			logger.Log(true, 1, 503, "Attempting to switch to AUTH LOGIN...")

			authLogin := sasl.NewLoginClient(alertOptions.SmtpAuthUser, alertOptions.SmtpAuthPass)

			if err = conn.Auth(authLogin); err != nil {
				logger.Log(true, 2, 500, fmt.Sprintf("Error encountered using AUTH LOGIN: %v", err))
				return err
			}
		}

	} else {
		conn, err = smtp.Dial(smtpServer)
		if err != nil {
			logger.Log(true, 2, 500, fmt.Sprintf("Error encountered dialing connection: %v", err))
			return fmt.Errorf("error during connection: %v", err)
		}
	}

	// Start building the message and headers

	mailOpts := smtp.MailOptions{}
	rcptOpts := smtp.RcptOptions{}

	if err = conn.Mail(alertOptions.SmtpFromField, &mailOpts); err != nil {
		logger.Log(true, 2, 503, fmt.Sprintf("Error setting sender: %v", err))
		return fmt.Errorf("error setting sender: %v", err)
	}
	if err = conn.Rcpt(alertOptions.SmtpToField, &rcptOpts); err != nil {
		logger.Log(true, 2, 503, fmt.Sprintf("Error setting recipient: %v", err))
		return fmt.Errorf("error setting recipient: %v", err)
	}

	wc, err := conn.Data()
	if err != nil {
		logger.Log(true, 2, 503, fmt.Sprintf("Error getting write closer: %v", err))
		return fmt.Errorf("error getting write closer: %v", err)
	}
	defer wc.Close()

	headers := make(map[string]string)
	headers["From"] = alertOptions.SmtpFromField
	headers["To"] = alertOptions.SmtpToField
	headers["Subject"] = alertOptions.SmtpSubjectField
	headers["Content-Type"] = "text/plain; charset=\"utf-8\""

	body := ""

	for hdr, val := range headers {
		body += fmt.Sprintf("%s: %s\r\n", hdr, val)
	}

	body += "\r\n"

	body += fmt.Sprintf("A potentially malicious network scan was detected coming from this IP address: %v\n", srcIp)

	if _, err = wc.Write([]byte(body)); err != nil {
		logger.Log(true, 2, 503, fmt.Sprintf("Error writing email body: %v", err))
		return fmt.Errorf("error writing email body: %v", err)
	}

	// After building the message, close the connection.

	if err = conn.Quit(); err != nil {
		if smtpErr, ok := err.(*smtp.SMTPError); ok && smtpErr.Code == 250 {
			logger.Log(true, 0, 510, ("Alert sent to SMTP recipient(s) successfully with response 250."))
		} else {
			logger.Log(true, 2, 503, fmt.Sprintf("Error closing connection: %v", err))
			return fmt.Errorf("error closing connection: %v", err)
		}
	} else {
		logger.Log(true, 0, 510, ("Alert sent to SMTP recipient(s) successfully."))
	}

	return nil
}
