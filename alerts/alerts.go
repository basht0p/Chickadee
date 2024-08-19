package alerts

import (
	"github.com/basht0p/chickadee/alerts/smtp"
	"github.com/basht0p/chickadee/models"
)

func TriggerAlert(alertOptions models.AlertOptions, alertMessage string, srcIp string) {

	if alertOptions.SmtpEnabled {
		smtp.SendSmtpAlert(alertOptions, alertMessage, srcIp)
	}
}
