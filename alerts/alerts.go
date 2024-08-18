package alerts

import (
	"github.com/basht0p/chickadee/alerts/smtp"
	"github.com/basht0p/chickadee/models"
)

func TriggerAlert(alertOptions models.AlertOptions) {

	if alertOptions.SmtpEnabled {
		smtp.SendSmtpAlert(alertOptions)
	}
}
