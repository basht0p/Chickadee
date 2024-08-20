package alerts

import (
	"github.com/basht0p/chickadee/alerts/smtp"
	snmptrap "github.com/basht0p/chickadee/alerts/snmp"
	"github.com/basht0p/chickadee/alerts/webhook"
	"github.com/basht0p/chickadee/models"
)

func TriggerAlert(alertOptions *models.AlertOptions, alertMessage string, srcIp string) {

	if alertOptions.SmtpEnabled {
		smtp.SendSmtpAlert(alertOptions, alertMessage, srcIp)
	}

	if alertOptions.WebhookEnabled {
		webhook.SendWebhookAlert(alertOptions, srcIp)
	}

	if alertOptions.SnmpEnabled {
		snmptrap.SendSnmpTrap(alertOptions, srcIp)
	}
}
