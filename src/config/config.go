package config

import (
	"fmt"

	"github.com/basht0p/chickadee/logger"
	"github.com/basht0p/chickadee/models"
	"gopkg.in/ini.v1"
)

func handleConfigErr(section string, err error) {
	if err != nil {
		logger.Log(true, 1, 503, fmt.Sprintf("Error reading config section %v: %v", section, err))
		fmt.Printf("Error reading %v: %v", section, err)
	}
}

func ReadConfig() (models.DetectionOptions, models.AlertOptions) {

	var detectionOptions models.DetectionOptions
	var alertOptions models.AlertOptions

	iniContent, err := ini.Load("config.ini")
	iniOptions := iniContent.Section("")
	handleConfigErr("config file", err)

	iniIface := iniOptions.Key("interface").String()
	handleConfigErr("interface", err)

	iniThresholdCount, err := iniOptions.Key("threshold_count").Uint()
	handleConfigErr("threshold_count", err)

	iniThresholdTime, err := iniOptions.Key("threshold_time").Uint()
	handleConfigErr("threshold_time", err)

	iniIgnoreTime, err := iniOptions.Key("ignore_time").Uint()
	handleConfigErr("ignore_time", err)

	iniAgentName := iniOptions.Key("agent_name").String()

	iniSmtpEnabled, err := iniOptions.Key("enable_smtp").Bool()
	handleConfigErr("enable_smtp", err)

	iniSmtpHost := iniOptions.Key("smtp_host").String()
	iniSmtpPort := iniOptions.Key("smtp_port").String()

	iniSmtpAuthEnabled, err := iniOptions.Key("enable_auth").Bool()
	handleConfigErr("enable_auth", err)

	iniSmtpAuthUser := iniOptions.Key("auth_user").String()
	iniSmtpAuthPass := iniOptions.Key("auth_pass").String()

	iniSmtpTlsEnabled, err := iniOptions.Key("enable_tls").Bool()
	handleConfigErr("enable_tls", err)

	iniSmtpTlsType, err := iniOptions.Key("tls_type").Uint()
	handleConfigErr("tls_type", err)

	iniSmtpTlsVerifyCa, err := iniOptions.Key("verify_ca").Bool()
	handleConfigErr("verify_ca", err)

	iniSmtpToField := iniOptions.Key("to").String()
	iniSmtpFromField := iniOptions.Key("from").String()
	iniSmtpSubjectField := iniOptions.Key("subject").String()

	iniWebhookEnabled, err := iniOptions.Key("enable_webhook").Bool()
	handleConfigErr("webhook enabled", err)

	iniWebhookUrl := iniOptions.Key("webhook_url").String()

	iniSnmpEnabled, err := iniOptions.Key("enable_snmptrap").Bool()
	handleConfigErr("snmp enabled", err)

	iniSnmpOid := iniOptions.Key("snmp_oid").String()
	iniSnmpServer := iniOptions.Key("snmp_server").String()
	iniSnmpPort := iniOptions.Key("snmp_port").String()
	iniSnmpCommunity := iniOptions.Key("snmp_community").String()

	detectionOptions = models.DetectionOptions{
		Iface:          iniIface,
		ThresholdCount: iniThresholdCount,
		ThresholdTime:  iniThresholdTime,
		IgnoreTime:     iniIgnoreTime,
		AgentName:      iniAgentName,
	}

	alertOptions = models.AlertOptions{
		SmtpEnabled:      iniSmtpEnabled,
		SmtpHost:         iniSmtpHost,
		SmtpPort:         iniSmtpPort,
		SmtpAuthEnabled:  iniSmtpAuthEnabled,
		SmtpAuthUser:     iniSmtpAuthUser,
		SmtpAuthPass:     iniSmtpAuthPass,
		SmtpTlsEnabled:   iniSmtpTlsEnabled,
		SmtpTlsType:      models.TLSType(iniSmtpTlsType),
		SmtpTlsVerifyCa:  iniSmtpTlsVerifyCa,
		SmtpToField:      iniSmtpToField,
		SmtpFromField:    iniSmtpFromField,
		SmtpSubjectField: (iniAgentName + ": " + iniSmtpSubjectField),
		WebhookEnabled:   iniWebhookEnabled,
		WebhookUrl:       iniWebhookUrl,
		SnmpEnabled:      iniSnmpEnabled,
		SnmpOid:          iniSnmpOid,
		SnmpServer:       iniSnmpServer,
		SnmpPort:         iniSnmpPort,
		SnmpCommunity:    iniSnmpCommunity,
	}

	return detectionOptions, alertOptions
}
