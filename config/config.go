package config

import (
	"fmt"

	"github.com/basht0p/chickadee/models"
	"gopkg.in/ini.v1"
)

func handleConfigErr(section string, err error) {
	if err != nil {
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

	iniSmtpEnabled, err := iniOptions.Key("enable_smtp").Bool()
	handleConfigErr("config file", err)

	iniSmtpHost := iniOptions.Key("smtp_host").String()
	iniSmtpPort := iniOptions.Key("smtp_port").String()

	iniSmtpAuthEnabled, err := iniOptions.Key("enable_auth").Bool()
	handleConfigErr("config file", err)

	iniSmtpAuthUser := iniOptions.Key("auth_user").String()
	iniSmtpAuthPass := iniOptions.Key("auth_pass").String()

	iniSmtpTlsEnabled, err := iniOptions.Key("enable_tls").Bool()
	handleConfigErr("config file", err)

	iniSmtpTlsType, err := iniOptions.Key("tls_type").Uint()
	handleConfigErr("config file", err)

	iniSmtpTlsVerifyCa, err := iniOptions.Key("verify_ca").Bool()
	handleConfigErr("config file", err)

	iniSmtpToField := iniOptions.Key("to").String()
	iniSmtpFromField := iniOptions.Key("from").String()
	iniSmtpSubjectField := iniOptions.Key("subject").String()

	detectionOptions = models.DetectionOptions{
		Iface:          iniIface,
		ThresholdCount: iniThresholdCount,
		ThresholdTime:  iniThresholdTime,
		IgnoreTime:     iniIgnoreTime,
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
		SmtpSubjectField: iniSmtpSubjectField,
	}

	return detectionOptions, alertOptions
}
