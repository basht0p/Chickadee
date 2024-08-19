package models

import (
	"time"
)

type PortScan struct {
	Port      uint16
	Timestamp time.Time
}

type TLSType int

const (
	NoTLS TLSType = iota
	SSLTLS
	STARTTLS
)

type DetectionOptions struct {
	Iface          string
	ThresholdCount uint
	ThresholdTime  uint
	IgnoreTime     uint
	AgentName      string
}

type AlertOptions struct {
	SmtpEnabled      bool
	SmtpHost         string
	SmtpPort         string
	SmtpAuthEnabled  bool
	SmtpAuthUser     string
	SmtpAuthPass     string
	SmtpTlsEnabled   bool
	SmtpTlsType      TLSType
	SmtpTlsVerifyCa  bool
	SmtpToField      string
	SmtpFromField    string
	SmtpSubjectField string
}
