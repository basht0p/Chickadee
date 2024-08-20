package models

import (
	"log"
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

type Webhook struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      WebhookData `json:"data"`
}

type WebhookData struct {
	SourceIP string `json:"src_ip"`
}

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
	WebhookEnabled   bool
	WebhookUrl       string
	SnmpEnabled      bool
	SnmpOid          string
	SnmpServer       string
	SnmpPort         string
	SnmpCommunity    string
}

type LoggerWrapper struct {
	logger *log.Logger
}
