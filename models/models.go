package models

import (
	"time"
)

type PortScan struct {
	Port      uint16
	Timestamp time.Time
}

type Config struct {
	Iface          string
	ThresholdCount uint
	ThresholdTime  uint
	IgnoreTime     uint
}
