package snmptrap

import (
	"fmt"
	"strconv"
	"time"

	"github.com/basht0p/chickadee/logger"
	"github.com/basht0p/chickadee/models"
	"github.com/gosnmp/gosnmp"
)

func SendSnmpTrap(alertOptions *models.AlertOptions, srcIp string) error {
	port, err := strconv.Atoi(alertOptions.SnmpPort)
	if err != nil {
		logger.Log(true, 1, 503, fmt.Sprintf("Invalid port number: %v", err))
		return fmt.Errorf("invalid port number: %v", err)
	}

	snmpConn := &gosnmp.GoSNMP{
		Target:    alertOptions.SmtpHost,
		Port:      uint16(port),
		Community: alertOptions.SnmpCommunity,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err = snmpConn.Connect()
	if err != nil {
		logger.Log(true, 1, 503, fmt.Sprintf("Failed to connect to SNMP server: %v", err))
		return fmt.Errorf("failed to connect to SNMP server: %v", err)
	}
	defer snmpConn.Conn.Close()

	trap := gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			{
				Name:  alertOptions.SnmpOid,
				Type:  gosnmp.IPAddress,
				Value: srcIp,
			},
		},
	}

	_, err = snmpConn.SendTrap(trap)
	if err != nil {
		logger.Log(true, 1, 503, fmt.Sprintf("Failed to send SNMP trap: %v", err))
		return fmt.Errorf("failed to send SNMP trap: %v", err)
	}

	logger.Log(true, 0, 510, fmt.Sprintf("Sent SNMP message to %v", alertOptions.SnmpServer))

	return nil
}
