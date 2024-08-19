package logger

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc/eventlog"
)

var elog *eventlog.Log

func SetupEventLog(sourceName string) error {
	var err error
	elog, err = eventlog.Open(sourceName)
	if err != nil {
		err = eventlog.InstallAsEventCreate(sourceName, eventlog.Info|eventlog.Warning|eventlog.Error)
		if err != nil {
			return fmt.Errorf("failed to install event log source: %v", err)
		}
		elog, err = eventlog.Open(sourceName)
		if err != nil {
			return fmt.Errorf("failed to open event log: %v", err)
		}
	}
	return nil
}

func CloseEventLog() {
	if elog != nil {
		elog.Close()
	}
}

func Log(winEvent bool, severity uint, eventID uint32, message string) {
	var severityName string = "INFO"

	switch severity {
	case 0:
		severityName = "INFO"
	case 1:
		severityName = "WARN"
	case 2:
		severityName = "ERR"
	}

	fullMessage := time.Now().Local().Format("Mon Jan 02 2006 15:04:05.99") + " " + severityName + ": " + message

	if winEvent {
		if elog != nil {
			switch severity {
			case 0:
				elog.Info(eventID, message)
			case 1:
				elog.Warning(eventID, message)
			case 2:
				elog.Error(eventID, message)
			}
		} else {
			fmt.Println("Event log is not initialized. Fallback to console: " + fullMessage)
		}
	} else {
		fmt.Println(fullMessage)
	}
}
